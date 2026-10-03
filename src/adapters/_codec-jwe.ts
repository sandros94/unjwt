import { encrypt, decrypt } from "../core/jwe";
import { DEFAULT_PBES2_ITERATIONS } from "../core/_internal";
import { isCryptoKey, isJWK, isSymmetricJWK, isPrivateJWK, isPublicJWK } from "../core/utils";
import type {
  ExpiresIn,
  JWEEncryptJWK,
  JWEDecryptJWK,
  JWEDecryptOptions,
  JWEAsymmetricPublicJWK,
  JWEAsymmetricPrivateJWK,
  JWEEncryptOptions,
  JWEHeaderParameters,
} from "../core/types";
import type { StrictOmit } from "../core/utils/types";
import {
  SESSION_CONTENT_TYPE,
  assertImportableKey,
  assertKeyMaterial,
  assertSessionContentType,
  invalidConfigError,
  invalidKeyError,
  rethrowAsInvalidToken,
  sessionRequiredClaims,
  sessionTyp,
  splitSessionClaims,
} from "./_session";
import type { SessionCodec, SessionCoreConfig, SessionCoreHooks } from "./_session-core";

/**
 * Key used for sealing — a symmetric JWK, a `CryptoKey`, or an asymmetric
 * pair: the public key seals, the private key unseals. A `CryptoKey` carries
 * no algorithm, so it additionally requires `jwe.encryptOptions.alg` and
 * `enc`. Passwords are not keys — derive one once with
 * `deriveJWKFromPassword()` and pass the JWK.
 */
export type JWESessionKey =
  | CryptoKey
  | JWEEncryptJWK
  | {
      privateKey: JWEAsymmetricPrivateJWK | CryptoKey;
      publicKey?: JWEAsymmetricPublicJWK | CryptoKey;
    };

/** JWE decrypt overrides a session accepts — everything the adapter does not own itself. */
export type SessionDecryptOptions = StrictOmit<
  JWEDecryptOptions,
  | "algorithms"
  | "encryptionAlgorithms"
  | "typ"
  | "maxTokenAge"
  | "validateClaims"
  | "forceUint8Array"
  | "payload"
>;

/**
 * JWE encrypt options a session accepts. `exp` and `nbf` are the adapter's to
 * mint — `exp` from `maxAge`, never an `nbf` — so the options that would set
 * them are not the caller's.
 */
export type SessionEncryptOptions = StrictOmit<
  JWEEncryptOptions,
  "expiresIn" | "expiresAt" | "notBeforeIn" | "notBeforeAt"
>;

/** JWE encrypt/decrypt overrides a session accepts. */
export interface JWESessionOptions {
  encryptOptions?: SessionEncryptOptions;
  decryptOptions?: SessionDecryptOptions;
}

/** The config of a JWE-backed (encrypted) session, minus its hooks. */
export interface JWESessionConfig<
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TCookie extends object = object,
> {
  /** Key used for sealing — see {@link JWESessionKey}. */
  key: JWESessionKey;
  /**
   * Session lifetime — sets `exp = iat + maxAge` in the token, requires an
   * incoming token to carry an `exp`, and drives the cookie expiry. Without it
   * the session writes no `exp` and never expires on its own.
   */
  maxAge?: MaxAge;
  /** Session name — drives the cookie name and the default session header. */
  name?: string;
  /** Cookie options (`false` to disable). Defaults: `path="/"`, `secure`, `sameSite: "lax"`, `httpOnly: true`. */
  cookie?: false | (TCookie & { chunkMaxLength?: number });
  /** Request header to read the token from (`false` to disable). Default `x-<name>-session`. */
  sessionHeader?: false | string;
  /** Session ID (`jti`) generator. Default `crypto.randomUUID`. */
  generateId?: () => string;
  /** JWE encrypt/decrypt overrides. Set `encryptOptions.alg` and `enc` to pin the session algorithms — unsealing then accepts only them. */
  jwe?: JWESessionOptions;
}

/** The JWE config as the codec reads it, whatever framework declares it. */
export interface JWECodecConfig extends SessionCoreConfig {
  key: JWESessionKey;
  jwe?: JWESessionOptions;
  hooks?: SessionCoreHooks & {
    onUnsealKeyLookup?: (args: {
      header: JWEHeaderParameters;
      config: any;
      [carrier: string]: unknown;
    }) => JWEDecryptJWK | Promise<JWEDecryptJWK>;
  };
}

/** Cookie attributes a JWE session writes unless the config overrides them. */
export const JWE_DEFAULT_COOKIE = {
  path: "/",
  secure: true,
  httpOnly: true,
  sameSite: "lax",
} as const;

/**
 * The JWE half of a session: seal the session claims into a compact token, and
 * unseal one back.
 *
 * Unsealing always runs claim validation (`jti` & `iat` required, `exp`
 * honoured and required alongside a `maxAge`), checks the `typ` and `cty`
 * headers, and pins the algorithms when the config does.
 */
export function createJWECodec(options: {
  prefix: string;
  defaultName: string;
}): SessionCodec<JWECodecConfig> {
  const { prefix, defaultName } = options;

  const openKey = (config: JWECodecConfig, carrier: Record<string, unknown>): unknown =>
    config.hooks?.onUnsealKeyLookup
      ? (header: JWEHeaderParameters) =>
          config.hooks!.onUnsealKeyLookup!({ header, ...carrier, config })
      : getDecryptKey(config, prefix);

  const assertDecryptKey = async (config: JWECodecConfig): Promise<void> => {
    if (config.hooks?.onUnsealKeyLookup) return;
    const key = getDecryptKey(config, prefix);
    await assertImportableKey(key, { alg: config.jwe?.encryptOptions?.alg, prefix });
  };

  return {
    family: "jwe",
    defaultName,
    defaultCookie: JWE_DEFAULT_COOKIE,

    now: (config) => config.jwe?.encryptOptions?.currentDate?.getTime() ?? Date.now(),

    issueKey: (config) => getEncryptKey(config, prefix),

    assertKeys: async (config) => {
      const key = getEncryptKey(config, prefix);
      await assertImportableKey(key, { alg: config.jwe?.encryptOptions?.alg, prefix });
      if (!isSymmetricJWK(key)) await assertDecryptKey(config);
    },

    openKey,

    issue: (config, state, key) => {
      const iat = Math.floor(state.createdAt / 1000);
      const exp = state.expiresAt ? Math.floor(state.expiresAt / 1000) : undefined;

      const payload: Record<string, any> = {
        ...state.data,
        jti: state.id,
        iat,
      };
      if (exp) {
        payload.exp = exp;
      }

      return encrypt(payload as Record<string, unknown>, key as JWEEncryptJWK, {
        ...config.jwe?.encryptOptions,
        // `exp` is computed from the session lifetime and carried via the claim
        // above; a session never writes `nbf`.
        expiresIn: undefined,
        expiresAt: undefined,
        notBeforeIn: undefined,
        notBeforeAt: undefined,
        protectedHeader: {
          ...config.jwe?.encryptOptions?.protectedHeader,
          typ: sessionTyp(config.jwe?.encryptOptions?.protectedHeader?.typ),
          cty: SESSION_CONTENT_TYPE,
        },
      });
    },

    open: async (config, sealed, carrier, resolvedKey) => {
      if (resolvedKey === undefined) await assertDecryptKey(config);
      const key = resolvedKey ?? openKey(config, carrier);

      const alg = config.jwe?.encryptOptions?.alg;
      const enc = config.jwe?.encryptOptions?.enc;

      const { payload, protectedHeader } = await decrypt<{ jti: string; iat: number }>(
        sealed,
        key as JWEDecryptJWK,
        {
          ...config.jwe?.decryptOptions,
          maxIterations: sessionMaxIterations(config),
          requiredClaims: sessionRequiredClaims(config.jwe?.decryptOptions?.requiredClaims, {
            maxAge: config.maxAge,
          }),
          typ: sessionTyp(config.jwe?.encryptOptions?.protectedHeader?.typ),
          maxTokenAge: undefined,
          algorithms: alg ? [alg] : undefined,
          encryptionAlgorithms: enc ? [enc] : undefined,
          payload: "json",
          validateClaims: true,
        },
      ).catch((error_: unknown) =>
        rethrowAsInvalidToken(error_, { prefix, token: sealed, family: "JWE" }),
      );

      assertSessionContentType(protectedHeader.cty, { prefix });

      const { jti, iat, exp, data } = splitSessionClaims(payload);

      return {
        id: jti,
        createdAt: iat * 1000,
        expiresAt: exp ? exp * 1000 : undefined,
        data,
      };
    },
  };
}

/**
 * PBES2 unwrap accepts at most the `p2c` the session itself mints, so a token
 * that asks a PBES2 session for a costlier iteration count is refused. The
 * session is PBES2 when its pinned `alg` says so, or when the key it mints
 * tokens with carries a PBES2 `alg` — whatever key a lookup hook opens with.
 */
function sessionMaxIterations(config: JWECodecConfig): number | undefined {
  const configured = config.jwe?.decryptOptions?.maxIterations;
  if (configured !== undefined) return configured;
  const alg = config.jwe?.encryptOptions?.alg ?? (isJWK(config.key) ? config.key.alg : undefined);
  return typeof alg === "string" && alg.startsWith("PBES2")
    ? (config.jwe?.encryptOptions?.p2c ?? DEFAULT_PBES2_ITERATIONS)
    : undefined;
}

function getEncryptKey(config: JWECodecConfig, prefix: string): JWEEncryptJWK | CryptoKey {
  const key = config.key;
  assertKeyMaterial(key, { prefix });

  let _key: JWEEncryptJWK | CryptoKey | undefined;
  if (isCryptoKey(key)) {
    _key = key;
  } else if (isSymmetricJWK(key)) {
    _key = key as JWEEncryptJWK;
  } else if (isKeyPair(key)) {
    // Without a public half, `encrypt` derives the public parts from the private JWK.
    const { publicKey, privateKey } = keyPairHalves(key, prefix);
    _key = (publicKey ?? privateKey) as JWEEncryptJWK;
  }

  if (!_key) {
    throw invalidKeyError(`${prefix} Invalid JWE key. It must be a JWK or a CryptoKey.`, key);
  }

  assertPinnedAlgEnc(_key, config, prefix);
  return _key;
}

function getDecryptKey(config: JWECodecConfig, prefix: string): JWEDecryptJWK | CryptoKey {
  const key = config.key;
  assertKeyMaterial(key, { prefix });

  let _key: JWEDecryptJWK | CryptoKey | undefined;
  if (isCryptoKey(key)) {
    _key = key;
  } else if (isSymmetricJWK(key)) {
    _key = key as JWEDecryptJWK;
  } else if (isKeyPair(key)) {
    _key = keyPairHalves(key, prefix).privateKey as JWEDecryptJWK;
  }

  if (!_key) {
    throw invalidKeyError(
      `${prefix} Invalid JWE key. It must be a JWK, a private JWK, or a CryptoKey.`,
      key,
    );
  }

  assertPinnedAlgEnc(_key, config, prefix);
  return _key;
}

function isKeyPair(key: object): key is { privateKey?: unknown; publicKey?: unknown } {
  return "privateKey" in key || "publicKey" in key;
}

/**
 * Both halves of an asymmetric pair, each checked to be the half it is named
 * after, whichever of them the caller is about to use — a half that is not key
 * material is a configuration the session cannot serve, never a value handed
 * on to the cipher.
 */
function keyPairHalves(
  key: { privateKey?: unknown; publicKey?: unknown },
  prefix: string,
): {
  privateKey: JWEAsymmetricPrivateJWK | CryptoKey;
  publicKey?: JWEAsymmetricPublicJWK | CryptoKey;
} {
  const { privateKey, publicKey } = key;
  if (!isCryptoKey(privateKey) && !isPrivateJWK(privateKey)) {
    throw invalidKeyError(
      `${prefix} Invalid JWE key: "privateKey" must be a private JWK or a CryptoKey.`,
      key,
    );
  }
  if (publicKey !== undefined && !isCryptoKey(publicKey) && !isPublicJWK(publicKey)) {
    throw invalidKeyError(
      `${prefix} Invalid JWE key: "publicKey" must be a public JWK or a CryptoKey.`,
      key,
    );
  }
  return {
    privateKey: privateKey as JWEAsymmetricPrivateJWK | CryptoKey,
    publicKey: publicKey as JWEAsymmetricPublicJWK | CryptoKey | undefined,
  };
}

function assertPinnedAlgEnc(key: unknown, config: JWECodecConfig, prefix: string): void {
  if (!isCryptoKey(key)) return;
  if (!config.jwe?.encryptOptions?.alg || !config.jwe?.encryptOptions?.enc) {
    throw invalidConfigError(
      `${prefix} A CryptoKey session key carries no algorithm: set "jwe.encryptOptions.alg" and "enc".`,
    );
  }
}
