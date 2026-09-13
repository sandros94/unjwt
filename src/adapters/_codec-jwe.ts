import { encrypt, decrypt } from "../core/jwe";
import { isCryptoKey, isSymmetricJWK, isPrivateJWK, isPublicJWK } from "../core/utils";
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

/** JWE encrypt/decrypt overrides a session accepts. */
export interface JWESessionOptions {
  encryptOptions?: Omit<JWEEncryptOptions, "expiresIn">;
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
   * Session lifetime — sets `exp = iat + maxAge` in the token, bounds the age
   * of an incoming token, and drives the cookie expiry. Without it the session
   * writes no `exp` and never expires on its own.
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
 * honoured), checks the `typ` and `cty` headers, pins the algorithms when the
 * config does, and enforces `maxAge` as `maxTokenAge`.
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

  return {
    family: "jwe",
    defaultName,
    defaultCookie: JWE_DEFAULT_COOKIE,

    now: (config) => config.jwe?.encryptOptions?.currentDate?.getTime() ?? Date.now(),

    issueKey: (config) => getEncryptKey(config, prefix),

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
        // `exp` is computed from the session lifetime and carried via the claim above.
        expiresIn: undefined,
        protectedHeader: {
          ...config.jwe?.encryptOptions?.protectedHeader,
          typ: sessionTyp(config.jwe?.encryptOptions?.protectedHeader?.typ),
          cty: SESSION_CONTENT_TYPE,
        },
      });
    },

    open: async (config, sealed, carrier, resolvedKey) => {
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
          maxTokenAge: config.maxAge,
          algorithms: alg ? [alg] : undefined,
          encryptionAlgorithms: enc ? [enc] : undefined,
          payload: "json",
          validateClaims: true,
        },
      ).catch((error_: unknown) => rethrowAsInvalidToken(error_, { prefix }));

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
 * that pins a pinned-algorithm session to a costlier iteration count is refused.
 */
function sessionMaxIterations(config: JWECodecConfig): number | undefined {
  const configured = config.jwe?.decryptOptions?.maxIterations;
  if (configured !== undefined) return configured;
  const alg = config.jwe?.encryptOptions?.alg;
  return typeof alg === "string" && alg.startsWith("PBES2")
    ? config.jwe?.encryptOptions?.p2c
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
  } else if ("publicKey" in key && key.publicKey) {
    const publicKey = key.publicKey;
    if (isCryptoKey(publicKey) || isPublicJWK(publicKey)) _key = publicKey as JWEEncryptJWK;
  }
  if (!_key && "privateKey" in key) {
    // Fall back to the private JWK — `encrypt` accepts a symmetric oct here or
    // extracts the public parts internally when the caller has no public half.
    const privateKey = key.privateKey;
    if (isCryptoKey(privateKey) || isPrivateJWK(privateKey)) {
      _key = privateKey as unknown as JWEEncryptJWK;
    }
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
  } else if ("privateKey" in key) {
    _key = key.privateKey as JWEAsymmetricPrivateJWK;
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

function assertPinnedAlgEnc(key: unknown, config: JWECodecConfig, prefix: string): void {
  if (!isCryptoKey(key)) return;
  if (!config.jwe?.encryptOptions?.alg || !config.jwe?.encryptOptions?.enc) {
    throw invalidConfigError(
      `${prefix} A CryptoKey session key carries no algorithm: set "jwe.encryptOptions.alg" and "enc".`,
    );
  }
}
