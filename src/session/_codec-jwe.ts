import { encrypt, decrypt } from "../core/jwe.ts";
import { DEFAULT_PBES2_ITERATIONS } from "../core/_internal.ts";
import {
  isCryptoKey,
  isJWK,
  isPrivateJWK,
  isPublicJWK,
  isSymmetricJWK,
} from "../core/utils/guards.ts";
import { toPublicJWK } from "../core/jwk.ts";
import type {
  ExpiresIn,
  JWEEncryptJWK,
  JWEDecryptJWK,
  JWEDecryptOptions,
  JWEAsymmetricPublicJWK,
  JWEAsymmetricPrivateJWK,
  JWEEncryptOptions,
  JWEHeaderParameters,
  JWEKeyLookup,
} from "../core/types/index.ts";
import type { StrictOmit } from "../core/utils/types.ts";
import { assertKeyMaterial, invalidKeyError } from "./_contract.ts";
import {
  type SessionPayload,
  assertKeyPair,
  assertPinnedCryptoKey,
  createSessionCodec,
  isKeyPair,
  sessionIssueOptions,
  sessionOpenOptions,
} from "./_codec.ts";
import type { SessionCodec, SessionCoreConfig, SessionCoreHooks } from "./_types.ts";
import type { SessionBaseConfig, SessionHooks } from "./types.ts";

/**
 * Symmetric JWK, `CryptoKey` (requires pinned `alg` and `enc`), or a pair: public seals, private unseals.
 * A private JWK alone seals with its own public half; a private `CryptoKey` has none to derive, so it comes with one.
 */
export type JWESessionKey =
  | CryptoKey
  | JWEEncryptJWK
  | {
      privateKey: JWEAsymmetricPrivateJWK;
      publicKey?: JWEAsymmetricPublicJWK | CryptoKey;
    }
  | {
      privateKey: CryptoKey;
      publicKey: JWEAsymmetricPublicJWK | CryptoKey;
    };

type JWESessionKeyPair = Extract<JWESessionKey, { privateKey: unknown }>;

/** JWE decrypt overrides, minus the options the adapter owns. */
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

/** JWE encrypt options, minus those setting `exp`/`nbf` (the adapter mints `exp` from `maxAge`). */
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
> extends SessionBaseConfig<MaxAge> {
  /** Key used for sealing — see {@link JWESessionKey}. */
  key: JWESessionKey;
  /** `false` to disable. Defaults: `path="/"`, `secure`, `sameSite: "lax"`, `httpOnly: true`. */
  cookie?: false | (TCookie & { chunkMaxLength?: number });
  /** Pinned `encryptOptions.alg`/`enc` restrict unsealing; `protectedHeader.typ` defaults to `"session+jwt"` (RFC 8725 §3.11). */
  jwe?: JWESessionOptions;
}

/** JWE session hooks, plus the unseal key lookup. */
export interface JWESessionHooks<
  TSession,
  TManager,
  TArgs extends Record<string, unknown>,
  TConfig,
> extends SessionHooks<TSession, TManager, TArgs, TConfig> {
  /** Resolve the decryption key for the incoming token from its protected header (e.g. by `kid`). */
  onUnsealKeyLookup?: (
    args: Partial<TArgs> & { header: JWEHeaderParameters; config: TConfig },
  ) => JWEDecryptJWK | Promise<JWEDecryptJWK>;
}

export interface JWECodecConfig extends SessionCoreConfig {
  key: JWESessionKey;
  jwe?: JWESessionOptions;
  hooks?: SessionCoreHooks & {
    onUnsealKeyLookup?(args: {
      header: JWEHeaderParameters;
      config: unknown;
      [arg: string]: unknown;
    }): JWEDecryptJWK | Promise<JWEDecryptJWK>;
  };
}

type JWEOpenKey = JWEDecryptJWK | CryptoKey | JWEKeyLookup<JWEDecryptJWK>;

export const JWE_DEFAULT_COOKIE = {
  path: "/",
  secure: true,
  httpOnly: true,
  sameSite: "lax",
} as const;

/** Seals session claims into a compact JWE; unsealing validates claims and `typ`, pinning algorithms when configured. */
export function createJWECodec(options: {
  prefix: string;
  defaultName: string;
}): SessionCodec<JWECodecConfig> {
  const { prefix, defaultName } = options;

  return createSessionCodec<JWECodecConfig, JWEEncryptJWK | CryptoKey, JWEOpenKey>({
    family: "jwe",
    prefix,
    defaultName,
    defaultCookie: JWE_DEFAULT_COOKIE,

    issueOptions: (config) => config.jwe?.encryptOptions,
    openOptions: (config) => config.jwe?.decryptOptions,
    issueKey: (config) => getEncryptKey(config, prefix),
    openKey: (config) => getDecryptKey(config, prefix),
    lookup: (config, args) => {
      const hooks = config.hooks;
      if (!hooks?.onUnsealKeyLookup) return undefined;
      return (header: JWEHeaderParameters) =>
        hooks.onUnsealKeyLookup?.({ header, ...args, config });
    },

    issue: (config, payload, key) =>
      // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- picks the JWK overload; a CryptoKey reaches here only with `alg` and `enc` pinned
      encrypt(payload, key as JWEEncryptJWK, sessionIssueOptions(config.jwe?.encryptOptions)),

    open: async (config, sealed, key) => {
      const { decryptOptions, encryptOptions } = config.jwe ?? {};
      const enc = encryptOptions?.enc;
      const { payload } = await decrypt<SessionPayload>(sealed, key, {
        ...decryptOptions,
        maxIterations: sessionMaxIterations(config),
        ...sessionOpenOptions({
          maxAge: config.maxAge,
          requiredClaims: decryptOptions?.requiredClaims,
          typ: encryptOptions?.protectedHeader?.typ,
          alg: encryptOptions?.alg,
        }),
        encryptionAlgorithms: enc ? [enc] : undefined,
      });
      return payload;
    },
  });
}

/** Caps a PBES2 session's accepted `p2c` at the count it mints itself. */
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

  let resolved: JWEEncryptJWK | CryptoKey | undefined;
  if (isCryptoKey(key) || isSymmetricJWK(key)) {
    resolved = key;
  } else if (isKeyPair(key)) {
    resolved = jweKeyPair(key, prefix).publicKey;
  }

  if (!resolved) {
    throw invalidKeyError(`${prefix} Invalid JWE key, expected a JWK or a CryptoKey.`, key);
  }

  assertPinnedAlgEnc(resolved, config, prefix);
  return resolved;
}

function getDecryptKey(config: JWECodecConfig, prefix: string): JWEDecryptJWK | CryptoKey {
  const key = config.key;
  assertKeyMaterial(key, { prefix });

  let resolved: JWEDecryptJWK | CryptoKey | undefined;
  if (isCryptoKey(key) || isSymmetricJWK(key)) {
    resolved = key;
  } else if (isKeyPair(key)) {
    resolved = jweKeyPair(key, prefix).privateKey;
  }

  if (!resolved) {
    throw invalidKeyError(
      `${prefix} Invalid JWE key, expected a JWK, a private JWK or a CryptoKey.`,
      key,
    );
  }

  assertPinnedAlgEnc(resolved, config, prefix);
  return resolved;
}

/** Both halves of the pair, the public one derived from a private JWK when the config carries none. */
function jweKeyPair(
  key: JWESessionKeyPair,
  prefix: string,
): {
  privateKey: JWEAsymmetricPrivateJWK | CryptoKey;
  publicKey: JWEAsymmetricPublicJWK | CryptoKey;
} {
  const pair = {
    privateKey: key.privateKey,
    publicKey: key.publicKey ?? derivedPublicHalf(key.privateKey, prefix),
  };
  assertKeyPair(pair, {
    prefix,
    family: "JWE",
    isPublic: (half) => isCryptoKey(half) || isPublicJWK(half),
    publicHalf: "a public JWK or a CryptoKey",
  });
  return pair;
}

/** A private JWK carries its public members; a private `CryptoKey` does not, so it needs the public half spelled out. */
function derivedPublicHalf(
  privateKey: JWEAsymmetricPrivateJWK | CryptoKey,
  prefix: string,
): JWEAsymmetricPublicJWK | CryptoKey {
  if (isPrivateJWK(privateKey)) return toPublicJWK(privateKey);
  throw invalidKeyError(
    `${prefix} Invalid JWE key: a CryptoKey "privateKey" needs its "publicKey".`,
    privateKey,
  );
}

function assertPinnedAlgEnc(key: unknown, config: JWECodecConfig, prefix: string): void {
  const { alg, enc } = config.jwe?.encryptOptions ?? {};
  assertPinnedCryptoKey(key, {
    pinned: Boolean(alg && enc),
    prefix,
    hint: '"jwe.encryptOptions.alg" and "enc"',
  });
}
