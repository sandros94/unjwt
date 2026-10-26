import { encrypt, decrypt } from "../../core/jwe/index.ts";
import { DEFAULT_PBES2_ITERATIONS } from "../../core/_internal/limits.ts";
import { isCryptoKey, isJWK } from "../../utils/guards.ts";
import type {
  ExpiresIn,
  JWEDecryptJWK,
  JWEDecryptOptions,
  JWEEncryptOptions,
  JWEHeaderParameters,
  JWEKeyLookup,
  JWKSet,
} from "../../core/types/index.ts";
import type { StrictOmit } from "../../utils/types.ts";
import {
  type SessionPayload,
  createSessionCodec,
  sessionIssueOptions,
  sessionOpenOptions,
} from "./codec.ts";
import {
  type JWESessionKey,
  type JWESessionOctJWK,
  type JWESessionSecret,
  assertIssuingKey,
  rotationSet,
  sessionKeys,
} from "./codec-jwe-keys.ts";
import type { SessionCodec, SessionCoreConfig, SessionCoreHooks } from "./types.ts";
import type { SessionBaseConfig, SessionHooks } from "../types.ts";

/** JWE decrypt options a session accepts. The session sets `algorithms`, `encryptionAlgorithms`, `typ`, `maxTokenAge`, `validateClaims` and `payload` itself. */
export type SessionDecryptOptions = StrictOmit<
  JWEDecryptOptions,
  "algorithms" | "encryptionAlgorithms" | "typ" | "maxTokenAge" | "validateClaims" | "payload"
>;

/** JWE encrypt options a session accepts. The session sets `exp` from `maxAge` and never sets `nbf`. */
export type SessionEncryptOptions = StrictOmit<
  JWEEncryptOptions,
  "expiresIn" | "expiresAt" | "notBeforeIn" | "notBeforeAt"
>;

/** The JWE options of a session: `encryptOptions` for each issued token, `decryptOptions` for each incoming one. */
export interface JWESessionOptions {
  encryptOptions?: SessionEncryptOptions;
  decryptOptions?: SessionDecryptOptions;
}

/** The config of a JWE session, without its hooks. */
export interface JWESessionConfig<
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TCookie extends object = object,
> extends SessionBaseConfig<MaxAge> {
  /** The key that encrypts and decrypts the token. See {@link JWESessionKey}. */
  key: JWESessionKey;
  /** Cookie attributes, or `false` for no cookie. `chunkMaxLength` is the size the token is split at (`4000` when unset). @default { path: "/", secure: true, httpOnly: true, sameSite: "lax" } */
  cookie?: false | (TCookie & { chunkMaxLength?: number });
  /** A pinned `encryptOptions.alg` and `enc` are the only algorithms decryption accepts. `encryptOptions.protectedHeader.typ` defaults to `"session+jwt"` (RFC 8725 §3.11). A PBES2 session accepts at most the `p2c` it issues with, unless `decryptOptions.maxIterations` is set. */
  jwe?: JWESessionOptions;
}

/** JWE session hooks, with the decrypt key lookup. */
export interface JWESessionHooks<
  TSession,
  TManager,
  TArgs extends Record<string, unknown>,
  TConfig,
> extends SessionHooks<TSession, TManager, TArgs, TConfig> {
  /** Returns the key that decrypts an incoming token, picked from its protected header (by `kid`, for example). Set, it replaces `key` for decryption. `open()` passes it no event. */
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

type JWEOpenKey =
  | JWEDecryptJWK
  | JWKSet
  | CryptoKey
  | JWEKeyLookup<JWEDecryptJWK | JWKSet | CryptoKey>;

export const JWE_DEFAULT_COOKIE = {
  path: "/",
  secure: true,
  httpOnly: true,
  sameSite: "lax",
} as const;

/** Encrypts session claims into a compact JWE and decrypts them, checking claims, `typ` and the pinned algorithms. */
export function createJWECodec(options: {
  prefix: string;
  defaultName: string;
}): SessionCodec<JWECodecConfig> {
  const { prefix, defaultName } = options;

  return createSessionCodec<JWECodecConfig, JWESessionSecret, JWEOpenKey>({
    family: "jwe",
    prefix,
    defaultName,
    defaultCookie: JWE_DEFAULT_COOKIE,

    issueOptions: (config) => config.jwe?.encryptOptions,
    openOptions: (config) => config.jwe?.decryptOptions,
    issueKey: (config) => getEncryptKey(config, prefix),
    openKey: (config) => getDecryptKey(config, prefix),
    lookup: (config) => {
      const hooks = config.hooks;
      if (!hooks?.onUnsealKeyLookup) return undefined;
      return (args) => (header: JWEHeaderParameters) =>
        hooks.onUnsealKeyLookup?.({ header, ...args, config });
    },
    importable: (_key, config) => {
      const { current, previous = [] } = sessionKeys(config.key, prefix);
      return [current, ...previous];
    },

    issue: (config, payload, key) =>
      // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- picks the JWK overload; a key without `alg` reaches here only with `alg` and `enc` pinned
      encrypt(payload, key as JWESessionOctJWK, sessionIssueOptions(config.jwe?.encryptOptions)),

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

/** Caps the `p2c` a PBES2 session accepts at the count it issues with. */
function sessionMaxIterations(config: JWECodecConfig): number | undefined {
  const configured = config.jwe?.decryptOptions?.maxIterations;
  if (configured !== undefined) return configured;
  const key = rotationSet(config.key)?.current ?? config.key;
  const alg = config.jwe?.encryptOptions?.alg ?? (isJWK(key) ? key.alg : undefined);
  return typeof alg === "string" && alg.startsWith("PBES2")
    ? (config.jwe?.encryptOptions?.p2c ?? DEFAULT_PBES2_ITERATIONS)
    : undefined;
}

function getEncryptKey(config: JWECodecConfig, prefix: string): JWESessionSecret {
  const { current } = sessionKeys(config.key, prefix);
  assertCurrentKey(current, config, prefix);
  return current;
}

/** `current` alone, or for a rotation set a JWK Set of `current` and `keys`. With a `CryptoKey` `current`, a token whose `kid` names one of `keys` gets `keys`, any other `current`. */
function getDecryptKey(config: JWECodecConfig, prefix: string): JWEOpenKey {
  const { current, previous } = sessionKeys(config.key, prefix);
  assertCurrentKey(current, config, prefix);
  if (!previous) return current;
  if (!isCryptoKey(current)) {
    return { keys: [current, ...previous.filter((key) => key !== current)] };
  }
  const set = { keys: previous };
  return (header: JWEHeaderParameters) =>
    header.kid !== undefined && previous.some((key) => key.kid === header.kid) ? set : current;
}

function assertCurrentKey(key: JWESessionSecret, config: JWECodecConfig, prefix: string): void {
  const { alg, enc } = config.jwe?.encryptOptions ?? {};
  const subject = rotationSet(config.key) ? 'The session key "current"' : "The session key";
  assertIssuingKey(key, { alg, enc, subject, prefix });
}
