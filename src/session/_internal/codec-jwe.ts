import { encrypt, decrypt } from "../../core/jwe/index.ts";
import { DEFAULT_PBES2_ITERATIONS } from "../../core/_internal/limits.ts";
import { isJWK, isJWKSet } from "../../utils/guards.ts";
import type {
  ExpiresIn,
  JWEDecryptJWK,
  JWEDecryptOptions,
  JWEEncryptOptions,
  JWEHeaderParameters,
  JWKSet,
} from "../../core/types/index.ts";
import type { StrictOmit } from "../../utils/types.ts";
import { type SessionPayload, createSessionCodec, sessionIssueOptions } from "./codec.ts";
import { type JWESessionKey, type JWESessionOctJWK, resolveSessionKeys } from "./codec-jwe-keys.ts";
import type { SessionCodec, SessionCoreConfig, SessionCoreHooks } from "./types.ts";
import type { SessionBaseConfig } from "../types.ts";

/**
 * JWE decrypt options a session accepts. `algorithms` names the `alg` values a key without its own `alg` (a `CryptoKey`, an `oct` JWK
 * without `alg`) decrypts, and with `onKeyLookup` set, may also name those only the keys it returns serve. The session sets `typ`,
 * `maxTokenAge`, `validateClaims` and `payload` itself, and takes no `encryptionAlgorithms`: a key decrypts every `enc` it serves.
 */
export type SessionDecryptOptions = StrictOmit<
  JWEDecryptOptions,
  "encryptionAlgorithms" | "typ" | "maxTokenAge" | "validateClaims" | "payload"
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
  /** The key, or JWK Set, that encrypts and decrypts the token. See {@link JWESessionKey}. */
  key: JWESessionKey;
  /** Cookie attributes, or `false` for no cookie. `chunkMaxLength` is the size the token is split at (`4000` when unset). @default { path: "/", secure: true, httpOnly: true, sameSite: "lax" } */
  cookie?: false | (TCookie & { chunkMaxLength?: number });
  /**
   * `encryptOptions.alg` and `enc` are what each token is encrypted with, and name the algorithm of a key without its own `alg`.
   * Decryption accepts every `alg` the key serves: a JWK's own `alg`, and for a key without one, the pin and each algorithm of
   * `decryptOptions.algorithms` its material carries. An empty `decryptOptions.algorithms`, or one listing an algorithm no key serves,
   * throws `ERR_SESSION_CONFIG_INVALID`, unless `onKeyLookup` is set for the latter. A `dir` key decrypts its own `enc` alone, a wrapping
   * key every `enc`. `encryptOptions.protectedHeader.typ` defaults to `"session+jwt"` (RFC 8725 §3.11). A PBES2 session accepts at most
   * the `p2c` it issues with, unless `decryptOptions.maxIterations` is set.
   */
  jwe?: JWESessionOptions;
}

export interface JWECodecConfig extends SessionCoreConfig {
  key: JWESessionKey;
  jwe?: JWESessionOptions;
  hooks?: SessionCoreHooks & {
    onKeyLookup?(
      this: void,
      args: {
        header: JWEHeaderParameters;
        config: unknown;
        [arg: string]: unknown;
      },
    ): JWEDecryptJWK | CryptoKey | JWKSet | Promise<JWEDecryptJWK | CryptoKey | JWKSet>;
  };
}

export const JWE_DEFAULT_COOKIE = {
  path: "/",
  secure: true,
  httpOnly: true,
  sameSite: "lax",
} as const;

/** Encrypts session claims into a compact JWE and decrypts them, checking claims, `typ` and the algorithms the keys serve. */
export function createJWECodec(options: {
  prefix: string;
  defaultName: string;
}): SessionCodec<JWECodecConfig> {
  const { prefix, defaultName } = options;

  return createSessionCodec({
    family: "jwe",
    prefix,
    defaultName,
    defaultCookie: JWE_DEFAULT_COOKIE,

    issueOptions: (config) => config.jwe?.encryptOptions,
    openOptions: (config) => config.jwe?.decryptOptions,
    resolveKeys: (config) =>
      resolveSessionKeys(config.key, {
        alg: config.jwe?.encryptOptions?.alg,
        enc: config.jwe?.encryptOptions?.enc,
        listed: config.jwe?.decryptOptions?.algorithms,
        limits: config.jwe?.decryptOptions?.limits,
        lookup: typeof config.hooks?.onKeyLookup === "function",
        prefix,
      }),
    lookup: (config) => config.hooks?.onKeyLookup,

    issue: (config, payload, key) =>
      // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- picks the JWK overload; a key without `alg` reaches here only with `alg` and `enc` pinned
      encrypt(payload, key as JWESessionOctJWK, sessionIssueOptions(config.jwe?.encryptOptions)),

    open: async (config, sealed, key, overrides) => {
      const { payload } = await decrypt<SessionPayload>(sealed, key, {
        ...config.jwe?.decryptOptions,
        maxIterations: sessionMaxIterations(config),
        ...overrides,
      });
      return payload;
    },
  });
}

/** Caps the `p2c` a PBES2 session accepts at the count it issues with. */
function sessionMaxIterations(config: JWECodecConfig): number | undefined {
  const configured = config.jwe?.decryptOptions?.maxIterations;
  if (configured !== undefined) return configured;
  const issuing = isJWKSet(config.key) ? config.key.keys[0] : config.key;
  const alg = config.jwe?.encryptOptions?.alg ?? (isJWK(issuing) ? issuing.alg : undefined);
  return typeof alg === "string" && alg.startsWith("PBES2")
    ? (config.jwe?.encryptOptions?.p2c ?? DEFAULT_PBES2_ITERATIONS)
    : undefined;
}
