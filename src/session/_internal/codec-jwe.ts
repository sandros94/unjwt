import { encrypt, decrypt } from "../../core/jwe/index.ts";
import { DEFAULT_PBES2_ITERATIONS, resolveLimit } from "../../core/_internal/limits.ts";
import { isJWK } from "../../utils/guards.ts";
import type {
  ExpiresIn,
  JWEDecryptJWK,
  JWEDecryptOptions,
  JWEEncryptOptions,
  JWEHeaderParameters,
  JWEKeyLookup,
  KeyManagementAlgorithm,
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
  resolveSessionKeys,
} from "./codec-jwe-keys.ts";
import { JWE_ALG_CTX } from "../../core/jwe/_internal/algorithms.ts";
import { createPBES2Budget } from "../../core/jwe/_internal/keys.ts";
import { type SessionOpeners, rotationSet } from "./key-set.ts";
import { openWithKeys } from "./open-with-keys.ts";
import type { SessionCodec, SessionCoreConfig, SessionCoreHooks } from "./types.ts";
import type { SessionBaseConfig, SessionHooks } from "../types.ts";

/**
 * JWE decrypt options a session accepts. `algorithms` names the `alg` values a key without its own `alg` (a `CryptoKey`, an `oct` JWK
 * without `alg`) decrypts. The session sets `encryptionAlgorithms`, `typ`, `maxTokenAge`, `validateClaims` and `payload` itself.
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
  /** The key that encrypts and decrypts the token. See {@link JWESessionKey}. */
  key: JWESessionKey;
  /** Cookie attributes, or `false` for no cookie. `chunkMaxLength` is the size the token is split at (`4000` when unset). @default { path: "/", secure: true, httpOnly: true, sameSite: "lax" } */
  cookie?: false | (TCookie & { chunkMaxLength?: number });
  /**
   * `encryptOptions.alg` and `enc` are what each token is issued with, and name the algorithm of a `current` key without its own `alg`.
   * Decryption accepts every `alg` the keys serve: a JWK's own `alg`, and for a key without one, each algorithm of `decryptOptions.algorithms`
   * its material carries. A `dir` key decrypts its own `enc` alone, a wrapping key every `enc`.
   * `encryptOptions.protectedHeader.typ` defaults to `"session+jwt"` (RFC 8725 §3.11). A PBES2 session accepts at most the `p2c` it issues with, unless `decryptOptions.maxIterations` is set.
   */
  jwe?: JWESessionOptions;
}

/** JWE session hooks, with the decrypt key lookup. */
export interface JWESessionHooks<
  TSession,
  TManager,
  TArgs extends Record<string, unknown>,
  TConfig,
> extends SessionHooks<TSession, TManager, TArgs, TConfig> {
  /** Returns the key that decrypts an incoming token, picked from its protected header (by `kid`, for example). Set, it replaces `key` for decryption: the token's `alg` is still one `key` serves or `decryptOptions.algorithms` lists. `open()` passes it no event. */
  onKeyLookup?: (
    args: Partial<TArgs> & { header: JWEHeaderParameters; config: TConfig },
  ) => JWEDecryptJWK | Promise<JWEDecryptJWK>;
}

export interface JWECodecConfig extends SessionCoreConfig {
  key: JWESessionKey;
  jwe?: JWESessionOptions;
  hooks?: SessionCoreHooks & {
    onKeyLookup?(args: {
      header: JWEHeaderParameters;
      config: unknown;
      [arg: string]: unknown;
    }): JWEDecryptJWK | Promise<JWEDecryptJWK>;
  };
}

/** The configured keys, or with a key lookup hook the lookup of one request. */
type JWEOpenKey =
  | SessionOpeners<JWESessionSecret, KeyManagementAlgorithm>
  | { lookup: JWEKeyLookup<JWEDecryptJWK>; algorithms: KeyManagementAlgorithm[] };

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

  return createSessionCodec<JWECodecConfig, JWESessionSecret, JWEOpenKey>({
    family: "jwe",
    prefix,
    defaultName,
    defaultCookie: JWE_DEFAULT_COOKIE,

    issueOptions: (config) => config.jwe?.encryptOptions,
    openOptions: (config) => config.jwe?.decryptOptions,
    issueKey: (config) => resolveKeys(config, prefix).current,
    openKey: (config) => resolveKeys(config, prefix),
    lookup: (config) => {
      const hooks = config.hooks;
      if (!hooks?.onKeyLookup) return undefined;
      const { algorithms } = resolveKeys(config, prefix);
      return (args) => ({
        lookup: (header: JWEHeaderParameters) => hooks.onKeyLookup?.({ header, ...args, config }),
        algorithms,
      });
    },
    importable: (config) => {
      const { current, entries } = resolveKeys(config, prefix);
      return entries.map(({ key, algorithms }) => ({
        key,
        alg: key === current ? config.jwe?.encryptOptions?.alg : algorithms[0],
      }));
    },

    issue: (config, payload, key) =>
      // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- picks the JWK overload; a key without `alg` reaches here only with `alg` and `enc` pinned
      encrypt(payload, key as JWESessionOctJWK, sessionIssueOptions(config.jwe?.encryptOptions)),

    open: async (config, sealed, key) => {
      const { decryptOptions, encryptOptions } = config.jwe ?? {};
      const opening = {
        ...decryptOptions,
        maxIterations: sessionMaxIterations(config),
        ...sessionOpenOptions({
          maxAge: config.maxAge,
          requiredClaims: decryptOptions?.requiredClaims,
          typ: encryptOptions?.protectedHeader?.typ,
          algorithms: key.algorithms,
        }),
      };
      if ("lookup" in key)
        return (await decrypt<SessionPayload>(sealed, key.lookup, opening)).payload;
      const budget = createPBES2Budget(resolveLimit(opening.limits, "pbes2Iterations"));
      return openWithKeys(key, {
        ctx: JWE_ALG_CTX,
        limit: resolveLimit(opening.limits, "keyCandidates"),
        failure: { code: "ERR_JWE_DECRYPTION_FAILED", message: "JWE decryption failed." },
        attempt: async (candidate) =>
          (await decrypt<SessionPayload>(sealed, candidate, opening)).payload,
        spend: ({ alg, p2c }: JWEHeaderParameters) => {
          const { minIterations, maxIterations } = opening;
          if (alg) budget.spend({ alg, p2c, minIterations, maxIterations });
        },
      });
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

function resolveKeys(
  config: JWECodecConfig,
  prefix: string,
): ReturnType<typeof resolveSessionKeys> {
  const { encryptOptions, decryptOptions } = config.jwe ?? {};
  return resolveSessionKeys(config.key, {
    alg: encryptOptions?.alg,
    enc: encryptOptions?.enc,
    listed: decryptOptions?.algorithms,
    keyCandidates: resolveLimit(decryptOptions?.limits, "keyCandidates"),
    lookup: typeof config.hooks?.onKeyLookup === "function",
    prefix,
  });
}
