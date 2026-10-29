import { sign, verify } from "../../core/jws/index.ts";
import type {
  ExpiresIn,
  JWKSet,
  JWSSignJWK,
  JWSVerifyJWK,
  JWSSignOptions,
  JWSVerifyOptions,
  JWSHeaderParameters,
} from "../../core/types/index.ts";
import type { StrictOmit } from "../../utils/types.ts";
import { type SessionPayload, createSessionCodec, sessionIssueOptions } from "./codec.ts";
import { type JWSSessionKey, resolveSessionKeys } from "./codec-jws-keys.ts";
import type { SessionCodec, SessionCoreConfig, SessionCoreHooks } from "./types.ts";
import type { SessionBaseConfig } from "../types.ts";

/**
 * JWS verify options a session accepts. `algorithms` names the `alg` values a key without its own `alg` (a `CryptoKey`, an `oct` or RSA JWK
 * without `alg`) verifies, and with `onKeyLookup` set, may also name those only the keys it returns serve. The session sets `typ`,
 * `maxTokenAge`, `validateClaims` and `payload` itself.
 */
export type SessionVerifyOptions = StrictOmit<
  JWSVerifyOptions,
  "typ" | "maxTokenAge" | "validateClaims" | "payload"
>;

/** JWS sign options a session accepts. The session sets `exp` from `maxAge` and never sets `nbf`. */
export type SessionSignOptions = StrictOmit<
  JWSSignOptions,
  "expiresIn" | "expiresAt" | "notBeforeIn" | "notBeforeAt"
>;

/** The JWS options of a session: `signOptions` for each issued token, `verifyOptions` for each incoming one. */
export interface JWSSessionOptions {
  signOptions?: SessionSignOptions;
  verifyOptions?: SessionVerifyOptions;
}

/** The config of a JWS session, without its hooks. */
export interface JWSSessionConfig<
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TCookie extends object = object,
> extends SessionBaseConfig<MaxAge> {
  /** The key, or JWK Set, that signs and verifies the token. See {@link JWSSessionKey}. */
  key: JWSSessionKey;
  /** Cookie attributes, or `false` for no cookie. `chunkMaxLength` is the size the token is split at (`4000` when unset). `httpOnly: false` lets page scripts read the signed payload. @default { path: "/", secure: true, httpOnly: true, sameSite: "lax" } */
  cookie?: false | (TCookie & { chunkMaxLength?: number });
  /**
   * `signOptions.alg` is what each token is signed with, and names the algorithm of a key without its own `alg`, both halves of a pair
   * included when neither names one: a half without one takes the `alg` its other half names. Verification accepts every `alg` the keys
   * serve: a JWK's own `alg` (or an EC or OKP JWK's curve), and for a key without one, the pin and each algorithm of
   * `verifyOptions.algorithms` its material carries. An empty `verifyOptions.algorithms`, or one listing an algorithm no key serves,
   * throws `ERR_SESSION_CONFIG_INVALID`, unless `onKeyLookup` is set for the latter.
   * `signOptions.protectedHeader.typ` defaults to `"session+jwt"` (RFC 8725 §3.11).
   */
  jws?: JWSSessionOptions;
}

export interface JWSCodecConfig extends SessionCoreConfig {
  key: JWSSessionKey;
  jws?: JWSSessionOptions;
  hooks?: SessionCoreHooks & {
    onKeyLookup?(
      this: void,
      args: {
        header: JWSHeaderParameters;
        config: unknown;
        [arg: string]: unknown;
      },
    ): JWSVerifyJWK | CryptoKey | JWKSet | Promise<JWSVerifyJWK | CryptoKey | JWKSet>;
  };
}

export const JWS_DEFAULT_COOKIE = {
  path: "/",
  secure: true,
  httpOnly: true,
  sameSite: "lax",
} as const;

/** Signs session claims into a compact JWS and verifies them, checking claims, `typ` and the algorithms the keys serve. */
export function createJWSCodec(options: {
  prefix: string;
  defaultName: string;
}): SessionCodec<JWSCodecConfig> {
  const { prefix, defaultName } = options;

  return createSessionCodec({
    family: "jws",
    prefix,
    defaultName,
    defaultCookie: JWS_DEFAULT_COOKIE,

    issueOptions: (config) => config.jws?.signOptions,
    openOptions: (config) => config.jws?.verifyOptions,
    resolveKeys: (config) =>
      resolveSessionKeys(config.key, {
        alg: config.jws?.signOptions?.alg,
        listed: config.jws?.verifyOptions?.algorithms,
        limits: config.jws?.verifyOptions?.limits,
        lookup: typeof config.hooks?.onKeyLookup === "function",
        prefix,
      }),
    lookup: (config) => config.hooks?.onKeyLookup,

    issue: (config, payload, key, alg) => {
      const signOptions = config.jws?.signOptions;
      const issuing = sessionIssueOptions(alg ? { ...signOptions, alg } : signOptions);
      // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- picks the JWK overload; a key that names no `alg`, by its own or its curve, reaches here only with `alg` pinned or named by the other half of its pair
      return sign(payload, key as JWSSignJWK, issuing);
    },

    open: async (config, token, key, overrides) => {
      const { payload } = await verify<SessionPayload>(token, key, {
        ...config.jws?.verifyOptions,
        ...overrides,
      });
      return payload;
    },
  });
}
