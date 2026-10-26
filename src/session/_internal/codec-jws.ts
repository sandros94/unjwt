import { sign, verify } from "../../core/jws/index.ts";
import { isCryptoKey, isJWK, isJWKSet, isSymmetricJWK, isPublicJWK } from "../../utils/guards.ts";
import { jwkAlgServes } from "../../utils/algorithms.ts";
import type {
  ExpiresIn,
  JWKSet,
  JWK_HMAC,
  JWK_oct,
  JWSSignJWK,
  JWSVerifyJWK,
  JWSAsymmetricPrivateJWK,
  JWSAsymmetricPublicJWK,
  JWSSignOptions,
  JWSVerifyOptions,
  JWSKeyLookup,
  JWSHeaderParameters,
} from "../../core/types/index.ts";
import type { StrictOmit } from "../../utils/types.ts";
import { assertKeyMaterial, invalidKeyError } from "./contract.ts";
import {
  type SessionPayload,
  assertKeyPair,
  assertPinnedCryptoKey,
  createSessionCodec,
  isKeyPair,
  sessionIssueOptions,
  sessionOpenOptions,
} from "./codec.ts";
import type { SessionCodec, SessionCoreConfig, SessionCoreHooks } from "./types.ts";
import type { SessionBaseConfig, SessionHooks } from "../types.ts";

/** An HMAC `oct` JWK, a `CryptoKey` (requires a pinned `jws.signOptions.alg`), or a pair: `privateKey` signs, `publicKey` (a JWK, a JWK list, a JWK Set or a `CryptoKey`) verifies. */
export type JWSSessionKey =
  | CryptoKey
  | JWK_oct<JWK_HMAC>
  | {
      privateKey: JWSAsymmetricPrivateJWK | CryptoKey;
      publicKey: JWSAsymmetricPublicJWK | JWSAsymmetricPublicJWK[] | JWKSet | CryptoKey;
    };

/** JWS verify options a session accepts. The session sets `algorithms`, `typ`, `maxTokenAge`, `validateClaims` and `payload` itself. */
export type SessionVerifyOptions = StrictOmit<
  JWSVerifyOptions,
  "algorithms" | "typ" | "maxTokenAge" | "validateClaims" | "payload"
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
  /** The key that signs and verifies the token. See {@link JWSSessionKey}. */
  key: JWSSessionKey;
  /** Cookie attributes, or `false` for no cookie. `chunkMaxLength` is the size the token is split at (`4000` when unset). `httpOnly: false` lets page scripts read the signed payload. @default { path: "/", secure: true, httpOnly: true, sameSite: "lax" } */
  cookie?: false | (TCookie & { chunkMaxLength?: number });
  /** A pinned `signOptions.alg` is the only algorithm verification accepts. `signOptions.protectedHeader.typ` defaults to `"session+jwt"` (RFC 8725 §3.11). */
  jws?: JWSSessionOptions;
}

/** JWS session hooks, with the verify key lookup. */
export interface JWSSessionHooks<
  TSession,
  TManager,
  TArgs extends Record<string, unknown>,
  TConfig,
> extends SessionHooks<TSession, TManager, TArgs, TConfig> {
  /** Returns the key or JWK Set that verifies an incoming token, picked from its protected header (by `kid`, for example). Set, it replaces `key` for verification. `open()` passes it no event. */
  onVerifyKeyLookup?: (
    args: Partial<TArgs> & { header: JWSHeaderParameters; config: TConfig },
  ) => JWKSet | JWSVerifyJWK | Promise<JWKSet | JWSVerifyJWK>;
}

export interface JWSCodecConfig extends SessionCoreConfig {
  key: JWSSessionKey;
  jws?: JWSSessionOptions;
  hooks?: SessionCoreHooks & {
    onVerifyKeyLookup?(args: {
      header: JWSHeaderParameters;
      config: unknown;
      [arg: string]: unknown;
    }): JWKSet | JWSVerifyJWK | Promise<JWKSet | JWSVerifyJWK>;
  };
}

type JWSOpenKey = JWSVerifyJWK | JWKSet | CryptoKey | JWSKeyLookup<JWKSet | JWSVerifyJWK>;

export const JWS_DEFAULT_COOKIE = {
  path: "/",
  secure: true,
  httpOnly: true,
  sameSite: "lax",
} as const;

/** Signs session claims into a compact JWS and verifies them, checking claims, `typ` and the pinned `alg`. */
export function createJWSCodec(options: {
  prefix: string;
  defaultName: string;
}): SessionCodec<JWSCodecConfig> {
  const { prefix, defaultName } = options;

  return createSessionCodec<JWSCodecConfig, JWSSignJWK | CryptoKey, JWSOpenKey>({
    family: "jws",
    prefix,
    defaultName,
    defaultCookie: JWS_DEFAULT_COOKIE,

    issueOptions: (config) => config.jws?.signOptions,
    openOptions: (config) => config.jws?.verifyOptions,
    issueKey: (config) => getSignKey(config, prefix),
    openKey: (config) => getVerifyKey(config, prefix),
    lookup: (config) => {
      const hooks = config.hooks;
      if (!hooks?.onVerifyKeyLookup) return undefined;
      return (args) => (header: JWSHeaderParameters) =>
        hooks.onVerifyKeyLookup?.({ header, ...args, config });
    },
    importable: (key) => (isJWKSet(key) ? key.keys : [key]),

    issue: (config, payload, key) =>
      // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- picks the JWK overload; a CryptoKey reaches here only with `alg` pinned
      sign(payload, key as JWSSignJWK, sessionIssueOptions(config.jws?.signOptions)),

    open: async (config, token, key) => {
      const { verifyOptions, signOptions } = config.jws ?? {};
      const { payload } = await verify<SessionPayload>(token, key, {
        ...verifyOptions,
        ...sessionOpenOptions({
          maxAge: config.maxAge,
          requiredClaims: verifyOptions?.requiredClaims,
          typ: signOptions?.protectedHeader?.typ,
          alg: signOptions?.alg,
        }),
      });
      return payload;
    },
  });
}

function getSignKey(config: JWSCodecConfig, prefix: string): JWSSignJWK | CryptoKey {
  const key = config.key;
  assertKeyMaterial(key, { prefix });

  let resolved: JWSSignJWK | CryptoKey | undefined;
  if (isCryptoKey(key) || isSymmetricJWK(key)) {
    resolved = key;
  } else if (isKeyPair(key)) {
    assertJWSKeyPair(key, prefix);
    resolved = key.privateKey;
  }

  if (!resolved) {
    throw invalidKeyError(
      `${prefix} Invalid JWS key, expected a symmetric JWK, a key pair or a CryptoKey.`,
      key,
    );
  }

  assertPinnedAlg(resolved, config, prefix);
  return resolved;
}

function getVerifyKey(config: JWSCodecConfig, prefix: string): JWSVerifyJWK | JWKSet | CryptoKey {
  const key = config.key;
  assertKeyMaterial(key, { prefix });

  let resolved: JWSVerifyJWK | JWKSet | CryptoKey | undefined;
  if (isCryptoKey(key) || isSymmetricJWK(key)) {
    resolved = key;
  } else if (isKeyPair(key)) {
    assertJWSKeyPair(key, prefix);
    resolved = Array.isArray(key.publicKey) ? { keys: key.publicKey } : key.publicKey;
  }

  if (!resolved) {
    throw invalidKeyError(
      `${prefix} Invalid JWS key, expected a symmetric JWK, a key pair or a CryptoKey.`,
      key,
    );
  }

  assertPinnedAlg(resolved, config, prefix);
  return resolved;
}

function assertJWSKeyPair(
  key: { privateKey?: unknown; publicKey?: unknown },
  prefix: string,
): void {
  assertKeyPair(key, {
    prefix,
    family: "JWS",
    isPublic: (half) =>
      isCryptoKey(half) ||
      isPublicJWK(half) ||
      isPublicKeyList(Array.isArray(half) ? half : isJWKSet(half) ? half.keys : undefined),
    publicHalf: "a public JWK, a non-empty JWK set or a CryptoKey",
  });
}

function isPublicKeyList(keys: readonly unknown[] | undefined): boolean {
  return keys !== undefined && keys.length > 0 && keys.every((candidate) => isPublicJWK(candidate));
}

function assertPinnedAlg(key: unknown, config: JWSCodecConfig, prefix: string): void {
  const pinned = config.jws?.signOptions?.alg;
  assertPinnedCryptoKey(key, { pinned: Boolean(pinned), prefix, hint: '"jws.signOptions.alg"' });
  if (pinned && isJWK(key) && key.alg && !jwkAlgServes({ kty: key.kty, alg: key.alg }, pinned)) {
    throw invalidKeyError(
      `${prefix} Invalid JWS key, its "alg" is "${key.alg}" but "jws.signOptions.alg" pins "${pinned}".`,
      key,
    );
  }
}
