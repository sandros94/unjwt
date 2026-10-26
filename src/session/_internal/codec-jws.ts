import { sign, verify } from "../../core/jws/index.ts";
import { isCryptoKey, isJWKSet, isSymmetricJWK, isPublicJWK } from "../../utils/guards.ts";
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

/** HS* `oct` JWK, `CryptoKey` (requires pinned `alg`), or a pair: private signs, public JWK/list/set verifies. */
export type JWSSessionKey =
  | CryptoKey
  | JWK_oct<JWK_HMAC>
  | {
      privateKey: JWSAsymmetricPrivateJWK | CryptoKey;
      publicKey: JWSAsymmetricPublicJWK | JWSAsymmetricPublicJWK[] | JWKSet | CryptoKey;
    };

/** JWS verify overrides, minus the options the adapter owns. */
export type SessionVerifyOptions = StrictOmit<
  JWSVerifyOptions,
  "algorithms" | "typ" | "maxTokenAge" | "validateClaims" | "payload"
>;

/** JWS sign options, minus those setting `exp`/`nbf` (the adapter mints `exp` from `maxAge`). */
export type SessionSignOptions = StrictOmit<
  JWSSignOptions,
  "expiresIn" | "expiresAt" | "notBeforeIn" | "notBeforeAt"
>;

/** JWS sign/verify overrides a session accepts. */
export interface JWSSessionOptions {
  signOptions?: SessionSignOptions;
  verifyOptions?: SessionVerifyOptions;
}

/** The config of a JWS-backed (signed, not encrypted) session, minus its hooks. */
export interface JWSSessionConfig<
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
  TCookie extends object = object,
> extends SessionBaseConfig<MaxAge> {
  /** Key used for signing — see {@link JWSSessionKey}. */
  key: JWSSessionKey;
  /** `false` to disable. Defaults: `path="/"`, `secure`, `sameSite: "lax"`, `httpOnly: true`; `httpOnly: false` lets page scripts read the (signed, not encrypted) payload. */
  cookie?: false | (TCookie & { chunkMaxLength?: number });
  /** Pinned `signOptions.alg` restricts verification; `protectedHeader.typ` defaults to `"session+jwt"` (RFC 8725 §3.11). */
  jws?: JWSSessionOptions;
}

/** JWS session hooks, plus the verify key lookup. */
export interface JWSSessionHooks<
  TSession,
  TManager,
  TArgs extends Record<string, unknown>,
  TConfig,
> extends SessionHooks<TSession, TManager, TArgs, TConfig> {
  /** Resolve the verification key(s) for the incoming token from its protected header (e.g. by `kid`). */
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

/** Signs session claims into a compact JWS; verifying validates claims and `typ`, pinning `alg` when configured. */
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
    lookup: (config, args) => {
      const hooks = config.hooks;
      if (!hooks?.onVerifyKeyLookup) return undefined;
      return (header: JWSHeaderParameters) =>
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
  assertPinnedCryptoKey(key, {
    pinned: Boolean(config.jws?.signOptions?.alg),
    prefix,
    hint: '"jws.signOptions.alg"',
  });
}
