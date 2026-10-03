import { sign, verify } from "../core/jws";
import { isCryptoKey, isJWKSet, isSymmetricJWK, isPrivateJWK, isPublicJWK } from "../core/utils";
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
  JWKLookupFunctionHeader,
  JWTClaimValidationOptions,
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
 * Key used for signing — a symmetric `oct` (HS*) JWK, a `CryptoKey`, or an
 * asymmetric pair: the private key signs, the public side verifies (single
 * JWK, array, or JWKSet for rotation). A `CryptoKey` carries no algorithm, so
 * it additionally requires `jws.signOptions.alg`.
 */
export type JWSSessionKey =
  | CryptoKey
  | JWK_oct<JWK_HMAC>
  | {
      privateKey: JWSAsymmetricPrivateJWK | CryptoKey;
      publicKey: JWSAsymmetricPublicJWK | JWSAsymmetricPublicJWK[] | JWKSet | CryptoKey;
    };

/**
 * JWS claim-validation overrides a session accepts — everything the adapter
 * does not own itself. A session token's life is bounded by its own `exp`, and
 * its `typ` is the one the session signs with, so neither `maxTokenAge` nor
 * `typ` is the caller's to set here.
 */
export type SessionVerifyOptions = StrictOmit<JWTClaimValidationOptions, "maxTokenAge" | "typ">;

/**
 * JWS sign options a session accepts. `exp` and `nbf` are the adapter's to
 * mint — `exp` from `maxAge`, never an `nbf` — so the options that would set
 * them are not the caller's.
 */
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
> {
  /** Key used for signing — see {@link JWSSessionKey}. */
  key: JWSSessionKey;
  /**
   * Session lifetime — sets `exp = iat + maxAge` in the token, requires an
   * incoming token to carry an `exp`, and drives the cookie expiry. Without it
   * the session writes no `exp` and never expires on its own.
   */
  maxAge?: MaxAge;
  /**
   * Session name — drives the cookie name and the default session header.
   * Prefer a `__Host-` prefix; a name ending in a dot and digits is refused.
   */
  name?: string;
  /**
   * Cookie options (`false` to disable). Defaults: `path="/"`, `secure`, `sameSite: "lax"`, `httpOnly: false` — the JWS payload is client-readable by design.
   * With a lifetime, `expires` follows the token's `exp` and `maxAge` is dropped.
   */
  cookie?: false | (TCookie & { chunkMaxLength?: number });
  /**
   * Request header to read the token from (`false` to disable), as a bare token
   * or `Bearer <token>`. Must be a header name. Default `x-<name>-session`.
   */
  sessionHeader?: false | string;
  /** Session ID (`jti`) generator. Default `crypto.randomUUID`. */
  generateId?: () => string;
  /** JWS sign/verify overrides. Set `signOptions.alg` to pin the session algorithm — verification then accepts only it. */
  jws?: JWSSessionOptions;
}

/** The JWS config as the codec reads it, whatever framework declares it. */
export interface JWSCodecConfig extends SessionCoreConfig {
  key: JWSSessionKey;
  jws?: JWSSessionOptions;
  hooks?: SessionCoreHooks & {
    onVerifyKeyLookup?: (args: {
      header: JWKLookupFunctionHeader;
      config: any;
      [carrier: string]: unknown;
    }) => JWKSet | JWSVerifyJWK | Promise<JWKSet | JWSVerifyJWK>;
  };
}

/** Cookie attributes a JWS session writes unless the config overrides them. */
export const JWS_DEFAULT_COOKIE = {
  path: "/",
  secure: true,
  httpOnly: false,
  sameSite: "lax",
} as const;

/**
 * The JWS half of a session: sign the session claims into a compact token, and
 * verify one back.
 *
 * Verification always runs claim validation (`jti` & `iat` required, `exp`
 * honoured and required alongside a `maxAge`), checks the `typ` and `cty`
 * headers, and pins the algorithm when the config does.
 */
export function createJWSCodec(options: {
  prefix: string;
  defaultName: string;
}): SessionCodec<JWSCodecConfig> {
  const { prefix, defaultName } = options;

  const openKey = (config: JWSCodecConfig, carrier: Record<string, unknown>): unknown =>
    config.hooks?.onVerifyKeyLookup
      ? (header: JWKLookupFunctionHeader) =>
          config.hooks!.onVerifyKeyLookup!({ header, ...carrier, config })
      : getVerifyKey(config, prefix);

  const assertVerifyKey = async (config: JWSCodecConfig): Promise<void> => {
    if (config.hooks?.onVerifyKeyLookup) return;
    const alg = config.jws?.signOptions?.alg;
    const key = getVerifyKey(config, prefix);
    for (const candidate of isJWKSet(key) ? key.keys : [key]) {
      await assertImportableKey(candidate, { alg, prefix });
    }
  };

  return {
    family: "jws",
    defaultName,
    defaultCookie: JWS_DEFAULT_COOKIE,

    now: (config) => config.jws?.signOptions?.currentDate?.getTime() ?? Date.now(),

    issueKey: (config) => getSignKey(config, prefix),

    assertKeys: async (config) => {
      const key = getSignKey(config, prefix);
      await assertImportableKey(key, { alg: config.jws?.signOptions?.alg, prefix });
      if (!isSymmetricJWK(key)) await assertVerifyKey(config);
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

      return sign(payload as Record<string, unknown>, key as JWSSignJWK, {
        ...config.jws?.signOptions,
        // `exp` is computed from the session lifetime and carried via the claim
        // above; a session never writes `nbf`.
        expiresIn: undefined,
        expiresAt: undefined,
        notBeforeIn: undefined,
        notBeforeAt: undefined,
        protectedHeader: {
          ...config.jws?.signOptions?.protectedHeader,
          kid: "kid" in (key as object) ? (key as JWSSignJWK).kid : undefined,
          typ: sessionTyp(config.jws?.signOptions?.protectedHeader?.typ),
          cty: SESSION_CONTENT_TYPE,
        },
      });
    },

    open: async (config, token, carrier, key) => {
      const alg = config.jws?.signOptions?.alg;
      if (key === undefined) await assertVerifyKey(config);
      const jwk = key ?? openKey(config, carrier);

      const { payload, protectedHeader } = await verify<{ jti: string; iat: number }>(
        token,
        jwk as JWSVerifyJWK,
        {
          ...config.jws?.verifyOptions,
          requiredClaims: sessionRequiredClaims(config.jws?.verifyOptions?.requiredClaims, {
            maxAge: config.maxAge,
          }),
          typ: sessionTyp(config.jws?.signOptions?.protectedHeader?.typ),
          maxTokenAge: undefined,
          algorithms: alg ? [alg] : undefined,
          payload: "json",
          validateClaims: true,
        },
      ).catch((error_: unknown) => rethrowAsInvalidToken(error_, { prefix, token, family: "JWS" }));

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

function getSignKey(config: JWSCodecConfig, prefix: string): JWSSignJWK | CryptoKey {
  const key = config.key;
  assertKeyMaterial(key, { prefix });

  let _key: JWSSignJWK | CryptoKey | undefined;
  if (isCryptoKey(key)) {
    _key = key;
  } else if (isSymmetricJWK(key)) {
    _key = key;
  } else if ("privateKey" in key) {
    const privateKey = key.privateKey;
    if (isCryptoKey(privateKey) || isPrivateJWK(privateKey)) _key = privateKey;
  }

  if (!_key) {
    throw invalidKeyError(
      `${prefix} Invalid JWS key. It must be a symmetric JWK, a private JWK, or a CryptoKey.`,
      key,
    );
  }

  assertPinnedAlg(_key, config, prefix);
  return _key;
}

function getVerifyKey(config: JWSCodecConfig, prefix: string): JWSVerifyJWK | JWKSet | CryptoKey {
  const key = config.key;
  assertKeyMaterial(key, { prefix });

  let _key: JWSVerifyJWK | JWKSet | CryptoKey | undefined;
  if (isCryptoKey(key)) {
    _key = key;
  } else if (isSymmetricJWK(key)) {
    _key = key;
  } else if ("publicKey" in key) {
    const publicKey = key.publicKey;
    if (isCryptoKey(publicKey)) {
      _key = publicKey;
    } else if (isPublicJWK(publicKey)) {
      _key = publicKey;
    } else if (Array.isArray(publicKey)) {
      const keys = publicKey.filter((candidate) => isPublicJWK(candidate));
      if (keys.length > 0) {
        _key = { keys };
      }
    } else if (
      publicKey &&
      typeof publicKey === "object" &&
      Array.isArray((publicKey as JWKSet).keys)
    ) {
      const keys = (publicKey as JWKSet).keys.filter((candidate) => isPublicJWK(candidate));
      if (keys.length > 0) {
        _key = { keys };
      }
    }
  }

  if (!_key) {
    throw invalidKeyError(
      `${prefix} Invalid JWS key. It must be a symmetric JWK, a public JWK/set, or a CryptoKey.`,
      key,
    );
  }

  assertPinnedAlg(_key, config, prefix);
  return _key;
}

function assertPinnedAlg(key: unknown, config: JWSCodecConfig, prefix: string): void {
  if (isCryptoKey(key) && !config.jws?.signOptions?.alg) {
    throw invalidConfigError(
      `${prefix} A CryptoKey session key carries no algorithm: set "jws.signOptions.alg".`,
    );
  }
}
