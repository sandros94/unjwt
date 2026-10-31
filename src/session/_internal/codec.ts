import type { ExpiresIn, JWTClaims, Duration, JWKAlgorithm } from "../../core/types/index.ts";
import { computeDurationInSeconds } from "../../utils/jwt.ts";
import { isJWKSet } from "../../utils/guards.ts";
import {
  RESERVED_CLAIMS,
  assertImportableKey,
  expiredSessionError,
  readFailedError,
  resolveExpiresAt,
  rethrowAsInvalidToken,
  sessionRequiredClaims,
  sessionTyp,
  invalidTokenError,
} from "./contract.ts";
import type {
  OpenedSession,
  SessionCodec,
  SessionCoreConfig,
  SessionKeys,
  StoredSession,
} from "./types.ts";
import type { ResolvedSessionKeys } from "./key-algorithms.ts";

export type SessionPayload = JWTClaims & { jti: string; iat: number };

/** A family's key lookup hook, called with a token's protected header, the session config and one request's hook arguments. */
export type SessionKeyLookupHook<Header, Found> = (args: {
  header: Header;
  config: unknown;
  [arg: string]: unknown;
}) => Found | Promise<Found>;

/** What a family supplies to build its session codec. */
export interface SessionCodecSpec<
  Config extends SessionCoreConfig,
  IssueKey,
  OpenKey,
  Header,
  Found,
  A extends JWKAlgorithm,
> {
  family: "jws" | "jwe";
  prefix: string;
  defaultName: string;
  defaultCookie: Record<string, unknown>;
  /** Returns the pinned `alg`, the session `typ` and the `currentDate` the session takes as the current time. */
  issueOptions: (
    config: Config,
  ) => { alg?: JWKAlgorithm; currentDate?: Date; protectedHeader?: { typ?: string } } | undefined;
  /** Returns the `clockTolerance` and `requiredClaims` an incoming token is checked with. */
  openOptions: (
    config: Config,
  ) => { clockTolerance?: number | Duration; requiredClaims?: string[] } | undefined;
  /** Resolves and checks the configured keys. Each JWK of the opening key or JWK Set is imported up front under its `alg`. */
  resolveKeys: (config: Config) => ResolvedSessionKeys<IssueKey, OpenKey, A>;
  /** The key lookup hook, when the config sets one. */
  lookup: (config: Config) => SessionKeyLookupHook<Header, Found> | undefined;
  issue: (
    config: Config,
    payload: Record<string, unknown>,
    key: IssueKey,
    alg: A | undefined,
  ) => Promise<string>;
  open: (
    config: Config,
    token: string,
    key: OpenKey | ((lookup: { header: Header }) => Found | Promise<Found>),
    options: SessionOpenOverrides<A>,
  ) => Promise<SessionPayload>;
}

/**
 * Keys are resolved once per config and each configured JWK is imported once. With a key lookup hook, the hook picks each request's
 * open key under the algorithms the configured keys serve. A throwing hook fails the read with `ERR_SESSION_READ_FAILED`. Any other
 * open failure but expiry throws `ERR_SESSION_TOKEN_INVALID`.
 */
export function createSessionCodec<
  Config extends SessionCoreConfig,
  IssueKey,
  OpenKey,
  Header,
  Found,
  A extends JWKAlgorithm,
>(spec: SessionCodecSpec<Config, IssueKey, OpenKey, Header, Found, A>): SessionCodec<Config> {
  const { prefix } = spec;

  const now = (config: Config) => spec.issueOptions(config)?.currentDate?.getTime() ?? Date.now();

  const openWith = async (
    config: Config,
    token: string,
    key: OpenKey | ((lookup: { header: Header }) => Found | Promise<Found>),
    algorithms: A[],
  ): Promise<OpenedSession> => {
    const options = spec.openOptions(config);
    const payload = await spec
      .open(
        config,
        token,
        key,
        sessionOpenOptions({
          maxAge: config.maxAge,
          requiredClaims: options?.requiredClaims,
          typ: spec.issueOptions(config)?.protectedHeader?.typ,
          algorithms,
        }),
      )
      .catch((error: unknown) => rethrowAsInvalidToken(error, { prefix }));
    const clock = { now: now(config), clockTolerance: options?.clockTolerance };
    assertNotFromTheFuture(payload, { ...clock, prefix });
    const opened = openedSession(payload, { maxAge: config.maxAge });
    assertNotPastMaxAge(opened, clock);
    return opened;
  };

  return {
    family: spec.family,
    defaultName: spec.defaultName,
    defaultCookie: spec.defaultCookie,

    now,

    keys: (config): SessionKeys => {
      const { issueKey, issueAlg, key, algorithms } = spec.resolveKeys(config);
      const hook = spec.lookup(config);
      const keyFor = (args: Record<string, unknown>) =>
        hook
          ? ({ header }: { header: Header }) =>
              lookUpKey(hook, { header, ...args, config }, { prefix })
          : key;
      const importable: readonly unknown[] = hook ? [] : isJWKSet(key) ? key.keys : [key];
      const assertOpenKeys = async (): Promise<void> => {
        for (const entry of importable) {
          await assertImportableKey(entry, { alg: undefined, prefix });
        }
      };

      return {
        assertKeys: async () => {
          await assertImportableKey(issueKey, {
            alg: issueAlg ?? spec.issueOptions(config)?.alg,
            prefix,
          });
          await assertOpenKeys();
        },

        issue: (state) => spec.issue(config, sessionPayload(state), issueKey, issueAlg),

        opener: (args) => {
          const opening = keyFor(args);
          return (token) => openWith(config, token, opening, algorithms);
        },

        open: async (token, args) => {
          await assertOpenKeys();
          return openWith(config, token, keyFor(args), algorithms);
        },
      };
    },
  };
}

export interface SessionIssueOverrides {
  expiresIn: undefined;
  expiresAt: undefined;
  notBeforeIn: undefined;
  notBeforeAt: undefined;
  protectedHeader: { typ: string };
}

/** Clears the `exp` and `nbf` options, as `exp` is a claim set from the session lifetime. Sets the session `typ` in the protected header. */
export function sessionIssueOptions<O extends { protectedHeader?: { typ?: string } }>(
  options: O | undefined,
): O & SessionIssueOverrides {
  return Object.assign({}, options, {
    expiresIn: undefined,
    expiresAt: undefined,
    notBeforeIn: undefined,
    notBeforeAt: undefined,
    protectedHeader: {
      ...options?.protectedHeader,
      typ: sessionTyp(options?.protectedHeader?.typ),
    },
  });
}

export interface SessionOpenOverrides<A extends string> {
  requiredClaims: string[];
  typ: string;
  maxTokenAge: undefined;
  algorithms: A[];
  payload: "json";
  validateClaims: true;
}

/** Claim validation, the session `typ` and the `alg` values the keys serve. The session checks `maxAge` itself, not through `maxTokenAge`. */
function sessionOpenOptions<A extends string>(options: {
  maxAge: ExpiresIn | undefined;
  requiredClaims: string[] | undefined;
  typ: string | undefined;
  algorithms: A[];
}): SessionOpenOverrides<A> {
  const { maxAge, requiredClaims, typ, algorithms } = options;
  return {
    requiredClaims: sessionRequiredClaims(requiredClaims, { maxAge }),
    typ: sessionTyp(typ),
    maxTokenAge: undefined,
    algorithms,
    payload: "json",
    validateClaims: true,
  };
}

function sessionPayload(state: StoredSession): Record<string, unknown> {
  const iat = Math.floor(state.createdAt / 1000);
  const exp = state.expiresAt ? Math.floor(state.expiresAt / 1000) : undefined;
  const payload: Record<string, unknown> = {};
  for (const key of Object.keys(state.data)) {
    if (!RESERVED_CLAIMS.includes(key)) payload[key] = state.data[key];
  }
  payload.jti = state.id;
  payload.iat = iat;
  if (exp) payload.exp = exp;
  return payload;
}

/** A session issued after the current time is refused whatever its `exp`. `clockTolerance` widens that bound (RFC 7519 §4.1.6). */
function assertNotFromTheFuture(
  payload: SessionPayload,
  options: { now: number; clockTolerance: number | Duration | undefined; prefix: string },
): void {
  if (payload.iat > Math.floor(options.now / 1000) + toleranceSeconds(options.clockTolerance)) {
    throw invalidTokenError(
      `${options.prefix} Invalid session token: "iat" is in the future (${new Date(payload.iat * 1000).toISOString()}).`,
    );
  }
}

/** A session past `iat + maxAge` is expired whatever its `exp`, as `exp` itself is (RFC 7519 §4.1.4). */
function assertNotPastMaxAge(
  opened: OpenedSession,
  options: { now: number; clockTolerance: number | Duration | undefined },
): void {
  const { expiresAt } = opened;
  if (expiresAt === undefined) return;
  if (expiresAt <= options.now - toleranceSeconds(options.clockTolerance) * 1000) {
    throw expiredSessionError({ id: opened.id, createdAt: opened.createdAt, expiresAt });
  }
}

/** Runs the key lookup hook. Whatever it throws is a read failure, not the token's. */
async function lookUpKey<Header, Found>(
  hook: SessionKeyLookupHook<Header, Found>,
  args: Parameters<SessionKeyLookupHook<Header, Found>>[0],
  options: { prefix: string },
): Promise<Found> {
  try {
    return await hook(args);
  } catch (error) {
    throw readFailedError(error, options);
  }
}

function toleranceSeconds(clockTolerance: number | Duration | undefined): number {
  return clockTolerance === undefined ? 0 : computeDurationInSeconds(clockTolerance);
}

/** With a `maxAge`, the session ends at `exp` or at `iat + maxAge`, whichever comes first. */
function openedSession(
  payload: SessionPayload,
  options: { maxAge: ExpiresIn | undefined },
): OpenedSession {
  const data: Record<string, unknown> = Object.create(null);
  for (const key of Object.keys(payload)) {
    if (RESERVED_CLAIMS.includes(key)) continue;
    data[key] = payload[key];
  }
  const createdAt = payload.iat * 1000;
  const exp = payload.exp ? payload.exp * 1000 : undefined;
  const bound = resolveExpiresAt(createdAt, options);
  return {
    id: payload.jti,
    createdAt,
    expiresAt: exp === undefined || bound === undefined ? (exp ?? bound) : Math.min(exp, bound),
    data,
  };
}
