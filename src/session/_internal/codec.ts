import type { ExpiresIn, JWTClaims, Duration, JWKAlgorithm } from "../../core/types/index.ts";
import { computeDurationInSeconds } from "../../utils/jwt.ts";
import { isCryptoKey, isPrivateJWK } from "../../utils/guards.ts";
import {
  RESERVED_CLAIMS,
  assertImportableKey,
  expiredSessionError,
  invalidKeyError,
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

export type SessionPayload = JWTClaims & { jti: string; iat: number };

/** A configured key and the `alg` it is imported under, `undefined` for a key that names its own. */
export interface ImportableKey {
  key: unknown;
  alg: JWKAlgorithm | undefined;
}

/** What a family supplies to build its session codec. */
export interface SessionCodecSpec<Config extends SessionCoreConfig, IssueKey, OpenKey> {
  family: "jws" | "jwe";
  prefix: string;
  defaultName: string;
  defaultCookie: Record<string, unknown>;
  /** Returns the pinned `alg` and the `currentDate` the session takes as the current time. */
  issueOptions: (config: Config) => { alg?: JWKAlgorithm; currentDate?: Date } | undefined;
  /** Returns the `clockTolerance` an incoming token is checked with. */
  openOptions: (config: Config) => { clockTolerance?: number | Duration } | undefined;
  issueKey: (config: Config) => IssueKey;
  openKey: (config: Config) => OpenKey;
  /** With a key lookup hook set, returns the open key for a request's hook arguments. */
  lookup: (config: Config) => ((args: Record<string, unknown>) => OpenKey) | undefined;
  /** The keys that open tokens, each to import up front under the `alg` it serves. */
  importable: (config: Config) => readonly ImportableKey[];
  issue: (config: Config, payload: Record<string, unknown>, key: IssueKey) => Promise<string>;
  open: (config: Config, token: string, key: OpenKey) => Promise<SessionPayload>;
}

/** Keys are resolved once per config and each configured JWK is imported once. Open failures other than expiry throw `ERR_SESSION_TOKEN_INVALID`. */
export function createSessionCodec<Config extends SessionCoreConfig, IssueKey, OpenKey>(
  spec: SessionCodecSpec<Config, IssueKey, OpenKey>,
): SessionCodec<Config> {
  const { prefix } = spec;

  const now = (config: Config) => spec.issueOptions(config)?.currentDate?.getTime() ?? Date.now();

  const openWith = async (config: Config, token: string, key: OpenKey): Promise<OpenedSession> => {
    const payload = await spec
      .open(config, token, key)
      .catch((error: unknown) => rethrowAsInvalidToken(error, { prefix }));
    const clock = { now: now(config), clockTolerance: spec.openOptions(config)?.clockTolerance };
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
      const issueKey = spec.issueKey(config);
      const { keyFor, importable } = openingKeys(spec, config);
      const assertOpenKeys = async (): Promise<void> => {
        for (const { key, alg } of importable) await assertImportableKey(key, { alg, prefix });
      };

      return {
        assertKeys: async () => {
          await assertImportableKey(issueKey, { alg: spec.issueOptions(config)?.alg, prefix });
          await assertOpenKeys();
        },

        issue: (state) => spec.issue(config, sessionPayload(state), issueKey),

        opener: (args) => {
          const key = keyFor(args);
          return (token) => openWith(config, token, key);
        },

        open: async (token, args) => {
          await assertOpenKeys();
          return openWith(config, token, keyFor(args));
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

/** Claim validation, the session `typ` and the `alg` values the keys serve. The session checks `maxAge` itself, not through `maxTokenAge`. */
export function sessionOpenOptions<A extends string>(options: {
  maxAge: ExpiresIn | undefined;
  requiredClaims: string[] | undefined;
  typ: string | undefined;
  algorithms: A[];
}): {
  requiredClaims: string[];
  typ: string;
  maxTokenAge: undefined;
  algorithms: A[];
  payload: "json";
  validateClaims: true;
} {
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

export function isKeyPair(key: object): key is { privateKey?: unknown; publicKey?: unknown } {
  return "privateKey" in key || "publicKey" in key;
}

/** Checks both halves of a pair, whichever one the caller is about to use. */
export function assertKeyPair(
  pair: { privateKey?: unknown; publicKey?: unknown },
  options: {
    prefix: string;
    family: "JWS" | "JWE";
    isPublic: (half: unknown) => boolean;
    publicHalf: string;
  },
): void {
  const { prefix, family } = options;
  if (!isCryptoKey(pair.privateKey) && !isPrivateJWK(pair.privateKey)) {
    throw invalidKeyError(
      `${prefix} Invalid ${family} key: "privateKey" must be a private JWK or a CryptoKey.`,
      pair,
    );
  }
  if (!options.isPublic(pair.publicKey)) {
    throw invalidKeyError(
      `${prefix} Invalid ${family} key: "publicKey" must be ${options.publicHalf}.`,
      pair,
    );
  }
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

/** With a lookup hook, the hook picks each request's open key. Otherwise the configured key opens every token and is imported before the first open. */
function openingKeys<Config extends SessionCoreConfig, IssueKey, OpenKey>(
  spec: SessionCodecSpec<Config, IssueKey, OpenKey>,
  config: Config,
): { keyFor: (args: Record<string, unknown>) => OpenKey; importable: readonly ImportableKey[] } {
  const lookup = spec.lookup(config);
  if (lookup) return { keyFor: lookup, importable: [] };
  const key = spec.openKey(config);
  return { keyFor: () => key, importable: spec.importable(config) };
}
