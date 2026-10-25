import type { ExpiresIn, JWTClaims, Duration, JWKAlgorithm } from "../../core/types/index.ts";
import { computeDurationInSeconds } from "../../utils/jwt.ts";
import { isCryptoKey, isPrivateJWK, isSymmetricJWK } from "../../utils/guards.ts";
import {
  RESERVED_CLAIMS,
  assertImportableKey,
  expiredSessionError,
  invalidConfigError,
  invalidKeyError,
  resolveExpiresAt,
  rethrowAsInvalidToken,
  sessionRequiredClaims,
  sessionTyp,
  invalidTokenError,
} from "./contract.ts";
import type { OpenedSession, SessionCodec, SessionCoreConfig, StoredSession } from "./types.ts";

export type SessionPayload = JWTClaims & { jti: string; iat: number };

/** What a family supplies to build its session codec. */
export interface SessionCodecSpec<Config extends SessionCoreConfig, IssueKey, OpenKey> {
  family: "jws" | "jwe";
  prefix: string;
  defaultName: string;
  defaultCookie: Record<string, unknown>;
  /** Supplies the pinned `alg` and the `currentDate` the session runs on. */
  issueOptions: (config: Config) => { alg?: JWKAlgorithm; currentDate?: Date } | undefined;
  /** Supplies the `clockTolerance` an incoming token is read with. */
  openOptions: (config: Config) => { clockTolerance?: number | Duration } | undefined;
  issueKey: (config: Config) => IssueKey;
  openKey: (config: Config) => OpenKey;
  lookup: (config: Config, args: Record<string, unknown>) => OpenKey | undefined;
  /** The JWKs of an open key to import up front. */
  importable?: (key: OpenKey) => readonly unknown[];
  issue: (config: Config, payload: Record<string, unknown>, key: IssueKey) => Promise<string>;
  open: (config: Config, token: string, key: OpenKey) => Promise<SessionPayload>;
}

/** Keys resolve before any token is read, each configured key checked once per key object; open failures other than expiry become `ERR_SESSION_TOKEN_INVALID`. */
export function createSessionCodec<Config extends SessionCoreConfig, IssueKey, OpenKey>(
  spec: SessionCodecSpec<Config, IssueKey, OpenKey>,
): SessionCodec<Config> {
  const { prefix } = spec;
  const alg = (config: Config) => spec.issueOptions(config)?.alg;

  const keyFor = (config: Config, args: Record<string, unknown>): OpenKey =>
    spec.lookup(config, args) ?? spec.openKey(config);

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

  const assertOpenKey = async (config: Config): Promise<void> => {
    if (spec.lookup(config, {})) return;
    const key = spec.openKey(config);
    for (const candidate of spec.importable ? spec.importable(key) : [key]) {
      await assertImportableKey(candidate, { alg: alg(config), prefix });
    }
  };

  return {
    family: spec.family,
    defaultName: spec.defaultName,
    defaultCookie: spec.defaultCookie,

    now,

    issuer: (config) => {
      const key = spec.issueKey(config);
      return (state) => spec.issue(config, sessionPayload(state), key);
    },

    assertKeys: async (config) => {
      const key = spec.issueKey(config);
      await assertImportableKey(key, { alg: alg(config), prefix });
      if (!isSymmetricJWK(key)) await assertOpenKey(config);
    },

    opener: (config, args) => {
      const key = keyFor(config, args);
      return (token) => openWith(config, token, key);
    },

    open: async (config, token, args) => {
      await assertOpenKey(config);
      return openWith(config, token, keyFor(config, args));
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

/** `exp` comes from the session lifetime as a claim, never `nbf`; the header carries the session `typ`. */
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

/** Claim validation, session `typ` and pinned `alg`; `maxAge` bounds a token's life in the session layer, not through `maxTokenAge`. */
export function sessionOpenOptions<A extends string>(options: {
  maxAge: ExpiresIn | undefined;
  requiredClaims: string[] | undefined;
  typ: string | undefined;
  alg: A | undefined;
}): {
  requiredClaims: string[];
  typ: string;
  maxTokenAge: undefined;
  algorithms: A[] | undefined;
  payload: "json";
  validateClaims: true;
} {
  const { maxAge, requiredClaims, typ, alg } = options;
  return {
    requiredClaims: sessionRequiredClaims(requiredClaims, { maxAge }),
    typ: sessionTyp(typ),
    maxTokenAge: undefined,
    algorithms: alg ? [alg] : undefined,
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

/** A `CryptoKey` carries no algorithm: it serves a session only with the config's algorithm pinned. */
export function assertPinnedCryptoKey(
  key: unknown,
  options: { pinned: boolean; prefix: string; hint: string },
): void {
  if (isCryptoKey(key) && !options.pinned) {
    throw invalidConfigError(
      `${options.prefix} A CryptoKey session key carries no algorithm, set ${options.hint}.`,
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

/** A session issued after "now" is refused whatever its `exp`; `clockTolerance` widens "now" (RFC 7519 §4.1.6). */
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
