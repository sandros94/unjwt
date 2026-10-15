import type { ExpiresIn, JWTClaims } from "../core/types";
import { isCryptoKey, isPrivateJWK, isSymmetricJWK } from "../core/utils/guards";
import {
  RESERVED_CLAIMS,
  assertImportableKey,
  invalidConfigError,
  invalidKeyError,
  rethrowAsInvalidToken,
  sessionRequiredClaims,
  sessionTyp,
} from "./_session";
import type {
  OpenedSession,
  SessionCodec,
  SessionCoreConfig,
  StoredSession,
} from "./_session-core";

export type SessionPayload = JWTClaims & { jti: string; iat: number };

/** What a family supplies to build its session codec. */
export interface SessionCodecSpec<Config extends SessionCoreConfig, IssueKey, OpenKey> {
  family: "jws" | "jwe";
  prefix: string;
  defaultName: string;
  defaultCookie: Record<string, unknown>;
  /** Supplies the pinned `alg` and the `currentDate` the session runs on. */
  issueOptions: (config: Config) => { alg?: string; currentDate?: Date } | undefined;
  issueKey: (config: Config) => IssueKey;
  openKey: (config: Config) => OpenKey;
  lookup: (config: Config, carrier: Record<string, unknown>) => OpenKey | undefined;
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

  const keyFor = (config: Config, carrier: Record<string, unknown>): OpenKey =>
    spec.lookup(config, carrier) ?? spec.openKey(config);

  const openWith = async (config: Config, token: string, key: OpenKey): Promise<OpenedSession> =>
    openedSession(
      await spec
        .open(config, token, key)
        .catch((error: unknown) => rethrowAsInvalidToken(error, { prefix })),
    );

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

    now: (config) => spec.issueOptions(config)?.currentDate?.getTime() ?? Date.now(),

    issuer: (config) => {
      const key = spec.issueKey(config);
      return (state) => spec.issue(config, sessionPayload(state), key);
    },

    assertKeys: async (config) => {
      const key = spec.issueKey(config);
      await assertImportableKey(key, { alg: alg(config), prefix });
      if (!isSymmetricJWK(key)) await assertOpenKey(config);
    },

    opener: (config, carrier) => {
      const key = keyFor(config, carrier);
      return (token) => openWith(config, token, key);
    },

    open: async (config, token, carrier) => {
      await assertOpenKey(config);
      return openWith(config, token, keyFor(config, carrier));
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

/** Claim validation, session `typ` and pinned `alg`; a token's life is bounded by `exp`, never `maxTokenAge`. */
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
      `${options.prefix} A CryptoKey session key carries no algorithm: set ${options.hint}.`,
    );
  }
}

function sessionPayload(state: StoredSession): Record<string, unknown> {
  const iat = Math.floor(state.createdAt / 1000);
  const exp = state.expiresAt ? Math.floor(state.expiresAt / 1000) : undefined;
  const payload: Record<string, unknown> = { ...state.data, jti: state.id, iat };
  if (exp) payload.exp = exp;
  return payload;
}

function openedSession(payload: SessionPayload): OpenedSession {
  const data: Record<string, unknown> = Object.create(null);
  for (const key of Object.keys(payload)) {
    if (RESERVED_CLAIMS.includes(key)) continue;
    data[key] = payload[key];
  }
  return {
    id: payload.jti,
    createdAt: payload.iat * 1000,
    expiresAt: payload.exp ? payload.exp * 1000 : undefined,
    data,
  };
}
