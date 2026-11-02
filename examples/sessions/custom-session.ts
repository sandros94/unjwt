// #region docs
import {
  type CookieAttributes,
  type SessionTransportOptions,
  type WebSessionEvent,
  assertSessionConfig,
  assertSessionTokenSource,
  assertSessionWritable,
  claimSessionName,
  resolveSessionTransport,
  webSessionDriver,
} from "unjwt/session";
import { base64UrlStringify, digestUrl, secureRandomBytes } from "unjwt/utils";

// #hide const store = your session store: a database table, Redis, a KV namespace
interface StoredEntry {
  data: Record<string, unknown>;
  expiresAt: number;
}
const entries = new Map<string, StoredEntry>();
const store = {
  get: async (id: string) => structuredClone(entries.get(id)),
  set: async (id: string, entry: StoredEntry) => void entries.set(id, structuredClone(entry)),
  delete: async (id: string) => void entries.delete(id),
};
// #endhide

export interface StoredSessionConfig {
  /** The cookie name, and the base of the `x-<name>-session` header. */
  name: string;
  /** Seconds a session lives after its last update. */
  maxAge?: number;
  sessionHeader?: boolean | string;
  cookie?: false | CookieAttributes;
}

const driver = webSessionDriver({ prefix: "[app-session]" });
const { prefix } = driver;
const defaultCookie: CookieAttributes = {
  path: "/",
  secure: true,
  httpOnly: true,
  sameSite: "lax",
};

export function defineStoredSession<T extends Record<string, unknown>>(
  config: StoredSessionConfig,
) {
  const { name, maxAge = 7 * 24 * 60 * 60, sessionHeader } = config;
  assertSessionConfig(config, { name, prefix, defaultCookie });
  const transportOptions: SessionTransportOptions = {
    name,
    sessionHeader,
    cookie: config.cookie === false ? false : { attrs: { ...defaultCookie, ...config.cookie } },
  };

  return {
    async use(event: WebSessionEvent) {
      claimSessionName(driver.state(event), { name, family: "stored", prefix });
      const transport = resolveSessionTransport(driver, event, transportOptions);
      assertSessionTokenSource(transport, { prefix });

      const token = transport.read();
      const id = token === undefined ? undefined : await digestUrl(token);
      const entry = id === undefined ? undefined : await store.get(id);
      const live = entry && entry.expiresAt > Date.now() ? entry : undefined;
      if (id !== undefined && !live) {
        await store.delete(id);
        if (transport.drop && transport.writable()) transport.drop();
      }

      const session = {
        source: transport.source,
        id: live ? id : undefined,
        token: live ? token : undefined,
        data: (live?.data ?? {}) as Partial<T>,
        async update(data: Partial<T>) {
          assertSessionWritable(transport, { operation: "update", prefix });
          if (session.id) await store.delete(session.id);
          const fresh = base64UrlStringify(secureRandomBytes(32));
          const freshId = await digestUrl(fresh);
          const expiresAt = Date.now() + maxAge * 1000;
          session.data = { ...session.data, ...data };
          await store.set(freshId, { data: session.data, expiresAt });
          transport.write?.(fresh, { expiresAt });
          session.id = freshId;
          session.token = fresh;
        },
        async clear() {
          assertSessionWritable(transport, { operation: "clear", prefix });
          if (session.id) await store.delete(session.id);
          transport.drop?.();
          session.id = undefined;
          session.token = undefined;
          session.data = {};
        },
      };
      return session;
    },
  };
}

export const appSession = defineStoredSession<{ userId: string }>({
  name: "__Host-app",
  maxAge: 24 * 60 * 60,
  sessionHeader: true,
});
// #endregion
