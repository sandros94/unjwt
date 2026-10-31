import { afterEach, describe, expect, it, vi } from "vitest";
import { generateJWK } from "unjwt/jwk";
import { defineJWESession } from "unjwt/session";

async function load(env: { kid: string | undefined; keys: Record<string, unknown> }) {
  vi.resetModules();
  vi.stubEnv("SESSION_KEY_ID", env.kid);
  vi.stubEnv(
    "SECRETS",
    JSON.stringify(
      Object.fromEntries(
        Object.entries(env.keys).map(([kid, key]) => [`session-keys/${kid}`, JSON.stringify(key)]),
      ),
    ),
  );
  return import("../../../examples/sessions/key-lookup.ts");
}

function headerOf(token: string): { kid?: string } {
  const [header = ""] = token.split(".");
  return JSON.parse(atob(header.replaceAll("-", "+").replaceAll("_", "/")));
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("examples/sessions/key-lookup", async () => {
  const [current, previous] = await Promise.all(
    ["2026-10", "2026-09"].map((kid) => generateJWK("A256KW", { kid })),
  );
  const issuedBy = (key: typeof current) =>
    defineJWESession({ key, maxAge: "7D" }).issue({ userId: "user_1a2b" });

  it("refuses to load without SESSION_KEY_ID, or when the secret manager lacks that key", async () => {
    await expect(load({ kid: undefined, keys: {} })).rejects.toThrow("SESSION_KEY_ID is not set");
    await expect(load({ kid: "2026-10", keys: {} })).rejects.toThrow(
      'No session key "2026-10" in the secret manager',
    );
  });

  it("issues with the current key and opens tokens of any key the secret manager holds", async () => {
    const { appSession } = await load({
      kid: "2026-10",
      keys: { "2026-10": current, "2026-09": previous },
    });
    const fresh = await appSession.issue({ userId: "user_1a2b" });

    expect(headerOf(fresh).kid).toBe("2026-10");
    expect((await appSession.open(fresh)).data).toEqual({ userId: "user_1a2b" });
    expect((await appSession.open(await issuedBy(previous))).data).toEqual({
      userId: "user_1a2b",
    });
  });

  it("follows the secret manager without a restart, and drops the cookie of a removed key", async () => {
    const { appSession, secretStore } = await load({
      kid: "2026-10",
      keys: { "2026-10": current },
    });
    const old = await issuedBy(previous);
    await expect(appSession.open(old)).rejects.toMatchObject({
      code: "ERR_SESSION_TOKEN_INVALID",
      cause: { code: "ERR_JWK_KEY_NOT_FOUND" },
    });

    secretStore.set("session-keys/2026-09", JSON.stringify(previous));
    expect((await appSession.open(old)).data).toEqual({ userId: "user_1a2b" });

    secretStore.delete("session-keys/2026-09");
    const headers = new Headers();
    const req = new Request("https://app.example.com/", {
      headers: { cookie: `__Host-unjwt-jwe=${old}` },
    });
    const session = await appSession.use({ req, res: { headers } });
    expect(session.id).toBeUndefined();
    expect(headers.get("set-cookie")).toContain("__Host-unjwt-jwe=;");
  });

  it("keeps the cookie when the secret manager fails", async () => {
    const { appSession, secretStore } = await load({
      kid: "2026-10",
      keys: { "2026-10": current },
    });
    const fresh = await appSession.issue({ userId: "user_1a2b" });
    vi.spyOn(secretStore, "get").mockImplementation(() => {
      throw new Error("secret manager unavailable");
    });
    const headers = new Headers();
    const req = new Request("https://app.example.com/", {
      headers: { cookie: `__Host-unjwt-jwe=${fresh}` },
    });
    const session = await appSession.use({ req, res: { headers } });

    expect(session.id).toBeUndefined();
    expect(headers.get("set-cookie")).toBeNull();
    await expect(appSession.open(fresh)).rejects.toMatchObject({
      code: "ERR_SESSION_READ_FAILED",
      cause: { message: "secret manager unavailable" },
    });
  });
});
