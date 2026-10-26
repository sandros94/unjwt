import { describe, expect, it } from "vitest";
import { Elysia } from "elysia";
import { generateJWK } from "unjwt/jwk";
import { jweSession } from "unjwt/adapters/elysia";
import {
  accountTokenFor,
  apiTokenFor,
  handle,
  handleAccount,
  handleApi,
} from "../../../examples/sessions/elysia-app.ts";

const origin = "https://app.example.com";

function cookieOf(response: Response): string {
  return response.headers.getSetCookie()[0]?.split(";", 1)[0] ?? "";
}

describe("examples/sessions/elysia-app", () => {
  it("logs in, guards /me, logs out", async () => {
    const login = await handle(
      new Request(`${origin}/login`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ userId: "user_1a2b" }),
      }),
    );
    expect(login.status).toBe(200);
    expect(typeof (await login.json()).expiresAt).toBe("number");
    const [line = ""] = login.headers.getSetCookie();
    for (const part of ["Path=/", "HttpOnly", "Secure", "SameSite=Lax"])
      expect(line).toContain(part);
    const cookie = cookieOf(login);
    expect(cookie).toMatch(/^__Host-elysia-jwe=/);

    const me = await handle(new Request(`${origin}/me`, { headers: { cookie } }));
    expect(me.status).toBe(200);
    expect(await me.json()).toEqual({ userId: "user_1a2b" });

    expect((await handle(new Request(`${origin}/me`))).status).toBe(401);

    const logout = await handle(
      new Request(`${origin}/logout`, { method: "POST", headers: { cookie } }),
    );
    expect(await logout.json()).toEqual({ signedOut: true });
    expect(logout.headers.getSetCookie()[0]).toContain("Max-Age=0");
  });

  it("reads an issued API token from the Authorization header under ctx.api", async () => {
    const token = await apiTokenFor("user_1a2b");
    const ok = await handleApi(
      new Request(`${origin}/api/whoami`, { headers: { authorization: `Bearer ${token}` } }),
    );
    expect(ok.status).toBe(200);
    expect(await ok.json()).toEqual({ userId: "user_1a2b", scope: "read" });
    expect(ok.headers.getSetCookie()).toEqual([]);

    expect((await handleApi(new Request(`${origin}/api/whoami`))).status).toBe(401);
  });
});

describe("examples/sessions/elysia-app: a definition in resolve", () => {
  it("reads the cookie the definition reads", async () => {
    const token = await accountTokenFor("user_1a2b");
    const response = await handleAccount(
      new Request(`${origin}/account`, { headers: { cookie: `__Host-account=${token}` } }),
    );
    expect(await response.json()).toEqual({ userId: "user_1a2b" });
  });
});

describe("Elysia plugin: hooks receive the context", () => {
  it("onError sees the request headers", async () => {
    const key = await generateJWK("A256GCM");
    const seen: string[] = [];
    const app = new Elysia()
      .use(
        jweSession({
          key,
          maxAge: "7D",
          hooks: {
            onError: ({ context, error }) => {
              seen.push(`${error.code} ${context.request.headers.get("user-agent")}`);
            },
          },
        }),
      )
      .get("/", ({ session }) => session.id ?? "none");
    const response = await app.handle(
      new Request(`${origin}/`, {
        headers: { "cookie": "__Host-elysia-jwe=tampered", "user-agent": "curl/8.7.1" },
      }),
    );
    expect(await response.text()).toBe("none");
    expect(seen).toEqual(["ERR_SESSION_TOKEN_INVALID curl/8.7.1"]);
  });
});
