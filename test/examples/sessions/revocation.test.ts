import { describe, expect, it } from "vitest";
import { appSession, signIn, signOutEverywhere } from "../../../examples/sessions/revocation.ts";

function request(cookie?: string): Request {
  return new Request("https://app.example.com/", { headers: cookie ? { cookie } : {} });
}

function cookieOf(response: Response): string {
  return response.headers.getSetCookie()[0]?.split(";", 1)[0] ?? "";
}

describe("examples/sessions/revocation", () => {
  it("keeps a session until the user signs out everywhere, then clears it on read", async () => {
    const cookie = cookieOf(await signIn(request(), "user_1a2b"));
    expect((await appSession.use(request(cookie))).data.userId).toBe("user_1a2b");

    await signOutEverywhere("user_1a2b");
    const headers = new Headers();
    const session = await appSession.use({ req: request(cookie), res: { headers } });
    expect(session.id).toBeUndefined();
    expect(session.data).toEqual({});
    expect(headers.getSetCookie()[0]).toContain("Max-Age=0");

    await new Promise((resolve) => setTimeout(resolve, 2));
    const fresh = cookieOf(await signIn(request(), "user_1a2b"));
    expect((await appSession.use(request(fresh))).id).toEqual(expect.any(String));
  });

  it("clears a session signed in more than 30 days ago, whatever its token says", async () => {
    const token = await appSession.issue({
      userId: "user_3c4d",
      signedInAt: Date.now() - 31 * 24 * 60 * 60 * 1000,
    });
    const session = await appSession.use({ token });
    expect(session.id).toBeUndefined();
  });
});
