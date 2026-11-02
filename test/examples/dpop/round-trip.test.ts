import { describe, expect, it, vi } from "vitest";
import { createDPoPProof, verifyDPoPProof } from "unjwt/dpop";
import { generateJWK, thumbprint } from "unjwt/jwk";
import { createClient } from "../../../examples/dpop/client.ts";
import {
  consumeOnce,
  currentNonce,
  ordersEndpoint,
  tokenEndpoint,
} from "../../../examples/dpop/server.ts";

function server() {
  const requests: Request[] = [];
  const send = vi.fn(async (request: Request) => {
    requests.push(request.clone());
    const { pathname } = new URL(request.url);
    if (pathname === "/token") return tokenEndpoint(request, "user_1a2b");
    if (pathname === "/orders") return ordersEndpoint(request);
    return new Response(null, { status: 404 });
  });
  return { send, requests };
}

async function login(client: Awaited<ReturnType<typeof createClient>>): Promise<string> {
  const response = await client.request("POST", "https://auth.example.com/token");
  expect(response.status).toBe(200);
  const body = (await response.json()) as { access_token: string; token_type: string };
  expect(body.token_type).toBe("DPoP");
  return body.access_token;
}

describe("examples/dpop", () => {
  it("gets a bound token and calls the API, retrying once for a nonce", async () => {
    const { send } = server();
    const client = await createClient(send);
    const token = await login(client);
    const response = await client.request("GET", "https://api.example.com/orders", token);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ sub: "user_1a2b", orders: [] });
    expect(send).toHaveBeenCalledTimes(3);

    await client.request("GET", "https://api.example.com/orders?page=2", token);
    expect(send).toHaveBeenCalledTimes(4);
  });

  it("asks again after the nonce rotates", async () => {
    const { send } = server();
    const client = await createClient(send);
    const token = await login(client);
    await client.request("GET", "https://api.example.com/orders", token);
    currentNonce(Date.now() + 6 * 60_000);
    send.mockClear();
    expect((await client.request("GET", "https://api.example.com/orders", token)).status).toBe(200);
    expect(send).toHaveBeenCalledTimes(2);
  });

  it("refuses a replayed request", async () => {
    const { send, requests } = server();
    const client = await createClient(send);
    const token = await login(client);
    await client.request("GET", "https://api.example.com/orders", token);
    const replay = await ordersEndpoint(requests.at(-1)!);
    expect(replay.status).toBe(401);
    expect(replay.headers.get("www-authenticate")).toContain('error="invalid_dpop_proof"');
  });

  it("refuses a token presented by another key", async () => {
    const owner = await createClient(server().send);
    const token = await login(owner);
    const { send } = server();
    const thief = await createClient(send);
    const response = await thief.request("GET", "https://api.example.com/orders", token);
    expect(response.status).toBe(401);
    expect(response.headers.get("www-authenticate")).toContain('error="invalid_dpop_proof"');
  });

  it("refuses a missing or doubled DPoP header", async () => {
    const proof = await createDPoPProof(
      { method: "GET", url: "https://api.example.com/orders" },
      { keyPair: await generateJWK("ES256") },
    );
    const cases: HeadersInit[] = [
      { authorization: "DPoP abc" },
      { authorization: "DPoP abc", dpop: `${proof}, ${proof}` },
    ];
    for (const headers of cases) {
      const response = await ordersEndpoint(
        new Request("https://api.example.com/orders", { headers }),
      );
      expect(response.headers.get("www-authenticate")).toContain('error="invalid_request"');
    }
  });

  it("refuses a proof for another URL at the token endpoint", async () => {
    const proof = await createDPoPProof(
      { method: "POST", url: "https://auth.example.com/authorize" },
      { keyPair: await generateJWK("ES256") },
    );
    const request = new Request("https://auth.example.com/token", {
      method: "POST",
      headers: { dpop: proof },
    });
    const response = await tokenEndpoint(request, "user_1a2b");
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid_dpop_proof" });
  });

  it("consumes each proof once", async () => {
    const keyPair = await generateJWK("ES256");
    const target = { method: "GET", url: "https://api.example.com/orders" };
    const result = await verifyDPoPProof(await createDPoPProof(target, { keyPair }), target, {
      algorithms: ["ES256"],
      maxTokenAge: 60,
    });
    expect(result.thumbprint).toBe(await thumbprint(keyPair.publicKey));
    expect(await consumeOnce(result)).toBe(true);
    expect(await consumeOnce(result)).toBe(false);
  });
});
