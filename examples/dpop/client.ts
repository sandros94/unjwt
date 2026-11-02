// #region docs
import { createDPoPProof } from "unjwt/dpop";
import { generateJWK } from "unjwt/jwk";

type Send = (request: Request) => Promise<Response>;

export interface DPoPClient {
  request(method: string, url: string, accessToken?: string): Promise<Response>;
}

/** A client that holds one key pair and proves it on every request. */
export async function createClient(send: Send = fetch): Promise<DPoPClient> {
  // Keep the pair for as long as the tokens bound to it live.
  const keyPair = await generateJWK("ES256");
  let nonce: string | undefined;

  async function attempt(method: string, url: string, accessToken?: string): Promise<Response> {
    const proof = await createDPoPProof(
      { method, url },
      { keyPair, nonce, accessToken: accessToken ? { token: accessToken } : undefined },
    );
    const headers = new Headers({ dpop: proof });
    if (accessToken) headers.set("authorization", `DPoP ${accessToken}`);
    const response = await send(new Request(url, { method, headers }));
    nonce = response.headers.get("dpop-nonce") ?? nonce;
    return response;
  }

  /** One request, sent a second time when the server asks for a fresh nonce. */
  async function request(method: string, url: string, accessToken?: string): Promise<Response> {
    const response = await attempt(method, url, accessToken);
    const challenge = response.headers.get("www-authenticate") ?? "";
    if (response.status !== 401 || !challenge.includes('error="use_dpop_nonce"')) return response;
    return attempt(method, url, accessToken);
  }

  return { request };
}
// #endregion
