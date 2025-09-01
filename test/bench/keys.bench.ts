import { bench, describe } from "vitest";

import { generateKey } from "../../src/jwk";
import { sign, verify } from "../../src/jws";

describe("RSA vs OKP signing", async () => {
  const [rsa256Keys, rsa384Keys, rsa512Keys, okpKeys] = await Promise.all([
    generateKey("RS256"),
    generateKey("RS384"),
    generateKey("RS512"),
    generateKey("Ed25519"),
  ]);

  bench("[sign] RSA256", async () => {
    await sign({ sub: "test" }, rsa256Keys.privateKey, { alg: "RS256" });
  });

  bench("[sign] RSA384", async () => {
    await sign({ sub: "test" }, rsa384Keys.privateKey, { alg: "RS384" });
  });

  bench("[sign] RSA512", async () => {
    await sign({ sub: "test" }, rsa512Keys.privateKey, { alg: "RS512" });
  });

  bench("[sign] Ed25519", async () => {
    await sign({ sub: "test" }, okpKeys.privateKey, { alg: "Ed25519" });
  });
});

describe("RSA vs OKP verifying", async () => {
  const [rsa256Keys, rsa384Keys, rsa512Keys, okpKeys] = await Promise.all([
    generateKey("RS256"),
    generateKey("RS384"),
    generateKey("RS512"),
    generateKey("Ed25519"),
  ]);
  const [rsa256Verify, rsa384Verify, rsa512Verify, okpVerify] =
    await Promise.all([
      sign({ sub: "test" }, rsa256Keys.privateKey, { alg: "RS256" }),
      sign({ sub: "test" }, rsa384Keys.privateKey, { alg: "RS384" }),
      sign({ sub: "test" }, rsa512Keys.privateKey, { alg: "RS512" }),
      sign({ sub: "test" }, okpKeys.privateKey, { alg: "Ed25519" }),
    ]);

  bench("[verify] RSA256", async () => {
    await verify(rsa256Verify, rsa256Keys.publicKey);
  });

  bench("[verify] RSA384", async () => {
    await verify(rsa384Verify, rsa384Keys.publicKey);
  });

  bench("[verify] RSA512", async () => {
    await verify(rsa512Verify, rsa512Keys.publicKey);
  });

  bench("[verify] Ed25519", async () => {
    await verify(okpVerify, okpKeys.publicKey);
  });
});
