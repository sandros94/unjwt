import { bench, describe } from "vitest";
import * as jose from "jose";

import { generateKey } from "../../src/core/jwk";
import { sign, verify } from "../../src/core/jws";

describe("Library comparison signing", async () => {
  const okpKeys = await generateKey("Ed25519");

  bench("[sign] unjwt", async () => {
    await sign({ sub: "test" }, okpKeys.privateKey, { alg: "Ed25519" });
  });

  bench("[sign] jose", async () => {
    await new jose.SignJWT({ sub: "test" })
      .setProtectedHeader({ alg: "Ed25519" })
      .sign(okpKeys.privateKey);
  });
});

describe("Library comparison verifying", async () => {
  const okpKeys = await generateKey("Ed25519");
  const jws = await sign({ sub: "test" }, okpKeys.privateKey, {
    alg: "Ed25519",
  });

  bench("[verify] unjwt", async () => {
    await verify(jws, okpKeys.publicKey);
  });

  bench("[verify] jose", async () => {
    await jose.jwtVerify(jws, okpKeys.publicKey);
  });
});
