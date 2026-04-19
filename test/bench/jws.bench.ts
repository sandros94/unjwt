import { bench, describe } from "vitest";
import { SignJWT, jwtVerify } from "jose";

import { generateJWK } from "../../src/core/jwk";
import { sign, verify } from "../../src/core/jws";

describe("Library comparison signing — RS256", async () => {
  const rsaKeys = await generateJWK("RS256");

  bench("[unjwt] sign — RS256", async () => {
    await sign({ sub: "test" }, rsaKeys.privateKey);
  });

  bench("[jose] sign — RS256", async () => {
    await new SignJWT({ sub: "test" })
      .setProtectedHeader({ alg: "RS256" })
      .sign(rsaKeys.privateKey);
  });
});

describe("Library comparison verifying — RS256", async () => {
  const rsaKeys = await generateJWK("RS256");
  const jws = await sign({ sub: "test" }, rsaKeys.privateKey);

  bench("[unjwt] verify — RS256", async () => {
    await verify(jws, rsaKeys.publicKey);
  });

  bench("[jose] verify — RS256", async () => {
    await jwtVerify(jws, rsaKeys.publicKey);
  });
});

describe("Library comparison signing — Ed25519", async () => {
  const okpKeys = await generateJWK("Ed25519");

  bench("[unjwt] sign — Ed25519", async () => {
    await sign({ sub: "test" }, okpKeys.privateKey);
  });

  bench("[jose] sign — Ed25519", async () => {
    await new SignJWT({ sub: "test" })
      .setProtectedHeader({ alg: "Ed25519" })
      .sign(okpKeys.privateKey);
  });
});

describe("Library comparison verifying — Ed25519", async () => {
  const okpKeys = await generateJWK("Ed25519");
  const jws = await sign({ sub: "test" }, okpKeys.privateKey);

  bench("[unjwt] verify — Ed25519", async () => {
    await verify(jws, okpKeys.publicKey);
  });

  bench("[jose] verify — Ed25519", async () => {
    await jwtVerify(jws, okpKeys.publicKey);
  });
});

describe("Library comparison roundtrip — RS256", async () => {
  const rsaKeys = await generateJWK("RS256");

  bench("[unjwt] roundtrip — RS256", async () => {
    const jws = await sign({ sub: "test" }, rsaKeys.privateKey);
    await verify(jws, rsaKeys.publicKey);
  });

  bench("[jose] roundtrip — RS256", async () => {
    const jws = await new SignJWT({ sub: "test" })
      .setProtectedHeader({ alg: "RS256" })
      .sign(rsaKeys.privateKey);
    await jwtVerify(jws, rsaKeys.publicKey);
  });
});

describe("Library comparison roundtrip — Ed25519", async () => {
  const okpKeys = await generateJWK("Ed25519");

  bench("[unjwt] roundtrip — Ed25519", async () => {
    const jws = await sign({ sub: "test" }, okpKeys.privateKey);
    await verify(jws, okpKeys.publicKey);
  });

  bench("[jose] roundtrip — Ed25519", async () => {
    const jws = await new SignJWT({ sub: "test" })
      .setProtectedHeader({ alg: "Ed25519" })
      .sign(okpKeys.privateKey);
    await jwtVerify(jws, okpKeys.publicKey);
  });
});
