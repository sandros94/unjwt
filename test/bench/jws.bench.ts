import { test } from "vitest";
import { SignJWT, jwtVerify } from "jose";

import { generateJWK } from "../../src/core/jwk.ts";
import { sign, verify } from "../../src/core/jws.ts";

test("Library comparison signing — RS256", async ({ bench }) => {
  const rsaKeys = await generateJWK("RS256");

  await bench.compare(
    bench("[unjwt] sign — RS256", async () => {
      await sign({ sub: "test" }, rsaKeys.privateKey);
    }),
    bench("[jose] sign — RS256", async () => {
      await new SignJWT({ sub: "test" })
        .setProtectedHeader({ alg: "RS256" })
        .sign(rsaKeys.privateKey);
    }),
  );
});

test("Library comparison verifying — RS256", async ({ bench }) => {
  const rsaKeys = await generateJWK("RS256");
  const jws = await sign({ sub: "test" }, rsaKeys.privateKey);

  await bench.compare(
    bench("[unjwt] verify — RS256", async () => {
      await verify(jws, rsaKeys.publicKey);
    }),
    bench("[jose] verify — RS256", async () => {
      await jwtVerify(jws, rsaKeys.publicKey);
    }),
  );
});

test("Library comparison signing — Ed25519", async ({ bench }) => {
  const okpKeys = await generateJWK("Ed25519");

  await bench.compare(
    bench("[unjwt] sign — Ed25519", async () => {
      await sign({ sub: "test" }, okpKeys.privateKey);
    }),
    bench("[jose] sign — Ed25519", async () => {
      await new SignJWT({ sub: "test" })
        .setProtectedHeader({ alg: "Ed25519" })
        .sign(okpKeys.privateKey);
    }),
  );
});

test("Library comparison verifying — Ed25519", async ({ bench }) => {
  const okpKeys = await generateJWK("Ed25519");
  const jws = await sign({ sub: "test" }, okpKeys.privateKey);

  await bench.compare(
    bench("[unjwt] verify — Ed25519", async () => {
      await verify(jws, okpKeys.publicKey);
    }),
    bench("[jose] verify — Ed25519", async () => {
      await jwtVerify(jws, okpKeys.publicKey);
    }),
  );
});

test("Library comparison roundtrip — RS256", async ({ bench }) => {
  const rsaKeys = await generateJWK("RS256");

  await bench.compare(
    bench("[unjwt] roundtrip — RS256", async () => {
      const jws = await sign({ sub: "test" }, rsaKeys.privateKey);
      await verify(jws, rsaKeys.publicKey);
    }),
    bench("[jose] roundtrip — RS256", async () => {
      const jws = await new SignJWT({ sub: "test" })
        .setProtectedHeader({ alg: "RS256" })
        .sign(rsaKeys.privateKey);
      await jwtVerify(jws, rsaKeys.publicKey);
    }),
  );
});

test("Library comparison roundtrip — Ed25519", async ({ bench }) => {
  const okpKeys = await generateJWK("Ed25519");

  await bench.compare(
    bench("[unjwt] roundtrip — Ed25519", async () => {
      const jws = await sign({ sub: "test" }, okpKeys.privateKey);
      await verify(jws, okpKeys.publicKey);
    }),
    bench("[jose] roundtrip — Ed25519", async () => {
      const jws = await new SignJWT({ sub: "test" })
        .setProtectedHeader({ alg: "Ed25519" })
        .sign(okpKeys.privateKey);
      await jwtVerify(jws, okpKeys.publicKey);
    }),
  );
});
