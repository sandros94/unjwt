import { bench, describe } from "vitest";

import { generateJWK } from "../../src/core/jwk";
import { sign, verify } from "../../src/core/jws";
import { encrypt, decrypt } from "../../src/core/jwe";

describe("JWK — JWS signing — per algorithm", async () => {
  const [rs256Keys, rs384Keys, rs512Keys, ps256Keys, es256Keys, okpKeys] = await Promise.all([
    generateJWK("RS256"),
    generateJWK("RS384"),
    generateJWK("RS512"),
    generateJWK("PS256"),
    generateJWK("ES256"),
    generateJWK("Ed25519"),
  ]);

  bench("[jwk — jws] sign — RS256", async () => {
    await sign({ sub: "test" }, rs256Keys.privateKey);
  });

  bench("[jwk — jws] sign — RS384", async () => {
    await sign({ sub: "test" }, rs384Keys.privateKey);
  });

  bench("[jwk — jws] sign — RS512", async () => {
    await sign({ sub: "test" }, rs512Keys.privateKey);
  });

  bench("[jwk — jws] sign — PS256", async () => {
    await sign({ sub: "test" }, ps256Keys.privateKey);
  });

  bench("[jwk — jws] sign — ES256", async () => {
    await sign({ sub: "test" }, es256Keys.privateKey);
  });

  bench("[jwk — jws] sign — Ed25519", async () => {
    await sign({ sub: "test" }, okpKeys.privateKey);
  });
});

describe("JWK — JWS verifying — per algorithm", async () => {
  const [rs256Keys, rs384Keys, rs512Keys, ps256Keys, es256Keys, okpKeys] = await Promise.all([
    generateJWK("RS256"),
    generateJWK("RS384"),
    generateJWK("RS512"),
    generateJWK("PS256"),
    generateJWK("ES256"),
    generateJWK("Ed25519"),
  ]);
  const [rs256Jws, rs384Jws, rs512Jws, ps256Jws, es256Jws, okpJws] = await Promise.all([
    sign({ sub: "test" }, rs256Keys.privateKey),
    sign({ sub: "test" }, rs384Keys.privateKey),
    sign({ sub: "test" }, rs512Keys.privateKey),
    sign({ sub: "test" }, ps256Keys.privateKey),
    sign({ sub: "test" }, es256Keys.privateKey),
    sign({ sub: "test" }, okpKeys.privateKey),
  ]);

  bench("[jwk — jws] verify — RS256", async () => {
    await verify(rs256Jws, rs256Keys.publicKey);
  });

  bench("[jwk — jws] verify — RS384", async () => {
    await verify(rs384Jws, rs384Keys.publicKey);
  });

  bench("[jwk — jws] verify — RS512", async () => {
    await verify(rs512Jws, rs512Keys.publicKey);
  });

  bench("[jwk — jws] verify — PS256", async () => {
    await verify(ps256Jws, ps256Keys.publicKey);
  });

  bench("[jwk — jws] verify — ES256", async () => {
    await verify(es256Jws, es256Keys.publicKey);
  });

  bench("[jwk — jws] verify — Ed25519", async () => {
    await verify(okpJws, okpKeys.publicKey);
  });
});

describe("JWK — JWS roundtrip — per algorithm", async () => {
  const [rs256Keys, rs384Keys, rs512Keys, ps256Keys, es256Keys, okpKeys] = await Promise.all([
    generateJWK("RS256"),
    generateJWK("RS384"),
    generateJWK("RS512"),
    generateJWK("PS256"),
    generateJWK("ES256"),
    generateJWK("Ed25519"),
  ]);

  bench("[jwk — jws] roundtrip — RS256", async () => {
    const jws = await sign({ sub: "test" }, rs256Keys.privateKey);
    await verify(jws, rs256Keys.publicKey);
  });

  bench("[jwk — jws] roundtrip — RS384", async () => {
    const jws = await sign({ sub: "test" }, rs384Keys.privateKey);
    await verify(jws, rs384Keys.publicKey);
  });

  bench("[jwk — jws] roundtrip — RS512", async () => {
    const jws = await sign({ sub: "test" }, rs512Keys.privateKey);
    await verify(jws, rs512Keys.publicKey);
  });

  bench("[jwk — jws] roundtrip — PS256", async () => {
    const jws = await sign({ sub: "test" }, ps256Keys.privateKey);
    await verify(jws, ps256Keys.publicKey);
  });

  bench("[jwk — jws] roundtrip — ES256", async () => {
    const jws = await sign({ sub: "test" }, es256Keys.privateKey);
    await verify(jws, es256Keys.publicKey);
  });

  bench("[jwk — jws] roundtrip — Ed25519", async () => {
    const jws = await sign({ sub: "test" }, okpKeys.privateKey);
    await verify(jws, okpKeys.publicKey);
  });
});

describe("JWK — JWE encryption — per algorithm", async () => {
  const [rsaKeys, ecKeys, okpKeys, aesKey] = await Promise.all([
    generateJWK("RSA-OAEP-256"),
    generateJWK("ECDH-ES+A256KW"),
    generateJWK("ECDH-ES+A256KW", { namedCurve: "X25519" }),
    generateJWK("A256KW"),
  ]);

  bench("[jwk — jwe] encrypt — RSA-OAEP-256", async () => {
    await encrypt({ sub: "test" }, rsaKeys.publicKey);
  });

  bench("[jwk — jwe] encrypt — ECDH-ES+A256KW (P-256)", async () => {
    await encrypt({ sub: "test" }, ecKeys.publicKey);
  });

  bench("[jwk — jwe] encrypt — ECDH-ES+A256KW (X25519)", async () => {
    await encrypt({ sub: "test" }, okpKeys.publicKey);
  });

  bench("[jwk — jwe] encrypt — A256KW", async () => {
    await encrypt({ sub: "test" }, aesKey);
  });
});

describe("JWK — JWE decryption — per algorithm", async () => {
  const [rsaKeys, ecKeys, okpKeys, aesKey] = await Promise.all([
    generateJWK("RSA-OAEP-256"),
    generateJWK("ECDH-ES+A256KW"),
    generateJWK("ECDH-ES+A256KW", { namedCurve: "X25519" }),
    generateJWK("A256KW"),
  ]);
  const [rsaJwe, ecJwe, okpJwe, aesJwe] = await Promise.all([
    encrypt({ sub: "test" }, rsaKeys.publicKey),
    encrypt({ sub: "test" }, ecKeys.publicKey),
    encrypt({ sub: "test" }, okpKeys.publicKey),
    encrypt({ sub: "test" }, aesKey),
  ]);

  bench("[jwk — jwe] decrypt — RSA-OAEP-256", async () => {
    await decrypt(rsaJwe, rsaKeys.privateKey);
  });

  bench("[jwk — jwe] decrypt — ECDH-ES+A256KW (P-256)", async () => {
    await decrypt(ecJwe, ecKeys.privateKey);
  });

  bench("[jwk — jwe] decrypt — ECDH-ES+A256KW (X25519)", async () => {
    await decrypt(okpJwe, okpKeys.privateKey);
  });

  bench("[jwk — jwe] decrypt — A256KW", async () => {
    await decrypt(aesJwe, aesKey);
  });
});

describe("JWK — JWE roundtrip — per algorithm", async () => {
  const [rsaKeys, ecKeys, okpKeys, aesKey] = await Promise.all([
    generateJWK("RSA-OAEP-256"),
    generateJWK("ECDH-ES+A256KW"),
    generateJWK("ECDH-ES+A256KW", { namedCurve: "X25519" }),
    generateJWK("A256KW"),
  ]);

  bench("[jwk — jwe] roundtrip — RSA-OAEP-256", async () => {
    const jwe = await encrypt({ sub: "test" }, rsaKeys.publicKey);
    await decrypt(jwe, rsaKeys.privateKey);
  });

  bench("[jwk — jwe] roundtrip — ECDH-ES+A256KW (P-256)", async () => {
    const jwe = await encrypt({ sub: "test" }, ecKeys.publicKey);
    await decrypt(jwe, ecKeys.privateKey);
  });

  bench("[jwk — jwe] roundtrip — ECDH-ES+A256KW (X25519)", async () => {
    const jwe = await encrypt({ sub: "test" }, okpKeys.publicKey);
    await decrypt(jwe, okpKeys.privateKey);
  });

  bench("[jwk — jwe] roundtrip — A256KW", async () => {
    const jwe = await encrypt({ sub: "test" }, aesKey);
    await decrypt(jwe, aesKey);
  });
});
