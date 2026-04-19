import { bench, describe } from "vitest";
import { EncryptJWT, jwtDecrypt } from "jose";

import { generateJWK } from "../../src/core/jwk";
import { encrypt, decrypt } from "../../src/core/jwe";

describe("Library comparison encryption — RSA-OAEP-256", async () => {
  const keys = await generateJWK("RSA-OAEP-256");

  bench("[unjwt] encrypt — RSA-OAEP-256", async () => {
    await encrypt({ sub: "test" }, keys.publicKey);
  });

  bench("[jose] encrypt — RSA-OAEP-256", async () => {
    await new EncryptJWT({ sub: "test" })
      .setProtectedHeader({ alg: "RSA-OAEP-256", enc: "A128GCM" })
      .encrypt(keys.publicKey);
  });
});

describe("Library comparison decryption — RSA-OAEP-256", async () => {
  const keys = await generateJWK("RSA-OAEP-256");
  const jwe = await encrypt({ sub: "test" }, keys.publicKey);

  bench("[unjwt] decrypt — RSA-OAEP-256", async () => {
    await decrypt(jwe, keys.privateKey);
  });

  bench("[jose] decrypt — RSA-OAEP-256", async () => {
    await jwtDecrypt(jwe, keys.privateKey);
  });
});

describe("Library comparison encryption — ECDH-ES+A256KW (X25519)", async () => {
  const keys = await generateJWK("ECDH-ES+A256KW", { namedCurve: "X25519" });

  bench("[unjwt] encrypt — ECDH-ES+A256KW (X25519)", async () => {
    await encrypt({ sub: "test" }, keys.publicKey);
  });

  bench("[jose] encrypt — ECDH-ES+A256KW (X25519)", async () => {
    await new EncryptJWT({ sub: "test" })
      .setProtectedHeader({ alg: "ECDH-ES+A256KW", enc: "A128GCM" })
      .encrypt(keys.publicKey);
  });
});

describe("Library comparison decryption — ECDH-ES+A256KW (X25519)", async () => {
  const keys = await generateJWK("ECDH-ES+A256KW", { namedCurve: "X25519" });
  const jwe = await encrypt({ sub: "test" }, keys.publicKey);

  bench("[unjwt] decrypt — ECDH-ES+A256KW (X25519)", async () => {
    await decrypt(jwe, keys.privateKey);
  });

  bench("[jose] decrypt — ECDH-ES+A256KW (X25519)", async () => {
    await jwtDecrypt(jwe, keys.privateKey);
  });
});

describe("Library comparison roundtrip — RSA-OAEP-256", async () => {
  const keys = await generateJWK("RSA-OAEP-256");

  bench("[unjwt] roundtrip — RSA-OAEP-256", async () => {
    const jwe = await encrypt({ sub: "test" }, keys.publicKey);
    await decrypt(jwe, keys.privateKey);
  });

  bench("[jose] roundtrip — RSA-OAEP-256", async () => {
    const jwe = await new EncryptJWT({ sub: "test" })
      .setProtectedHeader({ alg: "RSA-OAEP-256", enc: "A128GCM" })
      .encrypt(keys.publicKey);
    await jwtDecrypt(jwe, keys.privateKey);
  });
});

describe("Library comparison roundtrip — ECDH-ES+A256KW (X25519)", async () => {
  const keys = await generateJWK("ECDH-ES+A256KW", { namedCurve: "X25519" });

  bench("[unjwt] roundtrip — ECDH-ES+A256KW (X25519)", async () => {
    const jwe = await encrypt({ sub: "test" }, keys.publicKey);
    await decrypt(jwe, keys.privateKey);
  });

  bench("[jose] roundtrip — ECDH-ES+A256KW (X25519)", async () => {
    const jwe = await new EncryptJWT({ sub: "test" })
      .setProtectedHeader({ alg: "ECDH-ES+A256KW", enc: "A128GCM" })
      .encrypt(keys.publicKey);
    await jwtDecrypt(jwe, keys.privateKey);
  });
});
