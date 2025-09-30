import { bench, describe } from "vitest";
import * as jose from "jose";

import { generateKey } from "../../src/core/jwk";
import { encrypt, decrypt } from "../../src/core/jwe";

describe("Library comparison encryption", async () => {
  const keys = await generateKey("RSA-OAEP-256", { toJWK: true });

  bench("[encrypt] unjwt", async () => {
    await encrypt({ sub: "test" }, keys.publicKey);
  });

  bench("[encrypt] jose", async () => {
    await new jose.EncryptJWT({ sub: "test" })
      .setProtectedHeader({ alg: "RSA-OAEP-256", enc: "A128GCM" })
      .encrypt(keys.publicKey);
  });
});

describe("Library comparison decryption", async () => {
  const keys = await generateKey("RSA-OAEP-256", { toJWK: true });
  const jws = await encrypt({ sub: "test" }, keys.publicKey);

  bench("[decrypt] unjwt", async () => {
    await decrypt(jws, keys.privateKey);
  });

  bench("[decrypt] jose", async () => {
    await jose.jwtDecrypt(jws, keys.privateKey);
  });
});
