import { describe, it, expect } from "vitest";
import { seal, unseal } from "../src/jwe";
import type {
  JWEHeaderParameters,
  KeyWrappingAlgorithmType,
  ContentEncryptionAlgorithmType,
} from "../src/types";
import {
  KEY_WRAPPING_ALGORITHMS,
  CONTENT_ENCRYPTION_ALGORITHMS,
} from "../src/utils/defaults";

describe("JWE seal and unseal", () => {
  const plaintext = "Hello, JWE!";
  const password = "supersecretpassword";
  const plaintextBytes = new TextEncoder().encode(plaintext);
  const passwordBytes = new TextEncoder().encode(password);

  it("should seal and unseal data with default options (string)", async () => {
    const token = await seal(plaintext, password);
    expect(token).toBeTypeOf("string");
    expect(token.split(".").length).toBe(5);

    const decrypted = await unseal(token, password);
    expect(decrypted).toBe(plaintext);
  });

  it("should seal and unseal data with default options (Uint8Array)", async () => {
    const token = await seal(plaintextBytes, passwordBytes);
    expect(token).toBeTypeOf("string");
    expect(token.split(".").length).toBe(5);

    const decrypted = await unseal(token, passwordBytes);
    expect(decrypted).toBe(plaintext);
  });

  it("should seal and unseal data with custom options", async () => {
    const options = {
      iterations: 4096,
      saltSize: 32,
      protectedHeader: {
        alg: "PBES2-HS384+A192KW" as const,
        enc: "A192GCM" as const,
        custom: "value",
      },
    };
    const token = await seal(plaintext, password, options);
    expect(token).toBeTypeOf("string");
    expect(token.split(".").length).toBe(5);

    // Check header contains custom options
    const header = JSON.parse(
      Buffer.from(token.split(".")[0]!, "base64url").toString("utf8"), // Assert non-null
    ) as JWEHeaderParameters; // Type assertion for header
    expect(header.alg).toBe(options.protectedHeader.alg);
    expect(header.enc).toBe(options.protectedHeader.enc);
    expect(header.p2c).toBe(options.iterations);
    expect((header as any).custom).toBe(options.protectedHeader.custom); // Access custom prop
    expect(
      Buffer.from(header.p2s!, "base64url").byteLength, // Assert non-null
    ).toBe(options.saltSize);

    const decrypted = await unseal(token, password);
    expect(decrypted).toBe(plaintext);
  });

  it("should unseal data as Uint8Array when textOutput is false", async () => {
    const token = await seal(plaintextBytes, passwordBytes);
    const decryptedBytes = await unseal(token, passwordBytes, {
      textOutput: false,
    });
    expect(decryptedBytes).toBeInstanceOf(Uint8Array);
    expect(decryptedBytes).toEqual(plaintextBytes);
  });

  it("should throw error if token or section has been tampered", async () => {
    const token = await seal(plaintext, password);
    const tokenParts = token.split(".");

    // Tamper with the payload
    const tamperedToken = [
      ...tokenParts.slice(0, 2),
      "tamperedPayload",
      ...tokenParts.slice(3),
    ].join(".");
    await expect(unseal(tamperedToken, password)).rejects.toThrow();

    // Tamper with the header
    const tamperedHeader = [
      ...tokenParts.slice(0, 1),
      "tamperedHeader",
      ...tokenParts.slice(2),
    ].join(".");
    await expect(unseal(tamperedHeader, password)).rejects.toThrow();
  });

  it("should throw error if token is missing during unseal", async () => {
    // @ts-expect-error - Testing invalid input
    await expect(unseal(null, password)).rejects.toThrow("Missing JWE token");
    await expect(unseal("", password)).rejects.toThrow("Missing JWE token");
  });

  it("should throw error if password is missing during seal", async () => {
    // @ts-expect-error - Testing invalid input
    await expect(seal(plaintext, null)).rejects.toThrow("Missing password");
    await expect(seal(plaintext, "")).rejects.toThrow("Missing password");
  });

  it("should throw error if password is missing during unseal", async () => {
    const token = await seal(plaintext, password);
    // @ts-expect-error - Testing invalid input
    await expect(unseal(token, null)).rejects.toThrow("Missing password");
    await expect(unseal(token, "")).rejects.toThrow("Missing password");
  });

  it("should throw error for unsupported key wrapping algorithm", async () => {
    const options = {
      protectedHeader: { alg: "UNSUPPORTED_ALG" as any },
    };
    await expect(seal(plaintext, password, options)).rejects.toThrow(
      "Unsupported key wrapping algorithm: UNSUPPORTED_ALG",
    );

    // Manually craft a token with unsupported alg
    const tokenParts = (await seal(plaintext, password)).split(".");
    const badHeader = JSON.parse(
      Buffer.from(tokenParts[0]!, "base64url").toString("utf8"), // Assert non-null
    );
    badHeader.alg = "UNSUPPORTED_ALG";
    tokenParts[0] = Buffer.from(JSON.stringify(badHeader)).toString(
      "base64url",
    );
    const badToken = tokenParts.join(".");

    await expect(unseal(badToken, password)).rejects.toThrow(
      "Unsupported key wrapping algorithm: UNSUPPORTED_ALG",
    );
  });

  it("should throw error for unsupported content encryption algorithm", async () => {
    const options = {
      protectedHeader: { enc: "UNSUPPORTED_ENC" as any },
    };
    await expect(seal(plaintext, password, options)).rejects.toThrow(
      "Unsupported content encryption algorithm: UNSUPPORTED_ENC",
    );

    // Manually craft a token with unsupported enc
    const tokenParts = (await seal(plaintext, password)).split(".");
    const badHeader = JSON.parse(
      Buffer.from(tokenParts[0]!, "base64url").toString("utf8"), // Assert non-null
    );
    badHeader.enc = "UNSUPPORTED_ENC";
    tokenParts[0] = Buffer.from(JSON.stringify(badHeader)).toString(
      "base64url",
    );
    const badToken = tokenParts.join(".");

    await expect(unseal(badToken, password)).rejects.toThrow(
      "Unsupported content encryption algorithm: UNSUPPORTED_ENC",
    );
  });

  it("should handle different wrapping algorithms", async () => {
    const algs = Object.keys(
      KEY_WRAPPING_ALGORITHMS,
    ) as KeyWrappingAlgorithmType[];
    for (const alg of algs) {
      const token = await seal(plaintext, password, {
        protectedHeader: { alg },
      });
      const decrypted = await unseal(token, password);
      expect(decrypted).toBe(plaintext);
    }
  });

  it("should handle different encryption algorithms", async () => {
    const encs = Object.keys(
      CONTENT_ENCRYPTION_ALGORITHMS,
    ) as ContentEncryptionAlgorithmType[];

    // Filter out CBC algorithms, as not implemented yet
    const gcmEncs = encs.filter((enc) => {
      const { type } = CONTENT_ENCRYPTION_ALGORITHMS[enc];
      return type === "gcm";
    });

    for (const enc of gcmEncs) {
      const token = await seal(plaintext, password, {
        protectedHeader: { enc },
      });
      const decrypted = await unseal(token, password);
      expect(decrypted).toBe(plaintext);
    }
  });
});
