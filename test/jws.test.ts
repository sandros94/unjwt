import { describe, it, expect } from "vitest";
import { sign, verify } from "../src/jws";
import { base64UrlEncode } from "../src/utils";
import type { JWSSymmetricAlgorithm } from "../src/types";
import { JWS_SYMMETRIC_ALGORITHMS } from "../src/utils/defaults";

describe("JWS sign and verify (symmetric)", () => {
  const payload = { message: "Hello, JWS!" };
  const payloadString = JSON.stringify(payload);
  const secret = "supersecretkey";
  const payloadBytes = new TextEncoder().encode(payloadString);
  const secretBytes = new TextEncoder().encode(secret);

  it("should sign and verify data with default options (string)", async () => {
    const token = await sign(payloadString, secret);
    expect(token).toBeTypeOf("string");
    expect(token.split(".").length).toBe(3);

    const verifiedPayload = await verify(token, secret);
    expect(verifiedPayload).toBe(payloadString);
  });

  it("should sign and verify data with default options (Uint8Array)", async () => {
    const token = await sign(payloadBytes, secretBytes);
    expect(token).toBeTypeOf("string");
    expect(token.split(".").length).toBe(3);

    const verifiedPayload = await verify(token, secretBytes);
    expect(verifiedPayload).toBe(payloadString);
  });

  it("should sign and verify data with custom header", async () => {
    const options = {
      protectedHeader: {
        alg: "HS512" as const,
        typ: "CUSTOM",
        cty: "application/json",
        custom: "value",
      },
    };
    const token = await sign(payloadString, secret, options);
    expect(token).toBeTypeOf("string");
    expect(token.split(".").length).toBe(3);

    // Check header contains custom options
    const header = JSON.parse(
      Buffer.from(token.split(".")[0]!, "base64url").toString("utf8"),
    );
    expect(header.alg).toBe(options.protectedHeader.alg);
    expect(header.typ).toBe(options.protectedHeader.typ);
    expect(header.cty).toBe(options.protectedHeader.cty);
    expect(header.custom).toBe(options.protectedHeader.custom);

    const verifiedPayload = await verify(token, secret);
    expect(verifiedPayload).toBe(payloadString);
  });

  it("should verify payload as Uint8Array when textOutput is false", async () => {
    const token = await sign(payloadBytes, secretBytes);
    const verifiedPayloadBytes = await verify(token, secretBytes, {
      textOutput: false,
    });
    expect(verifiedPayloadBytes).toBeInstanceOf(Uint8Array);
    expect(verifiedPayloadBytes).toEqual(payloadBytes);
  });

  it("should throw error if token signature has been tampered", async () => {
    const token = await sign(payloadString, secret);
    const [header, payload, signature] = token.split(".");
    const tamperedSignature = signature!.slice(0, -1) + "X"; // Tamper last char
    const tamperedToken = `${header}.${payload}.${tamperedSignature}`;

    await expect(verify(tamperedToken, secret)).rejects.toThrow(
      "Signature verification failed",
    );
  });

  it("should throw error if token payload has been tampered", async () => {
    const token = await sign(payloadString, secret);
    const [header, _payload, signature] = token.split(".");
    const tamperedPayload = base64UrlEncode(
      new TextEncoder().encode('{"tampered":true}'), // Tamper payload
    );
    const tamperedToken = `${header}.${tamperedPayload}.${signature}`;

    await expect(verify(tamperedToken, secret)).rejects.toThrow(
      "Signature verification failed",
    );
  });

  it("should throw error if token header has been tampered", async () => {
    const token = await sign(payloadString, secret);
    const [_header, payload, signature] = token.split(".");
    const tamperedHeader = base64UrlEncode(
      new TextEncoder().encode('{"alg":"HS512"}'), // Change alg
    );
    const tamperedToken = `${tamperedHeader}.${payload}.${signature}`;

    // Verification uses alg from header, so it expects HS512 now
    await expect(verify(tamperedToken, secret)).rejects.toThrow(
      "Signature verification failed",
    );
  });

  it("should throw error if token is missing during verify", async () => {
    // @ts-expect-error - Testing invalid input
    await expect(verify(null, secret)).rejects.toThrow("Missing JWS token");
    await expect(verify("", secret)).rejects.toThrow("Missing JWS token");
  });

  it("should throw error if secret is missing during sign", async () => {
    // @ts-expect-error - Testing invalid input
    await expect(sign(payloadString, null)).rejects.toThrow(
      "Missing secret key",
    );
    await expect(sign(payloadString, "")).rejects.toThrow("Missing secret key");
  });

  it("should throw error if secret is missing during verify", async () => {
    const token = await sign(payloadString, secret);
    // @ts-expect-error - Testing invalid input
    await expect(verify(token, null)).rejects.toThrow("Missing secret key");
    await expect(verify(token, "")).rejects.toThrow("Missing secret key");
  });

  it("should throw error for unsupported algorithm during sign", async () => {
    const options = {
      protectedHeader: { alg: "UNSUPPORTED_ALG" as any },
    };
    await expect(sign(payloadString, secret, options)).rejects.toThrow(
      "Unsupported JWS algorithm: UNSUPPORTED_ALG",
    );
  });

  it("should throw error for unsupported algorithm during verify", async () => {
    // Manually craft a token with unsupported alg
    const token = await sign(payloadString, secret);
    const [header, payload, signature] = token.split(".");
    const badHeader = JSON.parse(
      Buffer.from(header!, "base64url").toString("utf8"),
    );
    badHeader.alg = "UNSUPPORTED_ALG";
    const badEncodedHeader = base64UrlEncode(
      new TextEncoder().encode(JSON.stringify(badHeader)),
    );
    const badToken = `${badEncodedHeader}.${payload}.${signature}`;

    await expect(verify(badToken, secret)).rejects.toThrow(
      "Unsupported JWS algorithm: UNSUPPORTED_ALG",
    );
  });

  it("should handle different symmetric algorithms", async () => {
    const algs = Object.keys(
      JWS_SYMMETRIC_ALGORITHMS,
    ) as JWSSymmetricAlgorithm[];
    for (const alg of algs) {
      const token = await sign(payloadString, secret, {
        protectedHeader: { alg },
      });
      const verifiedPayload = await verify(token, secret);
      expect(verifiedPayload).toBe(payloadString);
    }
  });

  it("should throw error for invalid token format", async () => {
    await expect(verify("invalid.token", secret)).rejects.toThrow(
      "Invalid JWS token format",
    );
    await expect(verify("a.b.c.d", secret)).rejects.toThrow(
      "Invalid JWS token format",
    );
  });
});
