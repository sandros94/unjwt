import { JWTError } from "../error.ts";

/** Concatenate multiple `Uint8Array`s into a single contiguous buffer. */
export function concatUint8Arrays(
  ...arrays: Readonly<Uint8Array<ArrayBuffer>[]>
): Uint8Array<ArrayBuffer> {
  const totalLength = arrays.reduce((length, arr) => length + arr.length, 0);
  const result = new Uint8Array(totalLength);

  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }

  return result;
}

/** The 4-octet big-endian encoding of an unsigned 32-bit integer. */
export function uint32be(value: number): Uint8Array<ArrayBuffer> {
  if (value < 0 || value >= 2 ** 32) {
    throw new JWTError(
      `value must be >= 0 and <= ${2 ** 32 - 1} (got ${value})`,
      "ERR_INVALID_OPTION",
    );
  }
  return new Uint8Array([value >>> 24, value >>> 16, value >>> 8, value & 0xff]);
}

/** Wrap a value in an array; returns the array unchanged if already an array. */
export function maybeArray<T>(item: T | T[]): T[] {
  return Array.isArray(item) ? item : [item];
}
