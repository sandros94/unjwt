import { JWTError } from "../error.ts";

/** Returns one `Uint8Array` with the bytes of `arrays` in order. */
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

/**
 * Returns the 4-octet big-endian encoding of an unsigned 32-bit integer.
 * @throws `ERR_INVALID_OPTION` if `value` is outside `0` to `2 ** 32 - 1`.
 */
export function uint32be(value: number): Uint8Array<ArrayBuffer> {
  if (value < 0 || value >= 2 ** 32) {
    throw new JWTError(
      `value must be >= 0 and <= ${2 ** 32 - 1} (got ${value})`,
      "ERR_INVALID_OPTION",
    );
  }
  return new Uint8Array([value >>> 24, value >>> 16, value >>> 8, value & 0xff]);
}

/** Returns `item` when it is an array, else `[item]`. */
export function maybeArray<T>(item: T | T[]): T[] {
  return Array.isArray(item) ? item : [item];
}
