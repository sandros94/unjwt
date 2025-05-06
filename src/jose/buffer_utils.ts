/* eslint-disable unicorn/filename-case */

/**
 * This is a fork of Jose library's utility functions.
 * @source https://github.com/panva/jose/tree/69b7960c67e05be55fa2ec31c74b987696c20c60/src/lib/buffer_utils.ts
 * @license MIT https://github.com/panva/jose/blob/69b7960c67e05be55fa2ec31c74b987696c20c60/LICENSE.md
 */

const MAX_INT32 = 2 ** 32;

function writeUInt32BE(buf: Uint8Array, value: number, offset?: number) {
  if (value < 0 || value >= MAX_INT32) {
    throw new RangeError(
      `value must be >= 0 and <= ${MAX_INT32 - 1}. Received ${value}`,
    );
  }
  buf.set([value >>> 24, value >>> 16, value >>> 8, value & 0xff], offset);
}

export function uint64be(value: number) {
  const high = Math.floor(value / MAX_INT32);
  const low = value % MAX_INT32;
  const buf = new Uint8Array(8);
  writeUInt32BE(buf, high, 0);
  writeUInt32BE(buf, low, 4);
  return buf;
}

export function uint32be(value: number) {
  const buf = new Uint8Array(4);
  writeUInt32BE(buf, value);
  return buf;
}
