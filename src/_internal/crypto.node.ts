import nodeCrypto from "node:crypto";

/**
 * Based on https://github.com/unjs/uncrypto/tree/v0.1.3
 * Published under MIT License.
 * https://github.com/unjs/uncrypto/blob/v0.1.3/LICENSE
 */

export const subtle: Crypto["subtle"] =
  (nodeCrypto.webcrypto?.subtle as Crypto["subtle"]) ||
  ({} as Crypto["subtle"]);

export const randomUUID: Crypto["randomUUID"] = () => {
  return nodeCrypto.randomUUID();
};

export const getRandomValues: Crypto["getRandomValues"] = (array: any) => {
  return nodeCrypto.webcrypto.getRandomValues(array);
};

const _crypto: Crypto = {
  randomUUID,
  getRandomValues,
  subtle,
};

export default _crypto;
