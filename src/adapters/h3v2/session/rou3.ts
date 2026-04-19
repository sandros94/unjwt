/**
 * FORK of rou3's `NullProtoObj`, just to avoid an additional peer dependency on `rou3` for this single export.
 *
 * LICENSE: MIT
 *
 * SOURCE: https://github.com/h3js/rou3/blob/f6a5b4deb14ebd73a46b5411835b002781f633cf/src/object.ts
 */

// prettier-ignore
export const NullProtoObj = /* @__PURE__ */ (()=>{const e=function(){};return e.prototype=Object.create(null),Object.freeze(e.prototype),e})() as unknown as { new (): any };
