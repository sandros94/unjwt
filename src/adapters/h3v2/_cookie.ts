import type { setCookie } from "h3v2";

export type CookieSerializeOptions = NonNullable<Parameters<typeof setCookie>[3]>;
