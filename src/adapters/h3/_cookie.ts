import type { setCookie } from "h3";

export type CookieSerializeOptions = NonNullable<Parameters<typeof setCookie>[3]>;
