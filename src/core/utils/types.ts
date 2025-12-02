export type StrictOmit<
  T,
  K extends keyof T | (string & {}) | (number & {}) | (symbol & {}),
> = {
  [P in keyof T as P extends K ? never : P]: T[P];
};
