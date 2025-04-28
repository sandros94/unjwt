export function lookupAlgorithm<T extends Record<string, any>>(
  alg: Readonly<keyof T>,
  supportedAlgorithms: Readonly<T>,
  algorithmType: Readonly<string>,
): T[keyof T] & { alg: keyof T } {
  const config = supportedAlgorithms[alg as keyof T];

  if (!config) {
    throw new Error(`Unsupported ${algorithmType} algorithm: ${String(alg)}`);
  }

  return { ...config, alg: alg as keyof T };
}
