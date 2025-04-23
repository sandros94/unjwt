export function lookupAlgorithm<T extends Record<string, any>>(
  alg: keyof T,
  supportedAlgorithms: T,
  algorithmType: string,
): T[keyof T] & { alg: keyof T } {
  const config = supportedAlgorithms[alg as keyof T];

  if (!config) {
    throw new Error(`Unsupported ${algorithmType} algorithm: ${String(alg)}`);
  }

  return { ...config, alg: alg as keyof T };
}
