/**
 * Computes (base^exp) mod mod using square-and-multiply algorithm with BigInt.
 */
export function modpow(base: bigint, exp: bigint, mod: bigint): bigint {
  if (mod === 1n) {
    return 0n;
  }
  if (exp < 0n) {
    throw new Error("Negative exponent not supported");
  }
  let result = 1n;
  let b = base % mod;
  let e = exp;

  while (e > 0n) {
    if (e & 1n) {
      result = (result * b) % mod;
    }
    e >>= 1n;
    b = (b * b) % mod;
  }
  return result;
}

