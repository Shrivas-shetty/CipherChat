const UINT32_RANGE = 0x1_0000_0000;

export function uniformInt(maxInclusive: number, rng: () => number = defaultRandom): number {
  if (!Number.isSafeInteger(maxInclusive) || maxInclusive < 0 || maxInclusive >= UINT32_RANGE) throw new RangeError("maxInclusive must be in [0, 2^32)");
  const size = maxInclusive + 1;
  const cutoff = Math.floor(UINT32_RANGE / size) * size;
  for (;;) {
    const value = Math.floor(rng() * UINT32_RANGE);
    if (!Number.isFinite(value) || value < 0 || value >= UINT32_RANGE) throw new RangeError("rng must return a number in [0, 1)");
    if (value < cutoff) return value % size;
  }
}

function defaultRandom(): number {
  const value = crypto.getRandomValues(new Uint32Array(1))[0];
  return value / UINT32_RANGE;
}
