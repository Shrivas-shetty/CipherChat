export type Attack = "preimage" | "second_preimage" | "collision";
export function expectedAttempts(attack: Attack, bits: number): number {
  return attack === "collision" ? Math.sqrt(Math.PI / 2) * 2 ** (bits / 2) : 2 ** bits;
}
export function successProbability(attack: Attack, bits: number, attempts: number): number {
  if (attempts <= 0) return 0;
  const p = 2 ** -bits;
  return attack === "collision" ? -Math.expm1(-attempts * (attempts - 1) / 2 ** (bits + 1)) : -Math.expm1(attempts * Math.log1p(-p));
}
export function formatSci(value: number): string {
  if (value === 0) return "0";
  return value.toExponential(1).replace(/e([+-])0+(\d+)/, "e$1$2");
}
export function formatPow2(bits: number): string {
  return `2^${bits} (about ${formatSci(2 ** bits)})`;
}
