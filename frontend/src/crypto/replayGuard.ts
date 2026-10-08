/**
 * Replay protection guard tracking the last accepted message counter per sender role.
 * Requires counter > last (gaps allowed, duplicates/decreases rejected as replay).
 */
export class ReplayGuard {
  private lastCounters: { I: number; R: number } = { I: 0, R: 0 };

  public check(role: "I" | "R", counter: number): boolean {
    return counter > this.lastCounters[role];
  }

  public commit(role: "I" | "R", counter: number): void {
    if (counter > this.lastCounters[role]) {
      this.lastCounters[role] = counter;
    }
  }

  public getLast(role: "I" | "R"): number {
    return this.lastCounters[role];
  }

  public reset(): void {
    this.lastCounters = { I: 0, R: 0 };
  }
}

