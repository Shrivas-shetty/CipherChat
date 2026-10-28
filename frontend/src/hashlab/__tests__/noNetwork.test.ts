import { describe, expect, it } from "vitest";
describe("Hashing Lab network isolation", () => {
  it("contains no network clients or HTTP API imports", () => {
    const logic = import.meta.glob("../**/*.{ts,tsx}", { eager: true, query: "?raw", import: "default" });
    const ui = import.meta.glob("../../dashboard/tabs/lab/hashing/**/*.{ts,tsx}", { eager: true, query: "?raw", import: "default" });
    const codeSources = [...Object.entries(logic), ...Object.entries(ui)].filter(([path]) => !path.includes("__tests__")).map(([, source]) => source) as string[];
    for (const code of codeSources) {
      expect(code).not.toMatch(/from\s+["'][^"']*(?:api\/http|dashboard\/api)["']/);
      expect(code).not.toMatch(/\b(?:fetch|XMLHttpRequest|WebSocket)\b/);
    }
  });
});
