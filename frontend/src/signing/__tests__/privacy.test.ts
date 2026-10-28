import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const signingRoot = join(here, "..");
const sourceFiles = (directory: string): string[] => readdirSync(directory, { withFileTypes: true })
  .flatMap((entry) => entry.isDirectory()
    ? sourceFiles(join(directory, entry.name))
    : entry.name.endsWith(".ts") || entry.name.endsWith(".tsx") ? [join(directory, entry.name)] : []);

describe("signing key privacy boundaries", () => {
  it("uses no forge, WebCrypto, or Worker implementation in production signing code", () => {
    for (const file of sourceFiles(signingRoot)) {
      if (file.includes(`${join("signing", "__tests__")}`)) continue;
      const source = readFileSync(file, "utf8");
      expect(source).not.toMatch(/from ["'][^"']*node-forge["']|crypto\.subtle|\bnew Worker\s*\(/);
    }
  });

  it("keeps API-layer imports out of signing code except the API adapter", () => {
    for (const file of sourceFiles(signingRoot)) {
      if (file.endsWith(`${join("signing", "api.ts")}`)) continue;
      const source = readFileSync(file, "utf8");
      expect(source).not.toMatch(/from ["'][^"']*(?:\/api\/http|\/api\/api)["']/);
    }
  });

  it("does not persist the in-memory signing key store", () => {
    const store = readFileSync(join(signingRoot, "keyStore.ts"), "utf8");
    expect(store).not.toMatch(/localStorage|sessionStorage|indexedDB/i);
  });
});
