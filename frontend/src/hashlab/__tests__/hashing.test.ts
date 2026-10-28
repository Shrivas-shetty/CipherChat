import { describe, expect, it } from "vitest";
import { digestKey, prefixHex, sha256, toHex, utf8 } from "../hashing";
describe("hashing helpers", () => {
  it("matches SHA-256 known answers and leading-bit keys", () => {
    expect(toHex(sha256(utf8("")))).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    const abc = sha256(utf8("abc"));
    expect(toHex(abc)).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    expect(digestKey(abc, 8)).toBe(0xba); expect(digestKey(abc, 12)).toBe(0xba7); expect(digestKey(abc, 16)).toBe(0xba78);
    expect(prefixHex(abc, 16)).toBe("ba78");
  });
});
