import { cbc } from "@noble/ciphers/aes.js";

export function aesCbcEncrypt(key: Uint8Array, iv: Uint8Array, plaintext: Uint8Array): Uint8Array {
  return cbc(key, iv).encrypt(plaintext);
}

export function aesCbcDecrypt(key: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  return cbc(key, iv).decrypt(ciphertext);
}
