"""Reference-only AES-CBC test oracle; the application must never import this module."""
import json
from pathlib import Path

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY = bytes(range(32))
IV = bytes(range(16))
PLAINTEXTS = [b"Cipher!", b"A" * 40, "Hi🙂 there 🌍! café 🔐!1234567890".encode("utf-8")]


def encrypt(key: bytes, iv: bytes, pt: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(pt) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return cipher.update(padded) + cipher.finalize()


def decrypt(key: bytes, iv: bytes, ct: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = cipher.update(ct) + cipher.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def diff_bits(a: bytes, b: bytes) -> int:
    return sum((x ^ y).bit_count() for x, y in zip(a, b))


def flip(data: bytes, bit_index: int) -> bytes:
    copy = bytearray(data)
    copy[bit_index // 8] ^= 1 << (7 - bit_index % 8)
    return bytes(copy)


def make_vectors() -> dict:
    cases = []
    for pt in PLAINTEXTS:
        ct = encrypt(KEY, IV, pt)
        key_trials = []
        for idx in (0, 7, 100, 255):
            changed = encrypt(flip(KEY, idx), IV, pt)
            key_trials.append({"bit_idx": idx, "changed_bits": diff_bits(ct, changed)})
        pt_trials = []
        for idx in dict.fromkeys((0, 3, 8 * len(pt) // 2, 8 * len(pt) - 1)):
            changed = encrypt(KEY, IV, flip(pt, idx))
            block = idx // 8 // 16
            start = block * 16
            pt_trials.append({"bit_idx": idx, "changed_bits": diff_bits(ct, changed), "block_changed_bits": diff_bits(ct[start:start + 16], changed[start:start + 16])})
        cases.append({"pt_hex": pt.hex(), "ct_hex": ct.hex(), "key_flip_trials": key_trials, "pt_flip_trials": pt_trials, "round_trip": decrypt(KEY, IV, ct).hex()})
    return {"key_hex": KEY.hex(), "iv_hex": IV.hex(), "cases": cases}


def main() -> None:
    target = Path(__file__).resolve().parents[3] / "shared" / "test_vectors" / "text_metrics.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(make_vectors(), indent=2) + "\n", encoding="utf-8")
    print(target)


if __name__ == "__main__":
    main()
