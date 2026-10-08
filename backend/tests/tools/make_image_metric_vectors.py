"""Pure-Python cross-language oracle for browser image-metric functions; never imported by app code."""
import json
from pathlib import Path

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY = bytes(range(32))
IV = bytes(range(16))


def encrypt(pt: bytes) -> bytes:
    padder = padding.PKCS7(128).padder(); padded = padder.update(pt) + padder.finalize()
    ctx = Cipher(algorithms.AES(KEY), modes.CBC(IV)).encryptor()
    return ctx.update(padded) + ctx.finalize()


def channel_values(buf: bytes, channel: int):
    return buf[channel::3]


def entropy(buf: bytes, channel: int) -> float:
    values = channel_values(buf, channel); counts = [0] * 256
    for value in values: counts[value] += 1
    import math
    return -sum((count / len(values)) * math.log2(count / len(values)) for count in counts if count)


def corr(buf: bytes, w: int, h: int, channel: int):
    if w <= 1: return None
    xs, ys = [], []
    for row in range(h):
        for col in range(w - 1):
            i = (row * w + col) * 3 + channel
            xs.append(buf[i]); ys.append(buf[i + 3])
    mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
    dx = [x - mx for x in xs]; dy = [y - my for y in ys]
    vx, vy = sum(x * x for x in dx), sum(y * y for y in dy)
    if vx == 0 or vy == 0: return None
    return sum(x * y for x, y in zip(dx, dy)) / (vx * vy) ** 0.5


def corr_set(buf: bytes, w: int, h: int):
    vals = [corr(buf, w, h, c) for c in range(3)]
    present = [v for v in vals if v is not None]
    return {**dict(zip(("r", "g", "b"), vals)), "avg": sum(present) / len(present) if present else None}


def mse(a: bytes, b: bytes): return sum((x - y) ** 2 for x, y in zip(a, b)) / len(a)


def make_pixels(w: int, h: int, mode: str) -> bytes:
    out = bytearray()
    for y in range(h):
        for x in range(w):
            if mode == "randomish": values = ((x * 37 + y * 19 + x * y * 3) % 256, (x * 11 + y * 53 + 17) % 256, (x * 71 + y * 7 + 201) % 256)
            elif mode == "gradient": values = ((x * 7 + y * 3) % 256, (x * 5 + y * 9 + (x ^ y)) % 256, (x * 13 + y * 17) % 256)
            elif mode == "odd": values = ((x * 43 + y * 29) % 256, (x * 17 + y * 61 + 9) % 256, (x * 23 + y * 31 + 101) % 256)
            else: values = ((x * 31 + y * 47) % 256, 77, (x * 13 + y * 7) % 256)
            out.extend(values)
    return bytes(out)


def make_vectors():
    cases = []
    for w, h, mode in ((8, 6, "randomish"), (16, 16, "gradient"), (5, 3, "odd"), (4, 4, "constant_g")):
        pt = make_pixels(w, h, mode); n = len(pt); ct = encrypt(pt); cipher = ct[:n]
        flips = []
        for index in dict.fromkeys((0, n // 2, n - 1)):
            changed_pt = bytearray(pt); changed_pt[index] ^= 1; changed_ct = encrypt(bytes(changed_pt))
            changed = sum(a != b for a, b in zip(cipher, changed_ct[:n]))
            abs_diff = sum(abs(a - b) for a, b in zip(cipher, changed_ct[:n]))
            flips.append({"byte_idx": index, "ct_hex": changed_ct.hex(), "changed_count": changed, "sum_abs_diff": abs_diff})
        ent = [entropy(cipher, c) for c in range(3)]; mse_enc = mse(pt, cipher)
        import math
        corr_pt, corr_ct = corr_set(pt, w, h), corr_set(cipher, w, h)
        cases.append({"w": w, "h": h, "pixels_hex": pt.hex(), "ct_hex": ct.hex(), "flip_trials": flips,
            "entropy_r": ent[0], "entropy_g": ent[1], "entropy_b": ent[2], "entropy_avg": sum(ent) / 3,
            "corr_pt": corr_pt, "corr_ct": corr_ct, "mse_enc": mse_enc,
            "psnr_enc": None if mse_enc == 0 else 10 * math.log10(65025 / mse_enc), "mse_dec": 0, "psnr_dec": None})
    return {"key_hex": KEY.hex(), "iv_hex": IV.hex(), "cases": cases}


def main():
    target = Path(__file__).resolve().parents[3] / "shared" / "test_vectors" / "image_metrics.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(make_vectors(), indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(target)


if __name__ == "__main__": main()
