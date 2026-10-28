import random

WORDS = ("cipher", "secure", "message", "network", "session", "integrity", "benchmark", "chat")


def make_text(length: int, marker: str | None = None, seed: int = 0) -> str:
    if length < 0:
        raise ValueError("length must be nonnegative")
    rng = random.Random(seed)
    prefix = f"{marker} " if marker and length >= len(marker) + 1 else ""
    result = prefix
    while len(result) < length:
        word = rng.choice(WORDS)
        result += (" " if result else "") + word
    return result[:length]


def make_rgb(side: int, seed: int = 0) -> bytes:
    if side < 1:
        raise ValueError("side must be positive")
    rng = random.Random(seed)
    noise = rng.randbytes(side * side * 3)
    out = bytearray(len(noise))
    for y in range(side):
        for x in range(side):
            i = (y * side + x) * 3
            out[i] = (x * 255 // max(1, side - 1) + noise[i] // 8) & 255
            out[i + 1] = (y * 255 // max(1, side - 1) + noise[i + 1] // 8) & 255
            out[i + 2] = ((x + y) * 127 // max(1, 2 * side - 2) + noise[i + 2] // 8) & 255
    return bytes(out)
