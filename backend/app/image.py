import re

MAX_IMAGE_DIM = 512
MAX_IMAGE_CIPHERTEXT_BYTES = 786_448
_IMAGE_META_RE = re.compile(r'^\{"w":([1-9][0-9]{0,2}),"h":([1-9][0-9]{0,2})\}$')


class ImageFormatError(ValueError):
    pass


def image_meta_json(w: int, h: int) -> str:
    if not isinstance(w, int) or not isinstance(h, int) or not (1 <= w <= MAX_IMAGE_DIM and 1 <= h <= MAX_IMAGE_DIM):
        raise ImageFormatError("bad_format")
    return f'{{"w":{w},"h":{h}}}'


def parse_image_meta(meta_json: str) -> tuple[int, int]:
    match = _IMAGE_META_RE.fullmatch(meta_json) if isinstance(meta_json, str) else None
    if not match:
        raise ImageFormatError("bad_format")
    w, h = map(int, match.groups())
    if w > MAX_IMAGE_DIM or h > MAX_IMAGE_DIM:
        raise ImageFormatError("bad_format")
    return w, h


def is_image_meta(meta_json: str) -> bool:
    try:
        parse_image_meta(meta_json)
        return True
    except ImageFormatError:
        return False


def expected_image_ct_len(w: int, h: int) -> int:
    if not (1 <= w <= MAX_IMAGE_DIM and 1 <= h <= MAX_IMAGE_DIM):
        raise ImageFormatError("bad_format")
    return ((w * h * 3) // 16 + 1) * 16
