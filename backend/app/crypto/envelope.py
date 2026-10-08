import base64
from dataclasses import dataclass
import hashlib
import hmac
import os
from typing import Optional

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from app.image import MAX_IMAGE_CIPHERTEXT_BYTES, MAX_IMAGE_DIM, ImageFormatError, expected_image_ct_len as _expected_image_ct_len, image_meta_json as _image_meta_json, is_image_meta, parse_image_meta as _parse_image_meta


class EnvelopeError(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def image_meta_json(w: int, h: int) -> str:
    try:
        return _image_meta_json(w, h)
    except ImageFormatError as exc:
        raise EnvelopeError("bad_format") from exc


def parse_image_meta(meta_json: str) -> tuple[int, int]:
    try:
        return _parse_image_meta(meta_json)
    except ImageFormatError as exc:
        raise EnvelopeError("bad_format") from exc


def expected_image_ct_len(w: int, h: int) -> int:
    try:
        return _expected_image_ct_len(w, h)
    except ImageFormatError as exc:
        raise EnvelopeError("bad_format") from exc




@dataclass
class Envelope:
    session_id: str
    sender_role: str
    counter: int
    msg_type: str
    meta_json: str
    iv: bytes
    ct: bytes
    hmac: bytes

    @property
    def iv_b64(self) -> str:
        return base64.b64encode(self.iv).decode("ascii")

    @property
    def ct_b64(self) -> str:
        return base64.b64encode(self.ct).decode("ascii")

    @property
    def hmac_b64(self) -> str:
        return base64.b64encode(self.hmac).decode("ascii")

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "sender_role": self.sender_role,
            "counter": self.counter,
            "msg_type": self.msg_type,
            "meta_json": self.meta_json,
            "iv": self.iv_b64,
            "ct": self.ct_b64,
            "hmac": self.hmac_b64,
        }


def _encode_field(data: bytes) -> bytes:
    return len(data).to_bytes(4, "big") + data


def build_mac_input(
    session_id: str,
    sender_role: str,
    counter: int,
    msg_type: str,
    meta_json: str,
    iv: bytes,
    ct: bytes,
) -> bytes:
    """
    Construct canonical deterministic MAC input:
    ASCII "CC1-msg" followed by 7 fields, each encoded as
    4-byte big-endian length + field bytes:
    1. session_id (ASCII uuid string, lowercase with hyphens)
    2. sender_role (1 byte ASCII: "I" or "R")
    3. counter (exactly 8 bytes, big-endian unsigned)
    4. msg_type (ASCII, "text")
    5. meta_json (UTF-8 bytes)
    6. iv (16 bytes)
    7. ciphertext (raw bytes)
    """
    s_bytes = session_id.strip().lower().encode("ascii")
    r_bytes = sender_role.strip().encode("ascii")
    c_bytes = counter.to_bytes(8, "big")
    t_bytes = msg_type.strip().encode("ascii")
    m_bytes = meta_json.encode("utf-8")

    return (
        b"CC1-msg"
        + _encode_field(s_bytes)
        + _encode_field(r_bytes)
        + _encode_field(c_bytes)
        + _encode_field(t_bytes)
        + _encode_field(m_bytes)
        + _encode_field(iv)
        + _encode_field(ct)
    )


def encrypt_message(
    k_enc: bytes,
    k_mac: bytes,
    session_id: str,
    sender_role: str,
    counter: int,
    plaintext_bytes: bytes,
    msg_type: str = "text",
    meta_json: str = "{}",
    iv: Optional[bytes] = None,
) -> Envelope:
    """
    Encrypt plaintext using AES-256-CBC with PKCS7 padding, then HMAC-SHA256 (Encrypt-then-MAC).
    `iv` may be injected ONLY for deterministic test vectors; otherwise random 16 bytes.
    """
    if len(k_enc) != 32 or len(k_mac) != 32:
        raise ValueError("k_enc and k_mac must be 32 bytes")
    if sender_role not in ("I", "R"):
        raise ValueError("sender_role must be 'I' or 'R'")
    if counter < 1:
        raise ValueError("counter must be >= 1")
    if msg_type not in ("text", "image"):
        raise ValueError("msg_type must be 'text' or 'image'")
    if msg_type == "text":
        if meta_json != "{}":
            raise ValueError("meta_json must be '{}' for text")
        if len(plaintext_bytes) < 1 or len(plaintext_bytes) > 8000:
            raise ValueError("plaintext_bytes must be between 1 and 8000 bytes")
    else:
        w, h = parse_image_meta(meta_json)
        if len(plaintext_bytes) != w * h * 3:
            raise ValueError("image plaintext length does not match dimensions")

    if iv is None:
        iv = os.urandom(16)
    elif len(iv) != 16:
        raise ValueError("iv must be exactly 16 bytes")

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext_bytes) + padder.finalize()

    cipher = Cipher(algorithms.AES(k_enc), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()

    mac_in = build_mac_input(session_id, sender_role, counter, msg_type, meta_json, iv, ct)
    tag = hmac.new(k_mac, mac_in, hashlib.sha256).digest()

    return Envelope(
        session_id=session_id.strip().lower(),
        sender_role=sender_role,
        counter=counter,
        msg_type=msg_type,
        meta_json=meta_json,
        iv=iv,
        ct=ct,
        hmac=tag,
    )


def verify_and_decrypt(
    k_enc: bytes,
    k_mac: bytes,
    session_id: str,
    sender_role: str,
    envelope: Envelope,
    last_counter: int,
) -> bytes:
    """
    Strict receive pipeline:
    1. Format checks -> "bad_format"
    2. Replay check -> "replay"
    3. Recompute HMAC and constant-time compare -> "hmac_mismatch"
    4. AES decrypt + PKCS7 unpad -> "decrypt_error"
    """
    # 1. Format checks
    if not (
        isinstance(envelope.iv, (bytes, bytearray))
        and len(envelope.iv) == 16
        and isinstance(envelope.hmac, (bytes, bytearray))
        and len(envelope.hmac) == 32
        and isinstance(envelope.ct, (bytes, bytearray))
        and 16 <= len(envelope.ct) <= (8192 if envelope.msg_type == "text" else MAX_IMAGE_CIPHERTEXT_BYTES)
        and len(envelope.ct) % 16 == 0
        and isinstance(envelope.counter, int)
        and envelope.counter >= 1
        and envelope.sender_role in ("I", "R")
        and envelope.sender_role == sender_role
        and envelope.session_id.strip().lower() == session_id.strip().lower()
        and envelope.msg_type in ("text", "image")
        and (envelope.msg_type == "image" or envelope.meta_json == "{}" or is_image_meta(envelope.meta_json))
    ):
        raise EnvelopeError("bad_format")

    # 2. Replay check
    if envelope.counter <= last_counter:
        raise EnvelopeError("replay")

    # 3. HMAC check (Encrypt-then-MAC: MUST verify before decrypting)
    mac_in = build_mac_input(
        session_id,
        sender_role,
        envelope.counter,
        envelope.msg_type,
        envelope.meta_json,
        envelope.iv,
        envelope.ct,
    )
    expected_tag = hmac.new(k_mac, mac_in, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_tag, envelope.hmac):
        raise EnvelopeError("hmac_mismatch")

    # 4. Decrypt + PKCS7 unpad + UTF-8 decode
    try:
        cipher = Cipher(algorithms.AES(k_enc), modes.CBC(envelope.iv))
        decryptor = cipher.decryptor()
        padded = decryptor.update(envelope.ct) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        pt = unpadder.update(padded) + unpadder.finalize()

        if envelope.msg_type == "text":
            if envelope.meta_json != "{}":
                raise EnvelopeError("bad_format")
            pt_str = pt.decode("utf-8")
            if not (1 <= len(pt_str) <= 2000 and 1 <= len(pt) <= 8000):
                raise EnvelopeError("decrypt_error")
        else:
            w, h = parse_image_meta(envelope.meta_json)
            if len(pt) != w * h * 3 or len(envelope.ct) != expected_image_ct_len(w, h):
                raise EnvelopeError("bad_format")
        return pt
    except EnvelopeError:
        raise
    except Exception:
        raise EnvelopeError("decrypt_error")

