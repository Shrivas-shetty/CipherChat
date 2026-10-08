from dataclasses import dataclass
import hashlib
import hmac

from app.crypto.params import (
    CONFIRM_PREFIX,
    FINGERPRINT_LEN,
    INFO_ENC,
    INFO_FINGERPRINT,
    INFO_MAC,
    KEY_LEN_ENC,
    KEY_LEN_MAC,
    SALT_PREFIX,
)


@dataclass(frozen=True)
class SessionKeys:
    k_enc: bytes
    k_mac: bytes
    fingerprint_bytes: bytes


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """
    HKDF-Extract(salt, IKM) -> PRK
    According to RFC 5869 Section 2.2 using HMAC-SHA256.
    If salt is not provided, it is set to a string of HashLen zeros.
    """
    if not salt:
        salt = b"\x00" * hashlib.sha256().digest_size
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """
    HKDF-Expand(PRK, info, L) -> OKM
    According to RFC 5869 Section 2.3 using HMAC-SHA256.
    """
    hash_len = hashlib.sha256().digest_size
    n = (length + hash_len - 1) // hash_len
    if n > 255:
        raise ValueError("Cannot expand to more than 255 * HashLen bytes")

    blocks = []
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        blocks.append(t)
    return b"".join(blocks)[:length]


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """
    Full HKDF-SHA256 extract and expand pipeline.
    """
    prk = hkdf_extract(salt, ikm)
    return hkdf_expand(prk, info, length)


def derive_session_keys(
    Z: bytes,
    session_id: str,
    pub_i: bytes,
    pub_r: bytes,
) -> SessionKeys:
    """
    Derives K_enc (32 bytes), K_mac (32 bytes), and fingerprint (8 bytes)
    via HKDF-SHA256 using salt computed from session_id, pub_initiator, and pub_responder.
    """
    clean_session_id = session_id.strip().lower().encode("ascii")
    salt_material = SALT_PREFIX + clean_session_id + pub_i + pub_r
    salt = hashlib.sha256(salt_material).digest()

    prk = hkdf_extract(salt, Z)
    k_enc = hkdf_expand(prk, INFO_ENC, KEY_LEN_ENC)
    k_mac = hkdf_expand(prk, INFO_MAC, KEY_LEN_MAC)
    fingerprint_bytes = hkdf_expand(prk, INFO_FINGERPRINT, FINGERPRINT_LEN)

    return SessionKeys(
        k_enc=k_enc,
        k_mac=k_mac,
        fingerprint_bytes=fingerprint_bytes,
    )


def fingerprint_str(fingerprint_bytes: bytes) -> str:
    """
    Formats the 8 bytes as uppercase hex in 4 groups of 4 separated by spaces,
    e.g. 'A1B2 C3D4 E5F6 0718'.
    """
    if len(fingerprint_bytes) != FINGERPRINT_LEN:
        raise ValueError(f"Fingerprint must be {FINGERPRINT_LEN} bytes")
    hex_str = fingerprint_bytes.hex().upper()
    return f"{hex_str[0:4]} {hex_str[4:8]} {hex_str[8:12]} {hex_str[12:16]}"


def confirm_tag(k_mac: bytes, session_id: str, role: str) -> str:
    """
    Computes key confirmation tag:
    HMAC-SHA256(key=K_mac, msg = ASCII 'CC1-confirm' || ASCII session_id || ASCII role_char)
    where role_char is 'I' for initiator and 'R' for responder.
    """
    if role in ("initiator", "I"):
        role_char = b"I"
    elif role in ("responder", "R"):
        role_char = b"R"
    else:
        raise ValueError(f"Invalid role: {role}")

    clean_session_id = session_id.strip().lower().encode("ascii")
    msg = CONFIRM_PREFIX + clean_session_id + role_char
    return hmac.new(k_mac, msg, hashlib.sha256).hexdigest().lower()


def verify_confirm_tag(
    k_mac: bytes,
    session_id: str,
    role: str,
    received_tag: str,
) -> bool:
    """
    Constant-time comparison of expected vs received confirmation tag.
    """
    expected = confirm_tag(k_mac, session_id, role)
    return hmac.compare_digest(expected, received_tag.strip().lower())

