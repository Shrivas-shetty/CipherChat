import secrets
from typing import Tuple, Union

from app.crypto.params import BYTE_LEN, G, P, PRIVATE_EXP_BYTES


def generate_private() -> int:
    """
    Generate 32 random bytes from CSPRNG, force top bit to 1 (x >= 2^255).
    """
    raw = bytearray(secrets.token_bytes(PRIVATE_EXP_BYTES))
    raw[0] |= 0x80
    return int.from_bytes(raw, "big")


def int_to_256bytes(val: int) -> bytes:
    """
    Encode non-negative integer into fixed-length 256-byte big-endian format.
    """
    if val < 0:
        raise ValueError("Cannot encode negative integer")
    return val.to_bytes(BYTE_LEN, "big")


def bytes_to_int(b: bytes) -> int:
    """
    Decode big-endian bytes into non-negative integer.
    """
    return int.from_bytes(b, "big")


def encode_public(y: int) -> str:
    """
    Wire format: lowercase hex of the 256-byte big-endian fixed-length encoding
    (always 512 hex chars, left-padded with zeros).
    """
    return int_to_256bytes(y).hex().lower()


def decode_public(hex_str: str) -> int:
    """
    Decode fixed-length 512 lowercase hex string into integer.
    Rejects wrong-length, uppercase, or non-hex strings.
    """
    if not isinstance(hex_str, str):
        raise ValueError("Public value must be a string")
    if len(hex_str) != BYTE_LEN * 2:
        raise ValueError(f"Public value must be exactly {BYTE_LEN * 2} hex characters")
    if not all(c in "0123456789abcdef" for c in hex_str):
        raise ValueError("Public value must contain only lowercase hexadecimal characters")
    raw_bytes = bytes.fromhex(hex_str)
    return bytes_to_int(raw_bytes)


def public_from_private(x: int) -> int:
    """
    Compute public value y = g^x mod p.
    """
    return pow(G, x, P)


def validate_public(y: Union[int, str]) -> Tuple[bool, str]:
    """
    Peer public validation: 2 <= y <= p - 2.
    Reject non-hex or wrong-length strings.
    Returns (True, "") on success, or (False, reason) on failure.
    """
    if isinstance(y, str):
        try:
            val = decode_public(y)
        except ValueError:
            return False, "bad_public"
    elif isinstance(y, int):
        val = y
    else:
        return False, "bad_public"

    if val < 2 or val > (P - 2):
        return False, "bad_public"

    return True, ""


def shared_secret(peer_y: int, x: int) -> bytes:
    """
    Compute shared secret Z = peer_y^x mod p, encoded as 256-byte big-endian fixed-length.
    """
    ok, _ = validate_public(peer_y)
    if not ok:
        raise ValueError("Invalid peer public value for Diffie-Hellman")
    z_int = pow(peer_y, x, P)
    return int_to_256bytes(z_int)

