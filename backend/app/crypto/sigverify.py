"""Public-key-only ECDSA P-256 verification for message envelopes."""
import hashlib
import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

# Order of the NIST P-256 base point.
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def parse_public_key(raw_bytes: bytes) -> ec.EllipticCurvePublicKey:
    try:
        if len(raw_bytes) != 65 or raw_bytes[0] != 0x04:
            raise ValueError
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw_bytes)
    except Exception as exc:
        raise ValueError("bad_public_key") from exc


def fingerprint_hex(raw_bytes: bytes) -> str:
    return hashlib.sha256(raw_bytes).hexdigest()


def build_mac_input_bytes(session_id, sender_role, counter, msg_type, meta_json, iv, ct) -> bytes:
    """Independent canonical Phase 4/5 MAC serialization (CC1-msg)."""
    sid = session_id.strip().lower().encode("ascii")
    role = sender_role.strip().encode("ascii")
    typ = msg_type.strip().encode("ascii")
    meta = meta_json.encode("utf-8")
    fields = (sid, role, counter.to_bytes(8, "big"), typ, meta, iv, ct)
    return b"CC1-msg" + b"".join(struct.pack(">I", len(field)) + field for field in fields)


def build_signature_input(mac_input: bytes, hmac_tag: bytes) -> bytes:
    return b"CC1-sig" + struct.pack(">I", len(mac_input)) + mac_input + struct.pack(">I", len(hmac_tag)) + hmac_tag


def verify_ecdsa(public_key_or_raw, signature64: bytes, signature_input: bytes) -> bool:
    try:
        key = (public_key_or_raw if isinstance(public_key_or_raw, ec.EllipticCurvePublicKey)
               else parse_public_key(public_key_or_raw))
        if not isinstance(key.curve, ec.SECP256R1) or len(signature64) != 64:
            return False
        r = int.from_bytes(signature64[:32], "big")
        s = int.from_bytes(signature64[32:], "big")
        if not (1 <= r < P256_ORDER and 1 <= s < P256_ORDER):
            return False
        der = encode_dss_signature(r, s)
        key.verify(der, signature_input, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError, OverflowError):
        return False
    except Exception:
        return False
