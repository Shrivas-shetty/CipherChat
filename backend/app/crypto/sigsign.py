"""ECDSA P-256 reference signer for tests and the headless benchmark client only."""
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature


def generate_keypair():
    return ec.generate_private_key(ec.SECP256R1())


def export_public_key(private_or_public_key) -> bytes:
    key = (private_or_public_key.public_key()
           if isinstance(private_or_public_key, ec.EllipticCurvePrivateKey)
           else private_or_public_key)
    return key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def sign_ecdsa(private_key, signature_input: bytes) -> bytes:
    der = private_key.sign(signature_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")
