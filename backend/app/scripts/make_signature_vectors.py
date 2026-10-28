"""Create fixed TEST ONLY cross-language ECDSA P-256 vectors."""
import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec

from app.crypto.sigsign import export_public_key, sign_ecdsa
from app.crypto.sigverify import build_mac_input_bytes, build_signature_input, fingerprint_hex


def main() -> None:
    private_scalar = 1  # Fixed TEST ONLY scalar; never use outside this fixture.
    private = ec.derive_private_key(private_scalar, ec.SECP256R1())
    public_bytes = export_public_key(private)
    mac = build_mac_input_bytes("00000000-0000-4000-8000-000000000001", "I", 1, "text", "{}",
                                bytes(range(16)), bytes(range(16, 32)))
    tag = bytes(range(32))
    signed = build_signature_input(mac, tag)
    result = {"label": "TEST ONLY; fixed private scalar is intentionally public in this fixture",
        "scheme": "ECDSA P-256 (secp256r1) with SHA-256",
        "private_key_hex_test_only": private_scalar.to_bytes(32, "big").hex(),
        "public_key_hex": public_bytes.hex(),
        "public_key_b64": base64.b64encode(public_bytes).decode("ascii"),
        "fingerprint_hex": fingerprint_hex(public_bytes), "mac_input_hex": mac.hex(),
        "hmac_tag_hex": tag.hex(), "signature_input_hex": signed.hex(),
        "python_signature_hex": sign_ecdsa(private, signed).hex(), "typescript_signature_hex": ""}
    path = Path(__file__).resolve().parents[3] / "shared" / "test_vectors" / "signature.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(path)


if __name__ == "__main__":
    main()
