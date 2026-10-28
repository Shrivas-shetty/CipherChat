import base64
import json
import os
from pathlib import Path
import re

from app.crypto.envelope import build_mac_input
from app.crypto.sigverify import P256_ORDER, build_mac_input_bytes, build_signature_input, parse_public_key, verify_ecdsa

VECTORS = Path(__file__).resolve().parents[3] / "shared" / "test_vectors" / "signature.json"


def test_signature_fixture_signatures_verify_and_mutations_fail():
    fixture = json.loads(VECTORS.read_text(encoding="utf-8"))
    public = base64.b64decode(fixture["public_key_b64"])
    signed = bytes.fromhex(fixture["signature_input_hex"])
    python_sig = bytes.fromhex(fixture["python_signature_hex"])
    ts_sig = bytes.fromhex(fixture["typescript_signature_hex"])
    assert verify_ecdsa(public, python_sig, signed)
    assert verify_ecdsa(public, ts_sig, signed)
    assert build_signature_input(bytes.fromhex(fixture["mac_input_hex"]), bytes.fromhex(fixture["hmac_tag_hex"])) == signed
    assert __import__("hashlib").sha256(public).hexdigest() == fixture["fingerprint_hex"]

    for original in (python_sig, ts_sig):
        changed_sig = bytearray(original); changed_sig[0] ^= 1
        changed_input = bytearray(signed); changed_input[0] ^= 1
        changed_public = bytearray(public); changed_public[1] ^= 1
        assert not verify_ecdsa(public, bytes(changed_sig), signed)
        assert not verify_ecdsa(public, original, bytes(changed_input))
        assert not verify_ecdsa(bytes(changed_public), original, signed)


def test_verifier_handles_bad_lengths_scalars_and_points_without_raising():
    fixture = json.loads(VECTORS.read_text(encoding="utf-8"))
    public = base64.b64decode(fixture["public_key_b64"])
    signed = bytes.fromhex(fixture["signature_input_hex"])
    valid_sig = bytes.fromhex(fixture["python_signature_hex"])
    for signature in (b"", bytes(63), bytes(65), bytes(64)):
        assert not verify_ecdsa(public, signature, signed)
    assert not verify_ecdsa(public, bytes(32) + valid_sig[32:], signed)
    assert not verify_ecdsa(public, P256_ORDER.to_bytes(32, "big") + valid_sig[32:], signed)
    assert not verify_ecdsa(public, valid_sig[:32] + bytes(32), signed)
    assert not verify_ecdsa(public, valid_sig[:32] + P256_ORDER.to_bytes(32, "big"), signed)
    for bad_public in (b"", bytes(64), bytes(65), b"\x04" + bytes(64), b"\x02" + bytes(32)):
        assert not verify_ecdsa(bad_public, bytes.fromhex(fixture["python_signature_hex"]), signed)
    import pytest
    with pytest.raises(ValueError, match="bad_public_key"):
        parse_public_key(b"not an EC point")


def test_independent_mac_input_matches_envelope_for_random_text_and_images():
    import random
    rng = random.Random(12012)
    for _ in range(200):
        image = bool(rng.getrandbits(1))
        sid = f"00000000-0000-4000-8000-{rng.randrange(1, 2**48):012x}"
        role = rng.choice(("I", "R")); counter = rng.randrange(1, 2**32)
        typ = "image" if image else "text"
        meta = f'{{"w":{rng.randrange(1,512)},"h":{rng.randrange(1,512)}}}' if image else "{}"
        iv = os.urandom(16); ct = os.urandom(rng.choice((16, 32, 64, 256)))
        assert build_mac_input_bytes(sid, role, counter, typ, meta, iv, ct) == build_mac_input(sid, role, counter, typ, meta, iv, ct)


def test_server_crypto_import_boundaries_and_schema_field_names():
    app_root = Path(__file__).resolve().parents[1]
    forbidden = ("app.crypto.sigsign", "app.crypto.envelope", "app.crypto.kdf")
    for area in ("routers", "ws", "services", "db"):
        for source in (app_root / area).rglob("*.py"):
            contents = source.read_text(encoding="utf-8")
            assert not any(module in contents for module in forbidden), str(source)
    verifier = (app_root / "crypto" / "sigverify.py").read_text(encoding="utf-8")
    assert not any(module in verifier for module in forbidden)

    from app.db.base import Base
    assert all(not re.search(r"private", column.name, re.IGNORECASE)
               for table in Base.metadata.tables.values() for column in table.columns)
