import json
from pathlib import Path
import random

import pytest

from app.crypto.dh import (
    bytes_to_int,
    decode_public,
    encode_public,
    generate_private,
    int_to_256bytes,
    public_from_private,
    shared_secret,
    validate_public,
)
from app.crypto.kdf import (
    confirm_tag,
    derive_session_keys,
    fingerprint_str,
    hkdf_expand,
    hkdf_extract,
    verify_confirm_tag,
)
from app.crypto.params import (
    BYTE_LEN,
    CONFIRM_PREFIX,
    FINGERPRINT_LEN,
    G,
    INFO_ENC,
    INFO_FINGERPRINT,
    INFO_MAC,
    KEY_LEN_ENC,
    KEY_LEN_MAC,
    P,
    PRIVATE_EXP_BYTES,
    SALT_PREFIX,
)


def miller_rabin(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def test_rfc3526_prime():
    # 2048-bit MODP safe prime
    assert P.bit_length() == 2048
    assert G == 2
    # Verify P is prime
    assert miller_rabin(P, rounds=20)
    # Verify (P - 1) / 2 is prime (safe prime)
    q = (P - 1) // 2
    assert q.bit_length() == 2047
    assert miller_rabin(q, rounds=20)


def test_rfc5869_vectors():
    # RFC 5869 Test Case 1
    ikm = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    l = 42

    expected_prk = bytes.fromhex(
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    )
    expected_okm = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    )

    prk = hkdf_extract(salt, ikm)
    assert prk == expected_prk

    okm = hkdf_expand(prk, info, l)
    assert okm == expected_okm


def test_private_key_generation():
    for _ in range(10):
        x = generate_private()
        assert x >= 2**255
        assert x < 2**256
        raw = int_to_256bytes(x)[-32:]  # 32 bytes
        assert (raw[0] & 0x80) == 0x80


def test_public_key_encoding_decoding():
    val = 12345678901234567890
    encoded = encode_public(val)
    assert len(encoded) == 512
    assert encoded == encoded.lower()
    decoded = decode_public(encoded)
    assert decoded == val


def test_public_key_validation():
    # Valid
    valid_pub = pow(G, 12345, P)
    assert validate_public(valid_pub)[0] is True
    valid_hex = encode_public(valid_pub)
    assert validate_public(valid_hex)[0] is True

    # Bad range
    assert validate_public(0)[0] is False
    assert validate_public(1)[0] is False
    assert validate_public(P - 1)[0] is False
    assert validate_public(P)[0] is False
    assert validate_public(P + 1)[0] is False

    # Bad format strings
    assert validate_public("123")[0] is False
    assert validate_public("zz" * 256)[0] is False
    assert validate_public(valid_hex.upper())[0] is False  # Uppercase rejected


def test_dh_hkdf_with_test_vectors():
    # Load shared test vector
    repo_root = Path(__file__).resolve().parent.parent.parent.parent
    vector_file = repo_root / "shared" / "test_vectors" / "dh_hkdf.json"
    assert vector_file.exists(), f"Test vector file missing: {vector_file}"

    with open(vector_file, "r", encoding="utf-8") as f:
        vec = json.load(f)

    session_id = vec["session_id"]
    alice_priv = int(vec["initiator"]["x_hex"], 16)
    bob_priv = int(vec["responder"]["x_hex"], 16)

    # 1. Check generated public keys match
    alice_pub_int = public_from_private(alice_priv)
    alice_pub_hex = encode_public(alice_pub_int)
    assert alice_pub_hex == vec["initiator"]["pub_hex"]

    bob_pub_int = public_from_private(bob_priv)
    bob_pub_hex = encode_public(bob_pub_int)
    assert bob_pub_hex == vec["responder"]["pub_hex"]

    # 2. Check shared secret matches from both perspectives
    bob_pub_decoded = decode_public(vec["responder"]["pub_hex"])
    alice_pub_decoded = decode_public(vec["initiator"]["pub_hex"])

    z_alice = shared_secret(bob_pub_decoded, alice_priv)
    z_bob = shared_secret(alice_pub_decoded, bob_priv)
    assert z_alice == z_bob
    assert z_alice.hex() == vec["shared_secret_z_hex"]

    # 3. Derive session keys and compare
    pub_i_bytes = bytes.fromhex(vec["initiator"]["pub_hex"])
    pub_r_bytes = bytes.fromhex(vec["responder"]["pub_hex"])

    keys = derive_session_keys(
        Z=z_alice,
        session_id=session_id,
        pub_i=pub_i_bytes,
        pub_r=pub_r_bytes,
    )

    assert keys.k_enc.hex() == vec["k_enc_hex"]
    assert keys.k_mac.hex() == vec["k_mac_hex"]
    assert fingerprint_str(keys.fingerprint_bytes) == vec["fingerprint_str"]
    assert vec["fingerprint_str"] == "60B3 9698 05E7 205C"

    # 4. Confirmation tags
    tag_init = confirm_tag(keys.k_mac, session_id, "initiator")
    tag_resp = confirm_tag(keys.k_mac, session_id, "responder")
    assert tag_init == vec["initiator"]["confirm_tag"]
    assert tag_resp == vec["responder"]["confirm_tag"]

    # 5. Tag verification
    assert verify_confirm_tag(keys.k_mac, session_id, "initiator", tag_init) is True
    assert verify_confirm_tag(keys.k_mac, session_id, "responder", tag_resp) is True
    # Swapped role or tampered tag fails
    assert verify_confirm_tag(keys.k_mac, session_id, "initiator", tag_resp) is False
    assert (
        verify_confirm_tag(keys.k_mac, session_id, "initiator", tag_init[:-1] + "0")
        is False
    )
