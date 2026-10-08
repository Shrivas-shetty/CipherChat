import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import pytest

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from app.crypto.envelope import (
    Envelope,
    EnvelopeError,
    build_mac_input,
    encrypt_message,
    verify_and_decrypt,
)
from app.scripts.make_envelope_vectors import generate_vectors


def test_nist_sp800_38a_f25_known_answer():
    """
    Known-answer test for AES-256-CBC from NIST SP 800-38A F.2.5.
    First block of ciphertext must match f58c4c04d6e5f1ba779eabfb5f7bfbd6.
    """
    key = bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")

    padder = padding.PKCS7(128).padder()
    padded_pt = padder.update(pt) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_pt) + encryptor.finalize()

    expected_first_block = "f58c4c04d6e5f1ba779eabfb5f7bfbd6"
    assert ct[:16].hex() == expected_first_block


def test_round_trip_various_payloads():
    k_enc = b"E" * 32
    k_mac = b"M" * 32
    session_id = "test-session-uuid-1234"
    role = "I"

    test_messages = [
        "ASCII text message",
        "Multi-byte Unicode: Café, crème brûlée, Übermensch, naïve, façade",
        "Emoji message: 🛡️🔐🚀💻🔒✨🎉",
        "A" * 16,  # Exactly 16 bytes (padding boundary test)
        "B" * 2000,  # 2000-character maximum
    ]

    counter = 1
    last_counter = 0

    for msg in test_messages:
        pt_bytes = msg.encode("utf-8")
        env = encrypt_message(
            k_enc=k_enc,
            k_mac=k_mac,
            session_id=session_id,
            sender_role=role,
            counter=counter,
            plaintext_bytes=pt_bytes,
        )

        decrypted = verify_and_decrypt(
            k_enc=k_enc,
            k_mac=k_mac,
            session_id=session_id,
            sender_role=role,
            envelope=env,
            last_counter=last_counter,
        )

        assert decrypted == pt_bytes
        assert decrypted.decode("utf-8") == msg

        last_counter = counter
        counter += 1


def test_iv_freshness():
    k_enc = b"E" * 32
    k_mac = b"M" * 32
    session_id = "test-session-uuid-1234"
    role = "I"
    pt = b"Identical plaintext"

    env1 = encrypt_message(k_enc, k_mac, session_id, role, 1, pt)
    env2 = encrypt_message(k_enc, k_mac, session_id, role, 2, pt)

    assert env1.iv != env2.iv
    assert env1.ct != env2.ct
    assert env1.hmac != env2.hmac


def test_wrong_key_fails():
    k_enc = b"E" * 32
    k_mac = b"M" * 32
    wrong_mac = b"W" * 32
    wrong_enc = b"X" * 32
    session_id = "test-session-uuid-1234"
    role = "I"
    pt = b"Secret data"

    env = encrypt_message(k_enc, k_mac, session_id, role, 1, pt)

    # Wrong K_mac fails at HMAC check
    with pytest.raises(EnvelopeError) as exc_info:
        verify_and_decrypt(k_enc, wrong_mac, session_id, role, env, last_counter=0)
    assert exc_info.value.reason == "hmac_mismatch"

    # Valid HMAC with wrong K_enc fails at decryption
    # Create envelope encrypted with wrong_enc, but MAC'd with k_mac
    env_wrong_enc = encrypt_message(wrong_enc, k_mac, session_id, role, 1, pt)
    with pytest.raises(EnvelopeError) as exc_info:
        verify_and_decrypt(k_enc, k_mac, session_id, role, env_wrong_enc, last_counter=0)
    assert exc_info.value.reason == "decrypt_error"


def test_mutation_matrix_hmac_mismatch():
    k_enc = b"E" * 32
    k_mac = b"M" * 32
    session_id = "test-session-uuid-1234"
    role = "I"
    pt = b"Tamper test message"

    base_env = encrypt_message(k_enc, k_mac, session_id, role, 10, pt)

    # 1. Flip bit in ciphertext
    mutated_ct = bytearray(base_env.ct)
    mutated_ct[0] ^= 0x01
    env_ct = Envelope(
        session_id=base_env.session_id,
        sender_role=base_env.sender_role,
        counter=base_env.counter,
        msg_type=base_env.msg_type,
        meta_json=base_env.meta_json,
        iv=base_env.iv,
        ct=bytes(mutated_ct),
        hmac=base_env.hmac,
    )
    with pytest.raises(EnvelopeError) as e:
        verify_and_decrypt(k_enc, k_mac, session_id, role, env_ct, 0)
    assert e.value.reason == "hmac_mismatch"

    # 2. Flip bit in IV
    mutated_iv = bytearray(base_env.iv)
    mutated_iv[0] ^= 0x01
    env_iv = Envelope(
        session_id=base_env.session_id,
        sender_role=base_env.sender_role,
        counter=base_env.counter,
        msg_type=base_env.msg_type,
        meta_json=base_env.meta_json,
        iv=bytes(mutated_iv),
        ct=base_env.ct,
        hmac=base_env.hmac,
    )
    with pytest.raises(EnvelopeError) as e:
        verify_and_decrypt(k_enc, k_mac, session_id, role, env_iv, 0)
    assert e.value.reason == "hmac_mismatch"

    # 3. Flip bit in HMAC
    mutated_hmac = bytearray(base_env.hmac)
    mutated_hmac[0] ^= 0x01
    env_hmac = Envelope(
        session_id=base_env.session_id,
        sender_role=base_env.sender_role,
        counter=base_env.counter,
        msg_type=base_env.msg_type,
        meta_json=base_env.meta_json,
        iv=base_env.iv,
        ct=base_env.ct,
        hmac=bytes(mutated_hmac),
    )
    with pytest.raises(EnvelopeError) as e:
        verify_and_decrypt(k_enc, k_mac, session_id, role, env_hmac, 0)
    assert e.value.reason == "hmac_mismatch"

    # 4. Mutated counter (still > last_counter, but changed from encrypted value)
    env_c = Envelope(
        session_id=base_env.session_id,
        sender_role=base_env.sender_role,
        counter=base_env.counter + 1,
        msg_type=base_env.msg_type,
        meta_json=base_env.meta_json,
        iv=base_env.iv,
        ct=base_env.ct,
        hmac=base_env.hmac,
    )
    with pytest.raises(EnvelopeError) as e:
        verify_and_decrypt(k_enc, k_mac, session_id, role, env_c, 0)
    assert e.value.reason == "hmac_mismatch"

    # 5. Mutated meta_json
    # Note: if meta_json is not "{}" it fails bad_format. But if we verify HMAC with different input:
    mac_in_meta = build_mac_input(session_id, role, 10, "text", '{"x":1}', base_env.iv, base_env.ct)
    tag_meta = hmac.new(k_mac, mac_in_meta, hashlib.sha256).digest()
    env_meta = Envelope(
        session_id=base_env.session_id,
        sender_role=base_env.sender_role,
        counter=base_env.counter,
        msg_type=base_env.msg_type,
        meta_json="{}",
        iv=base_env.iv,
        ct=base_env.ct,
        hmac=tag_meta,
    )
    with pytest.raises(EnvelopeError) as e:
        verify_and_decrypt(k_enc, k_mac, session_id, role, env_meta, 0)
    assert e.value.reason == "hmac_mismatch"


def test_replay_rejection():
    k_enc = b"E" * 32
    k_mac = b"M" * 32
    session_id = "test-session-uuid-1234"
    role = "I"
    pt = b"Replay test"

    env = encrypt_message(k_enc, k_mac, session_id, role, counter=5, plaintext_bytes=pt)

    # Replay: counter <= last_counter (equal)
    with pytest.raises(EnvelopeError) as e:
        verify_and_decrypt(k_enc, k_mac, session_id, role, env, last_counter=5)
    assert e.value.reason == "replay"

    # Replay: counter < last_counter (decreased)
    with pytest.raises(EnvelopeError) as e:
        verify_and_decrypt(k_enc, k_mac, session_id, role, env, last_counter=6)
    assert e.value.reason == "replay"


def test_bad_format_rejection():
    k_enc = b"E" * 32
    k_mac = b"M" * 32
    session_id = "test-session-uuid-1234"
    role = "I"
    pt = b"Format test"
    env = encrypt_message(k_enc, k_mac, session_id, role, counter=1, plaintext_bytes=pt)

    # Wrong IV length
    env_bad_iv = Envelope(
        session_id=session_id,
        sender_role=role,
        counter=1,
        msg_type="text",
        meta_json="{}",
        iv=b"short_iv",
        ct=env.ct,
        hmac=env.hmac,
    )
    with pytest.raises(EnvelopeError) as e:
        verify_and_decrypt(k_enc, k_mac, session_id, role, env_bad_iv, 0)
    assert e.value.reason == "bad_format"

    # Wrong HMAC length
    env_bad_hmac = Envelope(
        session_id=session_id,
        sender_role=role,
        counter=1,
        msg_type="text",
        meta_json="{}",
        iv=env.iv,
        ct=env.ct,
        hmac=b"short_hmac",
    )
    with pytest.raises(EnvelopeError) as e:
        verify_and_decrypt(k_enc, k_mac, session_id, role, env_bad_hmac, 0)
    assert e.value.reason == "bad_format"

    # Non-multiple of 16 CT length
    env_bad_ct = Envelope(
        session_id=session_id,
        sender_role=role,
        counter=1,
        msg_type="text",
        meta_json="{}",
        iv=env.iv,
        ct=b"123456789012345",  # 15 bytes
        hmac=env.hmac,
    )
    with pytest.raises(EnvelopeError) as e:
        verify_and_decrypt(k_enc, k_mac, session_id, role, env_bad_ct, 0)
    assert e.value.reason == "bad_format"

    # Counter below 1
    env_bad_c = Envelope(
        session_id=session_id,
        sender_role=role,
        counter=0,
        msg_type="text",
        meta_json="{}",
        iv=env.iv,
        ct=env.ct,
        hmac=env.hmac,
    )
    with pytest.raises(EnvelopeError) as e:
        verify_and_decrypt(k_enc, k_mac, session_id, role, env_bad_c, 0)
    assert e.value.reason == "bad_format"


def test_decrypt_error_with_valid_hmac():
    """
    Construct a valid MAC over garbage ciphertext that decrypts with bad padding.
    HMAC must verify, but decryption/unpadding must fail with decrypt_error.
    """
    k_enc = b"E" * 32
    k_mac = b"M" * 32
    session_id = "test-session-uuid-1234"
    role = "I"
    iv = os.urandom(16)
    # Random block of 16 bytes will almost certainly have invalid PKCS7 padding
    garbage_ct = os.urandom(32)

    mac_in = build_mac_input(session_id, role, 1, "text", "{}", iv, garbage_ct)
    valid_hmac = hmac.new(k_mac, mac_in, hashlib.sha256).digest()

    env = Envelope(
        session_id=session_id,
        sender_role=role,
        counter=1,
        msg_type="text",
        meta_json="{}",
        iv=iv,
        ct=garbage_ct,
        hmac=valid_hmac,
    )

    with pytest.raises(EnvelopeError) as e:
        verify_and_decrypt(k_enc, k_mac, session_id, role, env, 0)
    assert e.value.reason == "decrypt_error"


def test_shared_test_vectors_json_match():
    """
    Verify Python make_envelope_vectors reproduces shared/test_vectors/envelope.json
    and verify_and_decrypt successfully decrypts the vector envelopes.
    """
    repo_root = Path(__file__).resolve().parent.parent.parent.parent
    vector_file = repo_root / "shared" / "test_vectors" / "envelope.json"
    assert vector_file.exists()

    with open(vector_file, "r", encoding="utf-8") as f:
        committed_data = json.load(f)

    generated_data = generate_vectors()
    assert generated_data == committed_data

    k_enc = bytes.fromhex(committed_data["k_enc_hex"])
    k_mac = bytes.fromhex(committed_data["k_mac_hex"])

    for case in committed_data["cases"]:
        env = Envelope(
            session_id=case["session_id"],
            sender_role=case["sender_role"],
            counter=case["counter"],
            msg_type=case["msg_type"],
            meta_json=case["meta_json"],
            iv=bytes.fromhex(case["iv_hex"]),
            ct=bytes.fromhex(case["ct_hex"]),
            hmac=bytes.fromhex(case["hmac_hex"]),
        )

        pt = verify_and_decrypt(
            k_enc=k_enc,
            k_mac=k_mac,
            session_id=case["session_id"],
            sender_role=case["sender_role"],
            envelope=env,
            last_counter=0,
        )
        assert pt.decode("utf-8") == case["plaintext"]
