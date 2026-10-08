import base64
import json
from pathlib import Path

from app.crypto.envelope import build_mac_input, encrypt_message


def generate_vectors() -> dict:
    session_id = "a1b2c3d4-e5f6-47a8-9b0c-1d2e3f4a5b6c"
    k_enc = bytes.fromhex("ee986f66e2d764c00fa10cb72b4dd3cf62fc310ad65dea9f920d24c6a5a5f11a")
    k_mac = bytes.fromhex("47406beb19559ed4bb7604e6148f8dc59726294160905ab58918982e0a763dc2")

    cases = []

    # Case 1: ASCII message
    c1_role = "I"
    c1_counter = 1
    c1_pt = "Hello, Bob! Secure AES-256-CBC chat."
    c1_pt_bytes = c1_pt.encode("utf-8")
    c1_iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    env1 = encrypt_message(
        k_enc=k_enc,
        k_mac=k_mac,
        session_id=session_id,
        sender_role=c1_role,
        counter=c1_counter,
        plaintext_bytes=c1_pt_bytes,
        msg_type="text",
        meta_json="{}",
        iv=c1_iv,
    )
    mac_in1 = build_mac_input(session_id, c1_role, c1_counter, "text", "{}", c1_iv, env1.ct)
    cases.append(
        {
            "name": "case1_ascii",
            "session_id": session_id,
            "sender_role": c1_role,
            "counter": c1_counter,
            "msg_type": "text",
            "meta_json": "{}",
            "plaintext": c1_pt,
            "plaintext_hex": c1_pt_bytes.hex(),
            "iv_hex": c1_iv.hex(),
            "iv_b64": env1.iv_b64,
            "mac_input_hex": mac_in1.hex(),
            "ct_hex": env1.ct.hex(),
            "ct_b64": env1.ct_b64,
            "hmac_hex": env1.hmac.hex(),
            "hmac_b64": env1.hmac_b64,
        }
    )

    # Case 2: Unicode & Emoji message
    c2_role = "R"
    c2_counter = 1
    c2_pt = "🔐 CipherChat encrypted message with accents: voilà, café & emojis: 🛡️🚀"
    c2_pt_bytes = c2_pt.encode("utf-8")
    c2_iv = bytes.fromhex("101112131415161718191a1b1c1d1e1f")
    env2 = encrypt_message(
        k_enc=k_enc,
        k_mac=k_mac,
        session_id=session_id,
        sender_role=c2_role,
        counter=c2_counter,
        plaintext_bytes=c2_pt_bytes,
        msg_type="text",
        meta_json="{}",
        iv=c2_iv,
    )
    mac_in2 = build_mac_input(session_id, c2_role, c2_counter, "text", "{}", c2_iv, env2.ct)
    cases.append(
        {
            "name": "case2_unicode_emoji",
            "session_id": session_id,
            "sender_role": c2_role,
            "counter": c2_counter,
            "msg_type": "text",
            "meta_json": "{}",
            "plaintext": c2_pt,
            "plaintext_hex": c2_pt_bytes.hex(),
            "iv_hex": c2_iv.hex(),
            "iv_b64": env2.iv_b64,
            "mac_input_hex": mac_in2.hex(),
            "ct_hex": env2.ct.hex(),
            "ct_b64": env2.ct_b64,
            "hmac_hex": env2.hmac.hex(),
            "hmac_b64": env2.hmac_b64,
        }
    )

    return {
        "description": "CipherChat Phase 4 AES-256-CBC + HMAC-SHA256 envelope test vectors",
        "cipher": "aes-256-cbc-pkcs7",
        "mac": "hmac-sha256",
        "k_enc_hex": k_enc.hex(),
        "k_mac_hex": k_mac.hex(),
        "cases": cases,
    }


def main():
    repo_root = Path(__file__).resolve().parent.parent.parent.parent
    out_dir = repo_root / "shared" / "test_vectors"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "envelope.json"

    data = generate_vectors()
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"Wrote envelope test vectors to {out_file}")


if __name__ == "__main__":
    main()

