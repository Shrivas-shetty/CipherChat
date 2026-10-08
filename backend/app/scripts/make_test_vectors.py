import hashlib
import json
from pathlib import Path

from app.crypto.dh import (
    bytes_to_int,
    encode_public,
    int_to_256bytes,
    public_from_private,
    shared_secret,
)
from app.crypto.kdf import (
    confirm_tag,
    derive_session_keys,
    fingerprint_str,
)
from app.crypto.params import DH_GROUP, SALT_PREFIX


def generate_vectors() -> dict:
    session_id = "a1b2c3d4-e5f6-47a8-9b0c-1d2e3f4a5b6c"

    # Fixed 32-byte private exponents with MSB forced to 1 (>= 2^255)
    x_i_bytes = bytes.fromhex("800102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    x_r_bytes = bytes.fromhex("80202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e")

    x_i = bytes_to_int(x_i_bytes)
    x_r = bytes_to_int(x_r_bytes)

    # Compute public keys
    pub_i_int = public_from_private(x_i)
    pub_r_int = public_from_private(x_r)

    pub_i_hex = encode_public(pub_i_int)
    pub_r_hex = encode_public(pub_r_int)

    pub_i_bytes = int_to_256bytes(pub_i_int)
    pub_r_bytes = int_to_256bytes(pub_r_int)

    # Compute shared secret Z
    z_i = shared_secret(pub_r_int, x_i)
    z_r = shared_secret(pub_i_int, x_r)
    assert z_i == z_r, "Shared secrets do not match"
    z = z_i

    # Compute salt
    salt_material = SALT_PREFIX + session_id.encode("ascii") + pub_i_bytes + pub_r_bytes
    salt = hashlib.sha256(salt_material).digest()

    # Derive keys
    keys = derive_session_keys(z, session_id, pub_i_bytes, pub_r_bytes)
    fp_str = fingerprint_str(keys.fingerprint_bytes)

    # Compute confirmation tags
    confirm_tag_i = confirm_tag(keys.k_mac, session_id, "I")
    confirm_tag_r = confirm_tag(keys.k_mac, session_id, "R")

    return {
        "description": "CipherChat Phase 3 RFC 3526 Group 14 DH & HKDF test vector",
        "dh_group": DH_GROUP,
        "session_id": session_id,
        "initiator": {
            "x_hex": x_i_bytes.hex(),
            "pub_hex": pub_i_hex,
            "confirm_tag": confirm_tag_i,
        },
        "responder": {
            "x_hex": x_r_bytes.hex(),
            "pub_hex": pub_r_hex,
            "confirm_tag": confirm_tag_r,
        },
        "shared_secret_z_hex": z.hex(),
        "salt_hex": salt.hex(),
        "k_enc_hex": keys.k_enc.hex(),
        "k_mac_hex": keys.k_mac.hex(),
        "fingerprint_bytes_hex": keys.fingerprint_bytes.hex(),
        "fingerprint_str": fp_str,
    }


def main():
    root_dir = Path(__file__).resolve().parents[3]
    vectors_dir = root_dir / "shared" / "test_vectors"
    vectors_dir.mkdir(parents=True, exist_ok=True)

    data = generate_vectors()
    out_file = vectors_dir / "dh_hkdf.json"
    out_file.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"Generated test vectors at: {out_file}")


if __name__ == "__main__":
    main()

