import hashlib
import secrets


def hash_password(password):       # IS CONCEPT SHA 256 HASHING
    salt = secrets.token_hex(16)            #16 means 16 random bytes, which become 32 hexadecimal characters.
                                            # random salt prevents hash collusions
    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt.encode(),
        100000
    ).hex()

    return f"{salt}${password_hash}"          # attacker can see salt though (salt's job is to prevent collusion )


def verify_password(password, stored_password):
    salt, stored_hash = stored_password.split("$")

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt.encode(),
        100000
    ).hex()

    return secrets.compare_digest(password_hash, stored_hash)


