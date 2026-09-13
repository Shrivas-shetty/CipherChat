import hashlib
import secrets


def hash_password(password):                  # IS CONCEPT SHA 256 HASHING
    salt = secrets.token_hex(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt.encode(),
        100000
    ).hex()

    return f"{salt}${password_hash}"


def verify_password(password, stored_password):
    salt, stored_hash = stored_password.split("$")

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt.encode(),
        100000
    ).hex()

    return password_hash == stored_hash


