"""Shared test-only signing helper for API and metrics scenarios."""
import base64
from app.crypto.envelope import build_mac_input
from app.crypto.sigsign import export_public_key, generate_keypair, sign_ecdsa
from app.crypto.sigverify import build_signature_input

_signers: dict[str, tuple[int, object]] = {}


def register_signer(client, token: str, *, fresh: bool = False):
    if not fresh and token in _signers:
        return _signers[token]
    private = generate_keypair()
    response = client.post("/api/keys", headers={"Authorization": f"Bearer {token}"}, json={
        "public_key_b64": base64.b64encode(export_public_key(private)).decode("ascii"), "keygen_ms": 1.0})
    assert response.status_code == 201, response.text
    result = (response.json()["id"], private)
    _signers[token] = result
    return result


def signed_message_payload(client, token: str, env, plaintext_len: int) -> dict:
    key_id, private = register_signer(client, token)
    mac_input = build_mac_input(env.session_id, env.sender_role, env.counter, env.msg_type,
                                env.meta_json, env.iv, env.ct)
    signature = sign_ecdsa(private, build_signature_input(mac_input, env.hmac))
    return {"session_id": env.session_id, "counter": env.counter, "msg_type": env.msg_type,
        "meta_json": env.meta_json, "iv": env.iv_b64, "ct": env.ct_b64, "hmac": env.hmac_b64,
        "signer_key_id": key_id, "signature": base64.b64encode(signature).decode("ascii"),
        "sig_gen_ms": 1.0, "hmac_gen_us": 1.0, "pt_len_bytes": plaintext_len}
