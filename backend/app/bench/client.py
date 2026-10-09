"""HTTP/WebSocket headless participant. Cryptographic operations use app.crypto."""
import asyncio
import base64
import json
import time
from dataclasses import dataclass

import httpx
import websockets

from app.crypto.dh import decode_public, encode_public, generate_private, public_from_private, shared_secret
from app.crypto.kdf import confirm_tag, derive_session_keys, fingerprint_str


@dataclass
class BenchKeys:
    session_id: str
    role: str
    sender_role: str
    enc: bytes
    mac: bytes
    fingerprint: str
    duration_ms: float


class BenchUser:
    def __init__(self, base_url: str, username: str, password: str):
        self.base_url, self.username, self.password = base_url.rstrip("/"), username, password
        self.http = httpx.AsyncClient(base_url=self.base_url, timeout=30)
        self.token = None
        self.ws = None
        self.reader = None
        self.queues: dict[str, asyncio.Queue] = {}
        self.arrivals: dict[int, tuple[float, int]] = {}
        self.keys_future = asyncio.get_event_loop().create_future()
        self._pending_start = None
        self.send_counter = 0
        self.recv_counter = 0

    def _headers(self): return {"Authorization": f"Bearer {self.token}"}

    async def ensure_registered(self):
        response = await self.http.post("/api/auth/register", json={"username": self.username, "password": self.password})
        if response.status_code not in (201, 409): response.raise_for_status()

    async def login(self):
        response = await self.http.post("/api/auth/login", json={"username": self.username, "password": self.password})
        response.raise_for_status(); self.token = response.json()["access_token"]

    async def connect_ws(self):
        if self.keys_future.done():
            self.keys_future = asyncio.get_running_loop().create_future()
        url = self.base_url.replace("https://", "wss://").replace("http://", "ws://") + "/ws"
        self.ws = await websockets.connect(url, max_size=2_000_000)
        await self.ws.send(json.dumps({"v": 1, "type": "auth", "token": self.token}))
        self.reader = asyncio.create_task(self._read_loop())

    async def _read_loop(self):
        async for raw in self.ws:
            arrival = time.perf_counter()
            frame = json.loads(raw)
            if frame.get("type") in ("message_available", "baseline_available"):
                self.arrivals[frame["message_id"]] = (arrival, len(raw.encode()))
            kind = frame.get("type")
            if kind == "session_start":
                asyncio.create_task(self._handshake(frame, arrival))
            else:
                await self.queues.setdefault(kind, asyncio.Queue()).put((frame, arrival, len(raw.encode())))

    async def _handshake(self, frame, started):
        from app.crypto.envelope import Envelope
        session_id, role = frame["session_id"], frame["role"]
        key_start = time.perf_counter(); private = generate_private(); public = public_from_private(private)
        pub_hex = encode_public(public); keygen_ms = (time.perf_counter() - key_start) * 1000
        await self.ws.send(json.dumps({"v": 1, "type": "dh_public", "session_id": session_id, "public": pub_hex}))
        peer, _, _ = await self._wait("dh_public", session_id)
        derive_start = time.perf_counter(); peer_public = decode_public(peer["public"])
        init_public = bytes.fromhex(pub_hex if role == "initiator" else peer["public"])
        resp_public = bytes.fromhex(peer["public"] if role == "initiator" else pub_hex)
        keys = derive_session_keys(shared_secret(peer_public, private), session_id, init_public, resp_public)
        derive_ms = (time.perf_counter() - derive_start) * 1000
        tag = confirm_tag(keys.k_mac, session_id, role)
        await self.ws.send(json.dumps({"v": 1, "type": "key_confirm", "session_id": session_id, "tag": tag}))
        peer_confirm, _, _ = await self._wait("key_confirm", session_id)
        peer_role = "responder" if role == "initiator" else "initiator"
        if peer_confirm["tag"] != confirm_tag(keys.k_mac, session_id, peer_role): raise RuntimeError("key confirmation failed")
        fingerprint = fingerprint_str(keys.fingerprint_bytes)
        await self.ws.send(json.dumps({"v":1,"type":"key_verified","session_id":session_id,"fingerprint":fingerprint,"timings":{"keygen_ms":keygen_ms,"derive_ms":derive_ms}}))
        _, established_at, _ = await self._wait("session_established", session_id)
        result = BenchKeys(session_id, role, "I" if role == "initiator" else "R", keys.k_enc, keys.k_mac, fingerprint, (established_at-started)*1000)
        if not self.keys_future.done(): self.keys_future.set_result(result)

    async def _wait(self, kind, session_id=None):
        q = self.queues.setdefault(kind, asyncio.Queue())
        while True:
            item = await asyncio.wait_for(q.get(), 20)
            frame = item[0]
            if session_id is None or frame.get("session_id") == session_id: return item

    async def established(self): return await self.keys_future

    async def send_secure(self, kind, plaintext: bytes, w=None, h=None):
        from app.crypto.envelope import encrypt_message, image_meta_json
        keys = await self.established(); self.send_counter += 1
        meta = image_meta_json(w, h) if kind == "image" else "{}"
        envelope = encrypt_message(keys.enc, keys.mac, keys.session_id, keys.sender_role, self.send_counter, plaintext, kind, meta)
        payload = {"session_id": keys.session_id, "counter": self.send_counter, "msg_type": kind, "meta_json": meta,
                   "iv": envelope.iv_b64, "ct": envelope.ct_b64, "hmac": envelope.hmac_b64}
        body = json.dumps(payload, separators=(",", ":")).encode()
        response = await self.http.post("/api/messages", content=body, headers={**self._headers(), "Content-Type":"application/json"})
        response.raise_for_status(); return response.json(), len(body)

    async def receive_secure(self, message_id: int):
        from app.crypto.envelope import Envelope, verify_and_decrypt
        response = await self.http.get(f"/api/messages/{message_id}", headers=self._headers()); response.raise_for_status()
        data=response.json(); keys=await self.established()
        role = "R" if keys.sender_role == "I" else "I"
        env=Envelope(data["session_id"],data["from_role"],data["counter"],data["msg_type"],data["meta_json"],base64.b64decode(data["iv"]),base64.b64decode(data["ct"]),base64.b64decode(data["hmac"]))
        plaintext=verify_and_decrypt(keys.enc,keys.mac,keys.session_id,role,env,self.recv_counter); self.recv_counter=env.counter
        ver=time.perf_counter(); v=await self.http.post(f"/api/messages/{message_id}/verification",json={"status":"verified"},headers=self._headers()); v.raise_for_status()
        return plaintext,len(response.content),(time.perf_counter()-ver)*1000

    async def send_baseline(self, session_id: str, kind: str, payload: dict):
        body = json.dumps({"session_id": session_id, "kind": kind, **payload}, separators=(",", ":")).encode()
        response = await self.http.post("/api/baseline/messages", content=body,
            headers={**self._headers(), "Content-Type":"application/json"})
        return response, len(body)

    async def receive_baseline(self, message_id: int):
        response = await self.http.get(f"/api/baseline/messages/{message_id}", headers=self._headers())
        response.raise_for_status()
        return response.json(), len(response.content)

    async def close(self):
        if self.ws:
            await self.ws.close()
            if self.reader: await asyncio.gather(self.reader, return_exceptions=True)
            self.ws=None

    async def logout(self):
        if self.token:
            try: await self.http.post("/api/auth/logout",headers=self._headers())
            except Exception: pass
        await self.close(); await self.http.aclose()
