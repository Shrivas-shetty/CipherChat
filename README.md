# CipherChat (Phase 3)

Secure two-user chat over a LAN featuring in-browser Diffie-Hellman key exchange, HKDF key derivation, mutual key confirmation, session lifecycle management, and a blind server relay architecture.

> [!WARNING]
> **Known Limitation (Educational LAN Analysis):**
> Wire traffic is plain HTTP/WS, and chat message relay is still plaintext in Phase 3 (marked `TEMP`). End-to-end message encryption with AES-GCM/CBC and HMAC verification will be added in Phase 4. However, Diffie-Hellman keys, shared secrets, and HKDF session keys are already derived purely in-browser and NEVER touch the server.

---

## Core Principle: Blind Server Relay

The server operates strictly as a **blind relay** for the key exchange:
- **Relay Only:** Relays `session_start`, `dh_public`, and `key_confirm` frames between participants.
- **Validation:** Verifies parameter formats and checks that public values fall within the safe prime subgroup range ($2 \le y \le P - 2$).
- **Zero Knowledge:** The server never computes, inspects, receives, or stores any private exponent ($x$), shared secret ($Z$), or derived key ($K_{enc}, K_{mac}$).
- **Enforcement:** Enforced in code and guaranteed by automated source grep tests in `backend/app/tests/test_session_lifecycle.py`.

---

## Cryptographic Specification

| Component | Specification |
| :--- | :--- |
| **DH Group** | RFC 3526 Group 14 (2048-bit MODP safe prime), generator $g = 2$ |
| **Private Exponent** | 32 random bytes from CSPRNG (`crypto.getRandomValues` / `secrets.token_bytes`), top bit forced to 1 ($x \ge 2^{255}$) |
| **Public Wire Format** | 512 lowercase hex characters (fixed 256-byte big-endian encoding, zero-padded) |
| **Public Key Validation** | $2 \le y \le P - 2$; non-hex or wrong-length inputs rejected with `bad_public` |
| **Shared Secret** | $Z = \text{peer\_y}^x \pmod P$, encoded as 256-byte big-endian |
| **HKDF** | RFC 5869 HKDF-SHA256 |
| **HKDF Salt** | $\text{SHA-256}(\text{"CC1-salt"} \parallel \text{session\_id} \parallel \text{pub\_initiator} \parallel \text{pub\_responder})$ |
| **Derived Keys** | $K_{enc}$ (32B with `"CipherChat v1 enc"`), $K_{mac}$ (32B with `"CipherChat v1 mac"`), Fingerprint (8B with `"CipherChat v1 fingerprint"`) |
| **Fingerprint Format** | 4 groups of 4 uppercase hex characters separated by spaces (e.g. `60B3 9698 05E7 205C`) |
| **Confirmation Tag** | $\text{HMAC-SHA256}(K_{mac}, \text{"CC1-confirm"} \parallel \text{session\_id} \parallel \text{role\_char})$, verified in constant time |
| **Key Memory Safety** | Ephemeral in-memory store; byte arrays wiped with zeros (`fill(0)`) on session termination/logout/unmount |

---

## Architecture Overview

```
CipherChat/
├── backend/                  FastAPI + WebSocket server (SQLAlchemy 2.0 + SQLite)
│   ├── app/
│   │   ├── config.py         Config, DB_PATH, JWT settings, lockout policy
│   │   ├── deps.py           Auth dependencies (get_current_user, require_role)
│   │   ├── main.py           FastAPI app, lifespan DB init, server restart cleanup, SPA serving
│   │   ├── crypto/           Server-side reference crypto & verification
│   │   │   ├── params.py     RFC 3526 Group 14 prime P, generator G, and protocol constants
│   │   │   ├── dh.py         Public key validation & DH reference operations
│   │   │   └── kdf.py        HKDF-SHA256 key derivation & confirmation tag reference
│   │   ├── db/
│   │   │   ├── base.py       SQLAlchemy engine, WAL PRAGMA, SessionLocal, init_db
│   │   │   └── models.py     User, AuthSession, AuditLog, ChatSession models
│   │   ├── routers/
│   │   │   ├── auth.py       /api/auth (register, login, logout, me)
│   │   │   ├── health.py     /api/health
│   │   │   └── ws.py         /ws (authenticated WebSocket endpoint with handshake relay)
│   │   ├── scripts/          CLI utilities (seed_analyst, show_audit, verify_audit, make_test_vectors)
│   │   ├── services/         Audit logging with SHA-256 tamper-evident hash chaining
│   │   ├── tests/            Pytest auth, crypto, and session lifecycle test suites
│   │   └── ws/
│   │       ├── manager.py    Active ConnectionManager
│   │       └── session_coordinator.py Handshake state machine & 15s timeout watcher
│   └── data/                 SQLite database (app.db) and generated jwt_secret
├── frontend/                 Vite + React 19 + TypeScript SPA
│   └── src/
│       ├── api/              HTTP client (http.ts) with Bearer token & 401 handler
│       ├── auth/             AuthContext & sessionStorage manager
│       ├── components/       ServerAddressInput
│       ├── crypto/           In-browser cryptographic implementation
│       │   ├── params.ts     RFC 3526 Group 14 constants & byte lengths
│       │   ├── encoding.ts   Strict hex/byte/bigint conversions
│       │   ├── modpow.ts     Square-and-multiply BigInt modular exponentiation
│       │   ├── dh.ts         Browser DH key generation & shared secret computation
│       │   ├── kdf.ts        HKDF derivation, fingerprinting, confirmation tags
│       │   ├── sessionKeys.ts Ephemeral in-memory key storage with zeroing
│       │   ├── handshake.ts  HandshakeRunner client-side state machine
│       │   └── __tests__/    Vitest test suite verifying against shared vectors
│       ├── pages/            AuthPage, ChatPage, AnalystPage
│       └── ws/               ChatSocket (v1 protocol with DH frame types)
└── shared/
    └── test_vectors/
        └── dh_hkdf.json      Deterministic cross-language DH & HKDF test vectors
```

---

## Running the Application

### 1. Backend Setup

From `backend/`:

**Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

**macOS / Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### 2. Frontend Setup

From `frontend/`:

```powershell
npm install
npm run dev
```

To build production assets served directly by FastAPI:
```powershell
npm run build
```

---

## Running Automated Tests

### Backend Tests (pytest)
Runs auth, crypto DH/KDF, and session lifecycle tests (including blind-relay source grep and 15s timeout watcher):
```powershell
python -m pytest backend/app/tests -v
```

### Frontend Tests (vitest)
Runs in-browser cryptographic unit tests verifying compliance with `shared/test_vectors/dh_hkdf.json`:
```powershell
cd frontend
npm test
```

---

## Acceptance Tests (Phase 3)

1. **In-Browser Key Generation & Relay:** Two users log in and connect. Both browser consoles demonstrate BigInt modular exponentiation and send `dh_public`. The server relays the 512-hex public keys blindly.
2. **Key Confirmation & Fingerprint Matching:** Both browsers verify each other's confirmation tags. Once both send `key_verified`, both receive `session_established` with identical fingerprints (e.g. `60B3 9698 05E7 205C`).
3. **Session Info & Demo Panel:** Clicking "Key details (demo only)" reveals the session ID, role, keygen latency, and key derivation latency.
4. **Chat Session Gating:** Chat messages cannot be sent while in `waiting` or `negotiating` states; attempting to send returns `NO_SESSION`. Chat is enabled once established.
5. **Rejection of Malformed/Out-of-Range Public Keys:** Sending $y < 2$ or $y > P-2$ causes the server to abort the handshake, log `KEY_EXCHANGE_FAILED`, and terminate the session with `bad_public`.
6. **Handshake Timeout:** If either client fails to complete the handshake within 15 seconds, the server terminates with `handshake_timeout`.
7. **Clean Session Termination & Ordering:** When one user disconnects or logs out, the peer receives `session_terminated`, then `peer_left`, and then `status: waiting`.
8. **Memory Hygiene:** Derived session keys are wiped with zeros (`clearSessionKeys()`) on logout, session termination, or unmount.
9. **Cross-Language Test Vector Consistency:** Both Python pytest and TypeScript Vitest pass all test vector assertions against `shared/test_vectors/dh_hkdf.json`.
