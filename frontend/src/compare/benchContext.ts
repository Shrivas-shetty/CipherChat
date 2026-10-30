import { bigintTo256Bytes } from "../crypto/encoding";
import { deriveSessionKeys } from "../crypto/kdf";
import { generatePrivate, publicFromPrivate, sharedSecret, type PrivateKey } from "../crypto/dh";
import { generateSigningKeyPair } from "../signing/keygen";
import { formatFingerprint } from "../signing/signature";
import { ReplayGuard } from "../crypto/replayGuard";
import type { SetupTimings } from "./types";

export type BenchmarkContext = {
  kEnc: Uint8Array;
  kMac: Uint8Array;
  sessionId: string;
  privateKey: Uint8Array;
  publicKeyBytes: Uint8Array;
  publicKeyB64: string;
  fingerprint: string;
  setupTimings: SetupTimings;
  replayGuard: ReplayGuard;
  nextCounter: () => number;
  dispose: () => void;
};

type SetupDeps = {
  now?: () => number;
  randomValues?: <T extends ArrayBufferView>(array: T) => T;
  dhGeneratePrivate?: typeof generatePrivate;
  dhPublicFromPrivate?: typeof publicFromPrivate;
  dhSharedSecret?: typeof sharedSecret;
  deriveKeys?: typeof deriveSessionKeys;
  signingKeygen?: typeof generateSigningKeyPair;
};

const positiveDuration = (start: number, end: number) => Math.max(0.001, end - start);

function uuidV4(randomValues: NonNullable<SetupDeps["randomValues"]>): string {
  const bytes = new Uint8Array(16);
  randomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

export async function setupBenchmark(deps: SetupDeps = {}): Promise<BenchmarkContext> {
  const now = deps.now ?? (() => performance.now());
  const randomValues = deps.randomValues ?? ((array) => crypto.getRandomValues(array));
  const makePrivate = deps.dhGeneratePrivate ?? generatePrivate;
  const makePublic = deps.dhPublicFromPrivate ?? publicFromPrivate;
  const makeShared = deps.dhSharedSecret ?? sharedSecret;
  const derive = deps.deriveKeys ?? deriveSessionKeys;
  const makeSigningPair = deps.signingKeygen ?? generateSigningKeyPair;

  let partyA: PrivateKey | null = null;
  let partyB: PrivateKey | null = null;
  let secretA: Uint8Array | null = null;
  let secretB: Uint8Array | null = null;
  let derivedA: ReturnType<typeof deriveSessionKeys> | null = null;
  let derivedB: ReturnType<typeof deriveSessionKeys> | null = null;
  let signing: Awaited<ReturnType<typeof generateSigningKeyPair>> | null = null;
  let copiedEnc: Uint8Array | null = null;
  let copiedMac: Uint8Array | null = null;
  let transferred = false;

  try {
    const sessionId = uuidV4(randomValues);
    const dhStart = now();
    partyA = makePrivate();
    partyB = makePrivate();
    const publicA = makePublic(partyA.x);
    const publicB = makePublic(partyB.x);
    secretA = makeShared(publicB, partyA.x);
    secretB = makeShared(publicA, partyB.x);
    const dhEnd = now();

    const hkdfStart = now();
    const publicABytes = bigintTo256Bytes(publicA);
    const publicBBytes = bigintTo256Bytes(publicB);
    derivedA = derive(secretA, sessionId, publicABytes, publicBBytes);
    derivedB = derive(secretB, sessionId, publicABytes, publicBBytes);
    const hkdfEnd = now();
    if (!sameBytes(derivedA.kEnc, derivedB.kEnc) || !sameBytes(derivedA.kMac, derivedB.kMac) ||
        !sameBytes(derivedA.fingerprintBytes, derivedB.fingerprintBytes)) {
      throw new Error("Benchmark key derivation mismatch");
    }
    copiedEnc = new Uint8Array(derivedA.kEnc);
    copiedMac = new Uint8Array(derivedA.kMac);

    const signingStart = now();
    signing = await makeSigningPair();
    const signingEnd = now();
    const publicKeyBytes = new Uint8Array(signing.publicKeyBytes);
    const context: BenchmarkContext = {
      kEnc: copiedEnc,
      kMac: copiedMac,
      sessionId,
      privateKey: signing.privateKey,
      publicKeyBytes,
      publicKeyB64: signing.publicKeyB64,
      fingerprint: formatFingerprint(signing.fingerprint),
      setupTimings: {
        setup_keygen_ms: positiveDuration(signingStart, signingEnd),
        setup_dh_ms: positiveDuration(dhStart, dhEnd),
        setup_hkdf_ms: positiveDuration(hkdfStart, hkdfEnd),
      },
      replayGuard: new ReplayGuard(),
      nextCounter: (() => { let counter = 0; return () => ++counter; })(),
      dispose: () => {
        context.kEnc.fill(0);
        context.kMac.fill(0);
        context.privateKey.fill(0);
        context.publicKeyBytes.fill(0);
        context.kEnc = new Uint8Array();
        context.kMac = new Uint8Array();
        context.privateKey = new Uint8Array();
        context.publicKeyBytes = new Uint8Array();
        context.replayGuard.reset();
      },
    };
    transferred = true;
    return context;
  } finally {
    partyA?.bytes.fill(0);
    partyB?.bytes.fill(0);
    secretA?.fill(0);
    secretB?.fill(0);
    derivedA?.kEnc.fill(0); derivedA?.kMac.fill(0); derivedA?.fingerprintBytes.fill(0);
    derivedB?.kEnc.fill(0); derivedB?.kMac.fill(0); derivedB?.fingerprintBytes.fill(0);
    if (signing) signing.publicKeyBytes.fill(0);
    if (!transferred) {
      copiedEnc?.fill(0); copiedMac?.fill(0);
      signing?.privateKey.fill(0);
    }
  }
}
