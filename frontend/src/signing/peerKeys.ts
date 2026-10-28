import { fetchKey, type PeerKeyResponse } from "./api";
import { base64ToBytes } from "../crypto/base64";
import { parsePublicKeyBytes } from "./signature";

export type CachedPeerKey = PeerKeyResponse & { publicKeyBytes: Uint8Array };
const cache = new Map<number, CachedPeerKey>();
export async function getPeerKey(id: number): Promise<CachedPeerKey> {
  const existing = cache.get(id); if (existing) return existing;
  const raw = await fetchKey(id);
  const key = { ...raw, publicKeyBytes: parsePublicKeyBytes(base64ToBytes(raw.public_key_b64)) };
  cache.set(id, key); return key;
}
export function clearPeerKeys() { cache.clear(); }
