export type SigningKeyState = {
  privateKey: Uint8Array;
  publicKeyB64: string;
  fingerprint: string;
  keyId: number;
  keygenMs: number;
};

let current: SigningKeyState | null = null;
export const keyStore = {
  get: () => current,
  set: (value: SigningKeyState) => {
    if (current && current.privateKey !== value.privateKey) current.privateKey.fill(0);
    current = value;
  },
  clear: () => { current?.privateKey.fill(0); current = null; },
};
