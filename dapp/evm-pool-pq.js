// Post-quantum notes in the Ethereum pools, the same as tacit.wei's (its dapp/page.html, "post-quantum notes"; vectors in tests/vectors/pq-memo.json):
// a note whose memo cannot be opened, nor its keys, nullifier or owner worked out, by a recorder who later solves secp256k1, without also breaking
// ML-KEM-768 or knowing the root. The root is the PQ ID's 32 bytes (tacit-chain-root.js keeps it, tacit-chain-phrase.js writes it as 24 words; tacit.wei
// takes the same words). From it, with h(tag, x) = HMAC-SHA256(root, tag ‖ x):
//   ML-KEM-768 key pair   keygen(h("tacit-evm-pool-kem-v1", 0x00) ‖ h("tacit-evm-pool-kem-v1", 0x01))
//   self                  h("tacit-evm-pool-self-v1")              the self form's key (a note to oneself, 65 bytes, shaped as a classical memo)
//   ent                   h("tacit-evm-pool-kem-rand-v1")          the encapsulation randomness key (m = HMAC(ent, "tacit-evm-pool-kem-m-v1" ‖ pk_eph))
//   eph                   h("tacit-evm-pool-eph-pq-v1")            a spend's one-time keys, in place of the view key's
//   box                   h("tacit-evm-pool-receive-key-pq-v1")    deposit and refund boxes
//   tornado               h("tacit-wei-tornado-v1")                tacit.wei's whole notes
// An address names the ML-KEM key by kemHash(ek) = SHA-256("tacit-evm-pool-kem-v1" ‖ ek). The memo forms are in evm-pool-wallet.js (selfS, hybridS).
// Loaded only where a root is: the wallet module itself needs only hashing to read these memos, and takes this key set as `keys.pq`.

import { sha256, hmac, concatBytes } from './vendor/tacit-deps.min.js';
import { ml_kem768 } from './vendor/tacit-pq.min.js';

export const PQ_MEMO = 1153, KEM_CT = 1088, KEM_EK = 1184;
const te = new TextEncoder();
export const kemHash = (ek) => sha256(concatBytes(te.encode('tacit-evm-pool-kem-v1'), ek));

// Encapsulates to `ek` (1,184 bytes) with the 32-byte `m`: { ct (1,088), ss (32) }. noble checks the key (FIPS 203's modulus check).
export function encaps(ek, m) {
  if (!(ek instanceof Uint8Array) || ek.length !== KEM_EK) throw new Error('evm-pool-pq: an ML-KEM-768 key is 1184 bytes');
  const r = ml_kem768.encapsulate(ek, m);
  return { ct: r.cipherText, ss: r.sharedSecret };
}

// The key set a wallet takes as keys.pq.
export function pqKeys(root) {
  if (!(root instanceof Uint8Array) || root.length !== 32) throw new Error('evm-pool-pq: a root is 32 bytes');
  const h = (tag, x = new Uint8Array()) => hmac(sha256, root, concatBytes(te.encode(tag), x));
  const { publicKey: ek, secretKey: dk } = ml_kem768.keygen(concatBytes(h('tacit-evm-pool-kem-v1', Uint8Array.of(0)), h('tacit-evm-pool-kem-v1', Uint8Array.of(1))));
  return {
    ek, hash: kemHash(ek), self: h('tacit-evm-pool-self-v1'), ent: h('tacit-evm-pool-kem-rand-v1'), eph: h('tacit-evm-pool-eph-pq-v1'),
    box: h('tacit-evm-pool-receive-key-pq-v1'), tornado: h('tacit-wei-tornado-v1'),
    decaps: (ct) => ml_kem768.decapsulate(ct, dk), encaps,
  };
}
