// Post-quantum notes in the Ethereum pools (dapp/evm-pool-pq.js, and the self and hybrid memo forms in dapp/evm-pool-wallet.js) are tacit.wei's: the keys
// from a root are what its page derives, the memos it makes are byte for byte what this module makes (tests/vectors/pq-memo.json is tacit.wei's own file,
// test/dapp/vectors/pq-memo.json there), and this wallet opens both forms for their owner and no one else, while a classical memo still opens as before.
//   node tests/evm-pool-pq.test.mjs
import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import { createHash, createHmac } from 'node:crypto';
import { poseidon2, poseidon3, poseidon4, poseidon5, poseidon7 } from 'poseidon-lite';
import { makeEvmPoolZk } from '../dapp/evm-pool-zk.js';
import { evmPoolKeys, sealNote, sealSelf, sealHybrid, openNote, openNotes, PQ_MEMO, MEMO_LEN, pqTag } from '../dapp/evm-pool-wallet.js';
import { pqKeys, encaps, kemHash, KEM_EK } from '../dapp/evm-pool-pq.js';
import { ml_kem768 } from '../dapp/vendor/tacit-pq.min.js';
import { rootToPhrase, phraseToRoot } from '../dapp/tacit-chain-phrase.js';

const P = { 2: poseidon2, 3: poseidon3, 4: poseidon4, 5: poseidon5, 7: poseidon7 };
const zk = makeEvmPoolZk({ poseidon: (xs) => P[xs.length](xs) });
let pass = 0, fail = 0;
const check = (label, fn) => { try { fn(); console.log(`  PASS  ${label}`); pass++; } catch (e) { console.log(`  FAIL  ${label}: ${e.message}`); fail++; } };
const sha = (...b) => new Uint8Array(createHash('sha256').update(Buffer.concat(b.map((x) => Buffer.from(x)))).digest());
const hm = (k, ...b) => new Uint8Array(createHmac('sha256', Buffer.from(k)).update(Buffer.concat(b.map((x) => Buffer.from(x)))).digest());
const u8 = (s) => new TextEncoder().encode(s), hex = (b) => Buffer.from(b).toString('hex');
const seeded = (tag) => sha(u8('pq-memo test ' + tag));
const asset = 12345678901234567890n;
const V = JSON.parse(readFileSync(new URL('./vectors/pq-memo.json', import.meta.url), 'utf8'));

const person = (tag, rooted = true) => { const k = evmPoolKeys(zk, seeded(tag + ' key')); if (rooted) k.pq = pqKeys(seeded(tag + ' root')); return k; };
const A = person('alice'), B = person('bob'), C = person('carol', false);
const same = (o, n) => !!o && o.v === n.v && BigInt(n.leaf) === zk.leafOf(asset, o.v, o.npk, o.rho);

console.log('keys from the root, as tacit.wei derives them');
check('the ML-KEM-768 key pair is noble keygen(HMAC(root, "tacit-evm-pool-kem-v1" ‖ 0) ‖ HMAC(root, … ‖ 1))', () => {
  const r = seeded('alice root'), d = hm(r, u8('tacit-evm-pool-kem-v1'), [0]), z = hm(r, u8('tacit-evm-pool-kem-v1'), [1]);
  assert.equal(hex(A.pq.ek), hex(ml_kem768.keygen(new Uint8Array([...d, ...z])).publicKey));
  assert.equal(A.pq.ek.length, KEM_EK);
});
check('self, ent, eph, box and tornado are HMAC(root, their tag); the address names the key by SHA-256("tacit-evm-pool-kem-v1" ‖ ek)', () => {
  const r = seeded('alice root');
  for (const [k, tag] of [['self', 'tacit-evm-pool-self-v1'], ['ent', 'tacit-evm-pool-kem-rand-v1'], ['eph', 'tacit-evm-pool-eph-pq-v1'], ['box', 'tacit-evm-pool-receive-key-pq-v1'], ['tornado', 'tacit-wei-tornado-v1']]) assert.equal(hex(A.pq[k]), hex(hm(r, u8(tag))), k);
  assert.equal(hex(A.pq.hash), hex(sha(u8('tacit-evm-pool-kem-v1'), A.pq.ek)));
  assert.equal(hex(kemHash(A.pq.ek)), hex(A.pq.hash));
});
check('the root is the PQ ID\'s: its 24 words give it back', () => {
  const r = seeded('alice root'), words = rootToPhrase(r);
  assert.equal(words.split(' ').length, 24);
  assert.equal(hex(phraseToRoot(words)), hex(r));
});

console.log('tacit.wei\'s fixed vectors');
check('the self form and the hybrid form are byte for byte tacit.wei\'s, and so are their leaves and the key', () => {
  const keys = evmPoolKeys(zk, seeded('vector key')), e = 0xabcdefn;
  keys.pq = pqKeys(seeded('vector root'));
  const self = sealSelf(zk, { keys, value: 123456789n, asset, e });
  const hy = sealHybrid(zk, { to: keys, ek: keys.pq.ek, value: 987654321n, asset, e: e + 1n, ent: keys.pq.ent, encaps });
  assert.equal(hex(sha(self.memo)), V.self); assert.equal(String(self.leaf), V.selfLeaf);
  assert.equal(hex(sha(hy.memo)), V.hybrid); assert.equal(String(hy.leaf), V.hybridLeaf);
  assert.equal(hex(sha(keys.pq.ek)), V.ek);
  assert.ok(same(openNote(zk, keys, { memo: self.memo, leaf: self.leaf, asset }), self) && same(openNote(zk, keys, { memo: hy.memo, leaf: hy.leaf, asset }), hy), 'and this wallet opens both');
});

console.log('who opens what');
check('a classical memo opens for its owner with or without a root, and for no one else', () => {
  const n = sealNote(zk, { to: B, value: 7n, asset });
  assert.equal(n.memo.length, MEMO_LEN);
  assert.ok(same(openNote(zk, B, { memo: n.memo, leaf: n.leaf, asset }), n));
  assert.ok(same(openNote(zk, { ...B, pq: undefined }, { memo: n.memo, leaf: n.leaf, asset }), n));
  assert.equal(openNote(zk, A, { memo: n.memo, leaf: n.leaf, asset }), null);
});
check('the self form opens only with its root: not for the same key without it, not for anyone else', () => {
  const n = sealSelf(zk, { keys: A, value: 10n ** 17n, asset });
  assert.equal(n.memo.length, MEMO_LEN);
  assert.ok(same(openNote(zk, A, { memo: n.memo, leaf: n.leaf, asset }), n));
  assert.equal(openNote(zk, { ...A, pq: undefined }, { memo: n.memo, leaf: n.leaf, asset }), null);
  assert.equal(openNote(zk, B, { memo: n.memo, leaf: n.leaf, asset }), null);
});
check('a hybrid memo to Bob opens for Bob with his root (sent by Alice, or by Carol, who has none), not without it, not for Alice', () => {
  for (const ent of [A.pq.ent, null]) {
    const n = sealHybrid(zk, { to: B, ek: B.pq.ek, value: 5n * 10n ** 16n, asset, ent, encaps });
    assert.equal(n.memo.length, PQ_MEMO);
    const o = openNote(zk, B, { memo: n.memo, leaf: n.leaf, asset });
    assert.ok(same(o, n));
    assert.equal(o.s.length, 33, 'the note\'s secret is 33 bytes, as every note key derivation takes');
    assert.equal(openNote(zk, { ...B, pq: undefined }, { memo: n.memo, leaf: n.leaf, asset }), null);
    assert.equal(openNote(zk, A, { memo: n.memo, leaf: n.leaf, asset }), null);
  }
});
check('a memo whose leaf is not its note\'s is not taken, in any form', () => {
  const s = sealSelf(zk, { keys: A, value: 9n, asset }), h = sealHybrid(zk, { to: A, ek: A.pq.ek, value: 9n, asset, encaps });
  assert.equal(openNote(zk, A, { memo: s.memo, leaf: s.leaf + 1n, asset }), null);
  assert.equal(openNote(zk, A, { memo: h.memo, leaf: h.leaf + 1n, asset }), null);
  const bent = h.memo.slice(); bent[10] ^= 1;
  assert.equal(openNote(zk, A, { memo: bent, leaf: h.leaf, asset }), null, 'a changed ciphertext opens nothing');
});
check('the batch read opens a mix of all three forms and leaves the others\' alone', () => {
  const ns = [sealNote(zk, { to: A, value: 1n, asset }), sealSelf(zk, { keys: A, value: 2n, asset }), sealHybrid(zk, { to: A, ek: A.pq.ek, value: 3n, asset, encaps }),
    sealNote(zk, { to: B, value: 4n, asset }), sealHybrid(zk, { to: B, ek: B.pq.ek, value: 5n, asset, encaps }), sealSelf(zk, { keys: B, value: 6n, asset })];
  const items = [...ns.map((n) => ({ memo: n.memo, leaf: n.leaf, asset })), { memo: new Uint8Array(40), leaf: 1n, asset }, { memo: new Uint8Array(PQ_MEMO), leaf: 1n, asset }];
  const got = openNotes(zk, A, items).map((o) => (o ? o.v : null));
  assert.deepEqual(got, [1n, 2n, 3n, null, null, null, null, null]);
  assert.deepEqual(openNotes(zk, { ...A, pq: undefined }, items).map((o) => (o ? o.v : null)), [1n, null, null, null, null, null, null, null], 'without the root only the classical one');
  assert.deepEqual(openNotes(zk, C, items).map((o) => (o ? o.v : null)), Array(8).fill(null));
});
check('a wallet with a root keeps its state apart, under its key\'s hash; one without keeps the name it had', () => {
  assert.equal(pqTag(C), '');
  assert.match(pqTag(A), /^:pq[0-9a-f]{16}$/);
  assert.notEqual(pqTag(A), pqTag(B));
});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
