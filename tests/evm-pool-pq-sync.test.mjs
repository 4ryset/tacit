// A wallet with a post-quantum root (keys.pq) finds, on a pool with a real tree, the notes tacit.wei seals against a quantum computer (a hybrid memo
// paid to it, a self-form note of its own) beside a classical one, and can spend them: the proof's input is built from the note's keys. Without the
// root the same wallet sees only the classical note, and its saved state is kept under another name.
//   node tests/evm-pool-pq-sync.test.mjs
import assert from 'node:assert/strict';
import { makeEvmPoolWallet, evmPoolKeys, sealNote, sealSelf, sealHybrid, pqTag } from '../dapp/evm-pool-wallet.js';
import { makeEvmPoolZk, poolAsset, publicSignals } from '../dapp/evm-pool-zk.js';
import { pqKeys, encaps } from '../dapp/evm-pool-pq.js';
import { poseidon2, poseidon3, poseidon4, poseidon5, poseidon7 } from 'poseidon-lite';
import { keccak_256 } from '@noble/hashes/sha3';

let n = 0;
const check = async (name, fn) => { await fn(); n++; console.log(`ok - ${name}`); };
const P = { 2: poseidon2, 3: poseidon3, 4: poseidon4, 5: poseidon5, 7: poseidon7 };
const zk = makeEvmPoolZk({ poseidon: (xs) => P[xs.length](xs) });
const POOL = '0x000000c2A20657CE25f2Ba99737933D031AFBEE9', ROUTER = '0x0000006C96Afa6f1cD4DF8FE19bc0d8B6A6Cd7B5';
const topic = (sig) => '0x' + Buffer.from(keccak_256(new TextEncoder().encode(sig))).toString('hex');
const T_TRANSACT = topic('Transact(bytes32,bytes32,bytes32,bytes32,uint256,bytes32,address,int256,address,uint256,bytes,bytes)');
const w64 = (x) => BigInt.asUintN(256, BigInt(x)).toString(16).padStart(64, '0');
const asset = poolAsset({ chainId: 1n, pool: POOL, token: '0x0000000000000000000000000000000000000000' });
const E = 10n ** 16n;

// A pool whose tree is real: each transaction is one block, its leaves go into the tree and its Transact into the logs.
function fakePool() {
  const tree = zk.incTree(), sizeOf = new Map([[tree.root, 0]]), logs = [];
  let block = 0;
  return {
    get tip() { return block; }, get root() { return tree.root; }, get size() { return tree.size; },
    transact({ out, memo = [null, null] }) {
      block++;
      const firstIndex = tree.size, [o0, o1] = out, tx = '0x' + w64(block);
      tree.append(out.map(BigInt)); sizeOf.set(tree.root, tree.size);
      const m = memo.map((x) => Buffer.from(x ?? []).toString('hex')), pad = (h) => h + '0'.repeat((64 - (h.length % 64)) % 64);
      const body0 = w64(m[0].length / 2) + pad(m[0]);
      logs.push({ address: POOL, blockNumber: '0x' + block.toString(16), transactionHash: tx, logIndex: '0x0', topics: [T_TRANSACT, '0x' + w64(0), '0x' + w64(0)],
        data: '0x' + [o0, o1, firstIndex, 0, 0, 0, 0, 0, 320, 320 + body0.length / 2].map(w64).join('') + body0 + w64(m[1].length / 2) + pad(m[1]) });
      return tx;
    },
    node: async (m, p) => {
      if (m === 'eth_blockNumber') return '0x' + block.toString(16);
      if (m === 'eth_getLogs') {
        const f = p[0], at = [f.address].flat().map((a) => a.toLowerCase()), t0 = [f.topics?.[0] ?? []].flat().map((t) => t.toLowerCase());
        return logs.filter((l) => at.includes(l.address.toLowerCase()) && (!t0.length || t0.includes(l.topics[0])) && Number(l.blockNumber) >= Number(f.fromBlock) && Number(l.blockNumber) <= Number(f.toBlock));
      }
      if (m === 'eth_call') return '0x' + w64(sizeOf.get(BigInt('0x' + p[0].data.slice(-64))) ?? 0);
      if (m === 'eth_getTransactionReceipt') { const l = logs.filter((x) => x.transactionHash === p[0]); return l.length ? { status: '0x1', logs: l } : null; }
      return '0x0';
    },
  };
}


const mem = () => { const m = new Map(); return { get: (k) => m.get(k) ?? null, set: (k, v) => m.set(k, v), keys: () => [...m.keys()] }; };
const walletOn = (pool, keys, store = null, prove = null) => makeEvmPoolWallet({ zk, keys, keeper: null, store, feed: false, prove, chain: { chainId: 1, pool: POOL, router: ROUTER, rpc: pool.node, deployBlock: 1, confirmations: 0, logChunk: 50000 } });

const me = evmPoolKeys(zk, new Uint8Array(32).fill(7)); me.pq = pqKeys(new Uint8Array(32).fill(8));
const plain = { ...me, pq: undefined };
const other = evmPoolKeys(zk, new Uint8Array(32).fill(3)); other.pq = pqKeys(new Uint8Array(32).fill(4));
const pool = fakePool();
const classical = sealNote(zk, { to: me, value: 1n * E, asset });
const hybrid = sealHybrid(zk, { to: me, ek: me.pq.ek, value: 2n * E, asset, encaps });            // paid by someone with no root
const self = sealSelf(zk, { keys: me, value: 4n * E, asset });
const theirs = sealHybrid(zk, { to: other, ek: other.pq.ek, value: 8n * E, asset, encaps });
const dummy = sealHybrid(zk, { to: evmPoolKeys(zk, new Uint8Array(32).fill(5)), ek: other.pq.ek, value: 0n, asset, encaps });
pool.transact({ out: [classical.leaf, self.leaf], memo: [classical.memo, self.memo] });
pool.transact({ out: [hybrid.leaf, theirs.leaf], memo: [hybrid.memo, theirs.memo] });
pool.transact({ out: [dummy.leaf, 0n], memo: [dummy.memo, null] });

await check('with the root, the classical, hybrid and self-form notes are all in the balance; another person\'s hybrid note is not', async () => {
  const W = walletOn(pool, me);
  const s = await W.sync();
  assert.equal(s.balance, 7n * E);
  assert.deepEqual(W.notes().map((x) => BigInt(x.v)).sort(), [1n * E, 2n * E, 4n * E]);
});
await check('without the root the same key sees only the classical note', async () => {
  const s = await walletOn(pool, plain).sync();
  assert.equal(s.balance, 1n * E);
});
await check('the state with a root is kept under its own name, the plain one under the name it always had', async () => {
  const store = mem();
  await walletOn(pool, me, store).sync(); await walletOn(pool, plain, store).sync();
  const names = store.keys().filter((k) => k.startsWith('tacit-evm-pool-v1:'));
  assert.ok(names.some((k) => k.endsWith(pqTag(me))) && names.some((k) => k.endsWith(me.address)), names.join(', '));
});
await check('a hybrid-memo note and a self-form note are spent like any other: the proof\'s input carries their keys and paths', async () => {
  let input = null;
  const W = walletOn(pool, me, null, async (i) => { input = i; return { proof: { pi_a: ['1', '2', '1'], pi_b: [['3', '4'], ['5', '6'], ['1', '0']], pi_c: ['7', '8', '1'] }, publicSignals: publicSignals(i) }; });
  W.connect({ address: '0x' + '11'.repeat(20), send: async () => { throw Object.assign(new Error('User rejected the request.'), { code: 4001 }); } });
  await W.sync();
  await W.withdraw({ to: '0x' + '22'.repeat(20), amount: 6n * E, via: 'self' }).catch(() => {});
  assert.ok(input, 'a proof was asked for');
  const spent = input.inV.map(BigInt);
  assert.ok(spent.includes(2n * E) && spent.includes(4n * E), `the two post-quantum notes are the inputs (${spent})`);
  const nk = input.inNk.map(BigInt), owned = W.notes().filter((x) => [2n * E, 4n * E].includes(BigInt(x.v)));
  for (const o of owned) assert.ok(nk.includes(BigInt(o.nk)), 'each input\'s nullifier key is the note\'s own, from its 33-byte secret');
});

console.log(`${n} checks passed`);
