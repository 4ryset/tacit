import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const app = readFileSync(join(root, 'dapp/front/main.js'), 'utf8');

assert.match(
  app,
  /const worth = id \? dashWorth\(items\) : null, tot = \$\('#hold-tot'\), delta = \{\};/,
  'a connected public wallet must receive a portfolio total even without an unlocked Tacit key',
);
assert.doesNotMatch(
  app,
  /const worth = k \? dashWorth\(items\) : null/,
  'the total must not be restricted to private-key sessions',
);

console.log('portfolio total gate: public-wallet aggregate enabled');
