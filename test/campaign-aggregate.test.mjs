import assert from 'node:assert/strict';
import test from 'node:test';

import { assertAggregateOnly, plateauReached } from '../scripts/campaign-aggregate.mjs';

test('plateau requires three identical trailing aggregate signatures', () => {
  assert.equal(plateauReached(['a', 'a']), false);
  assert.equal(plateauReached(['a', 'b', 'b', 'b']), true);
  assert.equal(plateauReached(['a', 'b', 'b', 'c']), false);
});

test('aggregate evidence rejects identifier-bearing fields at any depth', () => {
  assert.doesNotThrow(() => assertAggregateOnly({ conditions: [{ runs: 3, stableFingerprint: true }] }));
  assert.throws(
    () => assertAggregateOnly({ conditions: [{ fingerprintTag: 'redacted-but-still-forbidden' }] }),
    /identifier-bearing field/,
  );
});
