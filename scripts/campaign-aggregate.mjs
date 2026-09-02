const FORBIDDEN_KEYS = new Set([
  'visitorId',
  'fingerprintTag',
  'sessionId',
  'sessionTag',
  'nonce',
  'signature',
  'components',
  'componentValues',
]);

export function plateauReached(signatures, windowSize = 3) {
  if (signatures.length < windowSize) return false;
  const window = signatures.slice(-windowSize);
  return window.every((signature) => signature === window[0]);
}

export function assertAggregateOnly(value, path = 'result') {
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertAggregateOnly(item, `${path}[${index}]`));
    return;
  }
  if (!value || typeof value !== 'object') return;
  for (const [key, child] of Object.entries(value)) {
    if (FORBIDDEN_KEYS.has(key)) throw new Error(`identifier-bearing field exported at ${path}.${key}`);
    assertAggregateOnly(child, `${path}.${key}`);
  }
}
