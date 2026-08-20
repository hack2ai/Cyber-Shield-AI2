const baseUrl = process.env.BASE_URL || 'http://127.0.0.1:4173';

async function request(body) {
  const response = await fetch(`${baseUrl}/api/analyze`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const payload = await response.json().catch(() => ({}));
  return { response, payload };
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

const missing = await request({});
assert(missing.response.status === 400, `Expected missing target to return 400, got ${missing.response.status}`);
assert(missing.payload.error === 'Target is required.', 'Unexpected missing-target error');

const oversized = await request({ url: 'a'.repeat(2049) });
assert(oversized.response.status === 413, `Expected oversized target to return 413, got ${oversized.response.status}`);

const localhost = await request({ url: 'http://localhost:3000' });
assert(localhost.response.status === 400, `Expected localhost to return 400, got ${localhost.response.status}`);
assert(/Local hostnames/i.test(localhost.payload.error || ''), 'Unexpected localhost rejection');

const privateV4 = await request({ url: '10.0.0.1' });
assert(privateV4.response.status === 400, `Expected private IPv4 to return 400, got ${privateV4.response.status}`);
assert(/Private or reserved IP/i.test(privateV4.payload.error || ''), 'Unexpected private IPv4 rejection');

const privateV6 = await request({ url: 'fd00::1' });
assert(privateV6.response.status === 400, `Expected private IPv6 to return 400, got ${privateV6.response.status}`);
assert(/Private or reserved IP/i.test(privateV6.payload.error || ''), 'Unexpected private IPv6 rejection');

// Five validation requests above already consumed five rate-limit slots.
// Send 24 more invalid requests so the next request is exactly #30.
for (let i = 0; i < 24; i += 1) {
  const result = await request({});
  assert(result.response.status === 400, `Expected validation response during rate-limit warmup, got ${result.response.status}`);
}

const thirtieth = await request({});
assert(thirtieth.response.status === 400, `Expected 30th request to remain allowed, got ${thirtieth.response.status}`);

const rateLimited = await request({});
assert(rateLimited.response.status === 429, `Expected 31st request to be rate limited, got ${rateLimited.response.status}`);
assert(/Rate limit exceeded/i.test(rateLimited.payload.error || ''), 'Unexpected rate-limit error');

console.log('API analyze smoke tests passed');
