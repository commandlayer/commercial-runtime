import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import crypto from 'node:crypto';

const verbs = ['authorize', 'verify'];

function jsonResponse(res, body, status = 200) {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
}

function requestSchema(verb) {
  return {
    $id: `https://schemas.test/schemas/v1.1.0/commercial/${verb}/requests/${verb}.request.schema.json`,
    type: 'object',
    required: ['x402', 'trace', 'payload'],
    properties: {
      x402: {
        type: 'object',
        required: ['verb', 'version', 'class', 'entry'],
        properties: {
          verb: { const: verb },
          version: { const: '1.1.0' },
          class: { const: 'commercial' },
          entry: { const: `x402://${verb}agent.eth/${verb}/v1.1.0` },
        },
      },
      trace: {
        type: 'object',
        required: ['trace_id'],
        properties: {
          trace_id: { type: 'string', minLength: 1 },
          parent_trace_id: { type: 'string', minLength: 1 },
        },
      },
      payload: { type: 'object' },
    },
  };
}

function receiptSchema(verb) {
  return {
    $id: `https://schemas.test/schemas/v1.1.0/commercial/${verb}/receipts/${verb}.receipt.schema.json`,
    type: 'object',
    required: ['status', 'x402', 'trace', 'metadata'],
    properties: {
      status: { type: 'string' },
      x402: {
        type: 'object',
        required: ['verb', 'version', 'class', 'entry'],
        properties: {
          verb: { const: verb },
          version: { const: '1.1.0' },
          class: { const: 'commercial' },
          entry: { const: `x402://${verb}agent.eth/${verb}/v1.1.0` },
        },
      },
      trace: {
        type: 'object',
        required: ['trace_id', 'started_at', 'completed_at', 'duration_ms', 'provider'],
        properties: {
          trace_id: { type: 'string', minLength: 1 },
          parent_trace_id: { type: 'string', minLength: 1 },
          started_at: { type: 'string', minLength: 1 },
          completed_at: { type: 'string', minLength: 1 },
          duration_ms: { type: 'number' },
          provider: { type: 'string', minLength: 1 },
        },
      },
      metadata: {
        type: 'object',
        required: ['proof', 'receipt_id'],
        properties: {
          receipt_id: { type: ['string', 'null'] },
          proof: {
            type: 'object',
            required: ['alg', 'canonical', 'signer_id', 'hash_sha256', 'signature_b64'],
            properties: {
              alg: { type: 'string' },
              canonical: { type: 'string' },
              signer_id: { type: 'string' },
              hash_sha256: { type: ['string', 'null'] },
              signature_b64: { type: ['string', 'null'] },
            },
          },
        },
      },
    },
  };
}

function createSchemaServer() {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname.startsWith('/schemas/v1.1.0/_shared/')) return jsonResponse(res, {});
    if (url.pathname.startsWith('/schemas/v1.1.0/commercial/_shared/')) return jsonResponse(res, {});

    const requestMatch = url.pathname.match(/^\/schemas\/v1\.1\.0\/commercial\/([^/]+)\/requests\/\1\.request\.schema\.json$/);
    if (requestMatch) return jsonResponse(res, requestSchema(requestMatch[1]));

    const receiptMatch = url.pathname.match(/^\/schemas\/v1\.1\.0\/commercial\/([^/]+)\/receipts\/\1\.receipt\.schema\.json$/);
    if (receiptMatch) return jsonResponse(res, receiptSchema(receiptMatch[1]));

    jsonResponse(res, { error: 'not found', path: url.pathname }, 404);
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
}


let sharedSchemaServer;
let sharedSchemaHost;
let sharedKeyPair;


after(async () => {
  if (sharedSchemaServer) {
    await new Promise((resolve, reject) => sharedSchemaServer.close((err) => (err ? reject(err) : resolve())));
    sharedSchemaServer = undefined;
    sharedSchemaHost = undefined;
    sharedKeyPair = undefined;
  }
});

async function ensureSharedTestInfra() {
  if (!sharedSchemaServer) {
    sharedSchemaServer = await createSchemaServer();
    sharedSchemaHost = `http://127.0.0.1:${sharedSchemaServer.address().port}`;
    sharedKeyPair = crypto.generateKeyPairSync('ed25519');
  }
}

async function createRuntimeServer() {
  await ensureSharedTestInfra();
  const { privateKey, publicKey } = sharedKeyPair;
  const env = {
    ...process.env,
    SERVICE_VERSION: '1.1.0',
    API_VERSION: '1.1.0',
    SCHEMA_VERSION: '1.1.0',
    SCHEMA_HOST: sharedSchemaHost,
    RECEIPT_SIGNING_PRIVATE_KEY_PEM_B64: Buffer.from(privateKey.export({ format: 'pem', type: 'pkcs8' })).toString('base64'),
    RECEIPT_SIGNING_PUBLIC_KEY_PEM_B64: Buffer.from(publicKey.export({ format: 'pem', type: 'spki' })).toString('base64'),
    DEFAULT_DAILY_FREE_CALLS: '1000',
    DEFAULT_RATE_RPS: '1000',
  };

  const previous = new Map();
  for (const [key, value] of Object.entries(env)) {
    previous.set(key, process.env[key]);
    process.env[key] = value;
  }

  const mod = await import(`../src/commercial.server.mjs?test=${Date.now()}-${Math.random()}`);
  const { app } = mod.buildApp();
  const runtimeServer = await new Promise((resolve) => {
    const server = app.listen(0, '127.0.0.1', () => resolve(server));
  });

  const restore = async () => {
    await Promise.all([
      new Promise((resolve, reject) => runtimeServer.close((err) => (err ? reject(err) : resolve()))),
      Promise.resolve(),
    ]);
    for (const [key, value] of previous.entries()) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  };

  return {
    baseUrl: `http://127.0.0.1:${runtimeServer.address().port}`,
    restore,
  };
}

async function postJson(baseUrl, path, body) {
  const response = await fetch(`${baseUrl}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { response, json: await response.json() };
}

test('serves v1.1.0 metadata and commercial routes', { concurrency: false }, async () => {
  const runtime = await createRuntimeServer();
  try {
    const index = await fetch(`${runtime.baseUrl}/`);
    const payload = await index.json();
    assert.equal(payload.version, '1.1.0');
    assert.equal(payload.api_version, '1.1.0');
    for (const verb of ['authorize', 'checkout', 'purchase', 'ship', 'verify']) {
      assert.match(payload.verbs.find((route) => route === `/${verb}/v1.1.0`), /v1\.1\.0$/);
    }
  } finally {
    await runtime.restore();
  }
});

test('accepts browser-friendly input and normalizes to the commercial envelope', { concurrency: false }, async () => {
  const runtime = await createRuntimeServer();
  try {
    const { response, json } = await postJson(runtime.baseUrl, '/authorize/v1.1.0', {
      parent_trace_id: 'parent-top-level',
      input: {
        buyer: '0xBEEF',
        chain_id: 'eip155:84532',
        amount: { value: '0.0001', currency: 'ETH' },
        payment_method: 'demo',
      },
    });
;
    assert.equal(response.status, 200);
    assert.equal(json.status, 'success');
    assert.equal(json.x402.verb, 'authorize');
    assert.equal(json.x402.version, '1.1.0');
    assert.equal(json.x402.class, 'commercial');
    assert.equal(json.x402.entry, 'x402://authorizeagent.eth/authorize/v1.1.0');
    assert.match(json.trace.trace_id, /^trace_/);
    assert.equal(json.trace.parent_trace_id, 'parent-top-level');
    assert.equal(json.result.amount.value, '0.0001');
    assert.equal(json.result.amount.currency, 'ETH');
    assert.ok(json.metadata?.proof?.signature_b64);
  } finally {
    await runtime.restore();
  }
});

test('still accepts full normalized commercial envelopes', { concurrency: false }, async () => {
  const runtime = await createRuntimeServer();
  try {
    const { response, json } = await postJson(runtime.baseUrl, '/authorize/v1.1.0', {
      x402: {
        verb: 'authorize',
        version: '1.1.0',
        class: 'commercial',
        entry: 'x402://authorizeagent.eth/authorize/v1.1.0',
      },
      trace: {
        trace_id: 'trace_explicit',
        parent_trace_id: 'parent_explicit',
      },
      payload: {
        amount: { value: '7.50', currency: 'USD' },
        settlement: { method: 'card', network: 'visa' },
      },
    });

    assert.equal(response.status, 200);
    assert.equal(json.x402.entry, 'x402://authorizeagent.eth/authorize/v1.1.0');
    assert.equal(json.trace.trace_id, 'trace_explicit');
    assert.equal(json.trace.parent_trace_id, 'parent_explicit');
    assert.equal(json.result.amount.value, '7.50');
    assert.equal(json.result.settlement.method, 'card');
  } finally {
    await runtime.restore();
  }
});

test('keeps receipt verification separate from the commercial verify verb route', { concurrency: false }, async () => {
  const runtime = await createRuntimeServer();
  try {
    const verifyVerb = await postJson(runtime.baseUrl, '/verify/v1.1.0', {
      input: { target: 'order_123', parent_trace_id: 'parent-input' },
    });
    assert.equal(verifyVerb.response.status, 200);
    assert.equal(verifyVerb.json.x402.verb, 'verify');
    assert.equal(verifyVerb.json.x402.entry, 'x402://verifyagent.eth/verify/v1.1.0');
    assert.equal(verifyVerb.json.result.target, 'order_123');
    assert.equal(verifyVerb.json.trace.parent_trace_id, 'parent-input');

    const authorize = await postJson(runtime.baseUrl, '/authorize/v1.1.0', {
      input: { amount: { value: '1.00', currency: 'USD' } },
    });
    const receiptCheck = await postJson(runtime.baseUrl, '/verify?schema=1', authorize.json);
    assert.equal(receiptCheck.response.status, 200);
    assert.equal(receiptCheck.json.ok, true);
    assert.equal(receiptCheck.json.checks.signature_valid, true);
    assert.equal(receiptCheck.json.checks.schema_valid, true);
    assert.equal(receiptCheck.json.values.verb, 'authorize');
  } finally {
    await runtime.restore();
  }
});
