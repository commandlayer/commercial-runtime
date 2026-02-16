import crypto from "crypto";
import { spawn } from "child_process";
import Ajv from "ajv";
import addFormats from "ajv-formats";

const VERBS = ["authorize", "checkout", "purchase", "ship", "verify"];
const PORT = Number(process.env.PORT || 8099);
const BASE = process.env.CONTRACT_CHECK_BASE_URL || `http://127.0.0.1:${PORT}`;
const SCHEMA_HOST = (process.env.SCHEMA_HOST || "https://www.commandlayer.org").replace(/\/+$/, "");
const FETCH_TIMEOUT_MS = 10_000;
const MAX_EXAMPLE_BYTES = 200_000;

function parseArg(name) {
  const i = process.argv.indexOf(name);
  if (i === -1) return null;
  return process.argv[i + 1] || null;
}

function hasFlag(name) {
  return process.argv.includes(name);
}

function pemToB64(pem) {
  return Buffer.from(pem, "utf8").toString("base64");
}

function ensureSigningKeys() {
  if (process.env.RECEIPT_SIGNING_PRIVATE_KEY_PEM_B64 && process.env.RECEIPT_SIGNING_PUBLIC_KEY_PEM_B64) return;
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  process.env.RECEIPT_SIGNING_PRIVATE_KEY_PEM_B64 = pemToB64(
    privateKey.export({ type: "pkcs8", format: "pem" }).toString()
  );
  process.env.RECEIPT_SIGNING_PUBLIC_KEY_PEM_B64 = pemToB64(
    publicKey.export({ type: "spki", format: "pem" }).toString()
  );
}

function maybeSwapSchemaHost(url) {
  if (url.includes("://www.commandlayer.org")) return url.replace("://www.commandlayer.org", "://commandlayer.org");
  if (url.includes("://commandlayer.org")) return url.replace("://commandlayer.org", "://www.commandlayer.org");
  return null;
}

function normalizeFetchUrl(url) {
  return String(url || "").replace(/^http:\/\//i, "https://");
}

function splitRef(ref) {
  const str = String(ref || "");
  const i = str.indexOf("#");
  if (i === -1) return { base: str, fragment: "" };
  return { base: str.slice(0, i), fragment: str.slice(i) };
}

function resolveJsonPointer(doc, fragment) {
  if (!fragment || fragment === "#") return doc;
  if (!fragment.startsWith("#/")) return null;

  const parts = fragment
    .slice(2)
    .split("/")
    .map((s) => s.replace(/~1/g, "/").replace(/~0/g, "~"));

  let cur = doc;
  for (const p of parts) {
    if (cur == null || typeof cur !== "object" || !(p in cur)) return null;
    cur = cur[p];
  }
  return cur;
}

function simplifyErrors(errors) {
  if (!Array.isArray(errors)) return [];
  return errors.slice(0, 20).map((e) => ({
    instancePath: e.instancePath,
    schemaPath: e.schemaPath,
    keyword: e.keyword,
    message: e.message,
  }));
}

function schemaUrl(verb, kind) {
  return `${SCHEMA_HOST}/schemas/v1.0.0/commercial/${verb}/${kind}/${verb}.${kind.slice(0, -1)}.schema.json`;
}

function makeAjv(fetchJson) {
  const ajv = new Ajv({
    allErrors: true,
    strict: false,
    validateSchema: false,
    loadSchema: async (uri) => await fetchJson(uri, `ajv loadSchema ${uri}`),
  });
  addFormats(ajv);
  return ajv;
}

function makeExampleSync(schema, resolveRefSync, depth = 0, seen = new Set(), baseUrl = "") {
  if (!schema || typeof schema !== "object") return null;
  if (depth > 6) return null;

  const keySeed = schema.$id || schema.$ref || `${baseUrl}:${schema.type || "unknown"}:${Object.keys(schema).slice(0, 5).join(",")}`;
  if (seen.has(keySeed)) return null;

  const nextSeen = new Set(seen);
  nextSeen.add(keySeed);

  if (schema.$ref) {
    const refSchema = resolveRefSync(schema.$ref, baseUrl);
    const resolvedBase = new URL(schema.$ref, baseUrl).toString();
    return makeExampleSync(refSchema, resolveRefSync, depth + 1, nextSeen, resolvedBase);
  }

  if (Array.isArray(schema.anyOf) && schema.anyOf.length) {
    return makeExampleSync(schema.anyOf[0], resolveRefSync, depth + 1, nextSeen, baseUrl);
  }
  if (Array.isArray(schema.oneOf) && schema.oneOf.length) {
    return makeExampleSync(schema.oneOf[0], resolveRefSync, depth + 1, nextSeen, baseUrl);
  }

  if (Array.isArray(schema.allOf) && schema.allOf.length) {
    const out = {};
    for (const part of schema.allOf) {
      const ex = makeExampleSync(part, resolveRefSync, depth + 1, nextSeen, baseUrl);
      if (ex && typeof ex === "object" && !Array.isArray(ex)) Object.assign(out, ex);
    }
    return out;
  }

  const t = Array.isArray(schema.type) ? schema.type[0] : schema.type;

  if (t === "object" || schema.properties) {
    const props = schema.properties || {};
    const req = Array.isArray(schema.required) ? schema.required : [];
    if (!req.length) return {};

    const obj = {};
    for (const k of req) {
      obj[k] = props[k] ? makeExampleSync(props[k], resolveRefSync, depth + 1, nextSeen, baseUrl) : null;
    }
    return obj;
  }

  if (t === "array" || schema.items) {
    return [makeExampleSync(schema.items || {}, resolveRefSync, depth + 1, nextSeen, baseUrl)];
  }

  if (schema.const !== undefined) return schema.const;
  if (Array.isArray(schema.enum) && schema.enum.length) return schema.enum[0];
  if (t === "string") {
    if (schema.format === "date-time") return new Date().toISOString();
    if (schema.format === "uri") return "https://example.com";
    return "x";
  }
  if (t === "integer") return 1;
  if (t === "number") return 1;
  if (t === "boolean") return true;

  return null;
}

function ensureExampleSize(verb, example) {
  const n = JSON.stringify(example).length;
  if (n > MAX_EXAMPLE_BYTES) throw new Error(`${verb} example too large (${n} bytes)`);
}

function makeFetchers() {
  const schemaCache = new Map();

  async function fetchJson(url, label = "schema") {
    const normalized = normalizeFetchUrl(url);
    if (schemaCache.has(normalized)) return schemaCache.get(normalized);

    const attempts = [normalized, maybeSwapSchemaHost(normalized)].filter(Boolean);
    let lastError = null;

    for (const attemptUrl of attempts) {
      if (schemaCache.has(attemptUrl)) return schemaCache.get(attemptUrl);

      const ac = new AbortController();
      const t = setTimeout(() => ac.abort(), FETCH_TIMEOUT_MS);
      try {
        const resp = await fetch(attemptUrl, { headers: { accept: "application/json" }, signal: ac.signal });
        if (!resp.ok) throw new Error(`${label} fetch failed at ${attemptUrl}: ${resp.status} ${resp.statusText}`);
        const json = await resp.json();
        schemaCache.set(attemptUrl, json);
        schemaCache.set(normalized, json);
        return json;
      } catch (e) {
        const msg = e?.name === "AbortError" ? `timeout after ${FETCH_TIMEOUT_MS}ms` : e?.message || String(e);
        lastError = new Error(`${label} fetch failed at ${attemptUrl}: ${msg}`);
      } finally {
        clearTimeout(t);
      }
    }

    throw new Error(lastError?.message || `${label} fetch failed: ${normalized}`);
  }

  return { fetchJson, schemaCache };
}

function makeResolverSync(rootSchema, rootUrl, schemaCache) {
  const refCache = new Map();

  return function resolveRefSync(ref, baseUrl = rootUrl) {
    const cacheKey = `${baseUrl}::${ref}`;
    if (refCache.has(cacheKey)) return refCache.get(cacheKey);

    const { base, fragment } = splitRef(ref);
    const resolvedUrl = base ? new URL(base, baseUrl).toString() : baseUrl;
    const doc = resolvedUrl === rootUrl ? rootSchema : schemaCache.get(resolvedUrl) || schemaCache.get(normalizeFetchUrl(resolvedUrl));
    if (!doc) throw new Error(`$ref not loaded in cache: ref=${ref} resolved=${resolvedUrl}`);

    const target = resolveJsonPointer(doc, fragment || "#");
    if (!target || typeof target !== "object") {
      throw new Error(`$ref resolution failed: ref=${ref} base=${baseUrl} resolved=${resolvedUrl}${fragment || ""}`);
    }

    refCache.set(cacheKey, target);
    return target;
  };
}

async function runChild(verb) {
  const { fetchJson, schemaCache } = makeFetchers();

  console.log(`compile request schema ${verb}`);
  const requestUrl = schemaUrl(verb, "requests");
  const receiptUrl = schemaUrl(verb, "receipts");

  const requestSchema = await fetchJson(requestUrl, `${verb} request schema`);
  const receiptSchema = await fetchJson(receiptUrl, `${verb} receipt schema`);

  const reqAjv = makeAjv(fetchJson);
  const validateReq = await reqAjv.compileAsync(requestSchema);

  const resolveRefSync = makeResolverSync(requestSchema, requestUrl, schemaCache);
  const x402 = makeExampleSync(requestSchema?.properties?.x402 || {}, resolveRefSync, 0, new Set(), requestUrl);
  const trace = makeExampleSync(requestSchema?.properties?.trace || {}, resolveRefSync, 0, new Set(), requestUrl);
  const payload = makeExampleSync(requestSchema?.properties?.payload || {}, resolveRefSync, 0, new Set(), requestUrl);

  const requestBody = { x402: x402 ?? {}, trace: trace ?? {}, payload: payload ?? {} };
  ensureExampleSize(verb, requestBody);

  if (!validateReq(requestBody)) {
    throw new Error(`${verb} request example schema-invalid: ${JSON.stringify(simplifyErrors(validateReq.errors))}`);
  }

  console.log(`POST ${verb}`);
  const resp = await fetch(`${BASE}/${verb}/v1.0.0`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(requestBody),
  });

  const text = await resp.text();
  let receipt;
  try {
    receipt = JSON.parse(text);
  } catch {
    throw new Error(`${verb} route returned non-JSON: status=${resp.status}`);
  }

  if (!resp.ok) {
    throw new Error(`${verb} route failed: status=${resp.status} body=${JSON.stringify(receipt).slice(0, 1000)}`);
  }

  console.log(`validate receipt ${verb}`);
  const receiptAjv = makeAjv(fetchJson);
  const validateReceipt = await receiptAjv.compileAsync(receiptSchema);
  if (!validateReceipt(receipt)) {
    throw new Error(`${verb} receipt schema-invalid: ${JSON.stringify(simplifyErrors(validateReceipt.errors))}`);
  }

  console.log(`PASS ${verb}`);
}

function spawnVerbChild(verb) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["scripts/contract-check.mjs", "--child", "--verb", verb], {
      env: {
        ...process.env,
        PORT: String(PORT),
        SCHEMA_HOST,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });

    child.stdout.on("data", (d) => process.stdout.write(d));
    child.stderr.on("data", (d) => process.stderr.write(d));

    child.on("error", (e) => reject(e));
    child.on("close", (code) => {
      if (code === 0) return resolve();
      reject(new Error(`child failed for verb=${verb} exit=${code}`));
    });
  });
}

async function runParent() {
  ensureSigningKeys();
  process.env.PORT = String(PORT);
  process.env.SCHEMA_HOST = SCHEMA_HOST;

  console.log("boot contract-check parent");
  const { start } = await import("../src/commercial.server.mjs");
  const server = start();
  await new Promise((r) => setTimeout(r, 250));

  try {
    for (const verb of VERBS) {
      console.log(`running verb ${verb}`);
      await spawnVerbChild(verb);
    }
    console.log("PASS contract-check all verbs");
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

async function main() {
  if (hasFlag("--child")) {
    const verb = parseArg("--verb");
    if (!verb || !VERBS.includes(verb)) {
      throw new Error(`invalid --verb, expected one of: ${VERBS.join(",")}`);
    }
    await runChild(verb);
    return;
  }

  await runParent();
}

main().catch((e) => {
  console.error("contract check failed:", e?.message || e);
  process.exit(1);
});
