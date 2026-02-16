import crypto from "crypto";
import Ajv from "ajv";
import addFormats from "ajv-formats";

const VERBS = ["authorize", "checkout", "purchase", "ship", "verify"];
const PORT = Number(process.env.PORT || 8099);
const BASE = process.env.CONTRACT_CHECK_BASE_URL || `http://127.0.0.1:${PORT}`;
const SCHEMA_HOST = (process.env.SCHEMA_HOST || "https://www.commandlayer.org").replace(/\/+$/, "");

const schemaCache = new Map(); // finalUrl -> schema json

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

async function fetchSchema(url, label = "schema") {
  const normalized = normalizeFetchUrl(url);
  if (schemaCache.has(normalized)) return schemaCache.get(normalized);

  const attempts = [normalized, maybeSwapSchemaHost(normalized)].filter(Boolean);
  let lastError = null;

  for (const attemptUrl of attempts) {
    if (schemaCache.has(attemptUrl)) return schemaCache.get(attemptUrl);

    try {
      const resp = await fetch(attemptUrl, { headers: { accept: "application/json" } });
      if (!resp.ok) throw new Error(`${label} fetch failed: ${attemptUrl} -> ${resp.status} ${resp.statusText}`);

      const json = await resp.json();
      schemaCache.set(attemptUrl, json);
      // also memoize normalized primary URL to same object
      schemaCache.set(normalized, json);
      return json;
    } catch (e) {
      const msg = e?.message || String(e);
      lastError = new Error(`${label} fetch failed at ${attemptUrl}: ${msg}`);
    }
  }

  throw new Error(lastError?.message || `${label} fetch failed: ${normalized}`);
}

function splitRef(ref) {
  const str = String(ref || "");
  const idx = str.indexOf("#");
  if (idx === -1) return { base: str, fragment: "" };
  return { base: str.slice(0, idx), fragment: str.slice(idx) };
}

function resolveJsonPointer(doc, fragment) {
  if (!fragment || fragment === "#") return doc;
  if (!fragment.startsWith("#/")) return null;

  const parts = fragment
    .slice(2)
    .split("/")
    .map((s) => s.replace(/~1/g, "/").replace(/~0/g, "~"));

  let cur = doc;
  for (const part of parts) {
    if (cur == null || typeof cur !== "object" || !(part in cur)) return null;
    cur = cur[part];
  }
  return cur;
}

function makeResolver(rootSchema, rootUrl) {
  const refCache = new Map();

  return async function resolveRef(ref, baseUrl = rootUrl) {
    const cacheKey = `${baseUrl}::${ref}`;
    if (refCache.has(cacheKey)) return refCache.get(cacheKey);

    const { base, fragment } = splitRef(ref);
    const resolvedUrl = base ? new URL(base, baseUrl).toString() : baseUrl;
    const doc = resolvedUrl === rootUrl ? rootSchema : await fetchSchema(resolvedUrl, `$ref ${ref}`);

    const target = resolveJsonPointer(doc, fragment || "#");
    if (!target || typeof target !== "object") {
      throw new Error(`$ref resolution failed: ref=${ref} base=${baseUrl} resolved=${resolvedUrl}${fragment || ""}`);
    }

    refCache.set(cacheKey, target);
    return target;
  };
}

async function makeExample(schema, resolveRef, depth = 0, seen = new Set(), baseUrl = "") {
  if (!schema || typeof schema !== "object") return null;
  if (depth > 6) return null;

  const keySeed = schema.$id || schema.$ref || `${baseUrl}:${schema.type || "unknown"}:${Object.keys(schema).slice(0, 5).join(",")}`;
  if (seen.has(keySeed)) return null;

  const nextSeen = new Set(seen);
  nextSeen.add(keySeed);

  if (schema.$ref) {
    const refSchema = await resolveRef(schema.$ref, baseUrl);
    return await makeExample(refSchema, resolveRef, depth + 1, nextSeen, new URL(schema.$ref, baseUrl).toString());
  }

  if (Array.isArray(schema.anyOf) && schema.anyOf.length) {
    return await makeExample(schema.anyOf[0], resolveRef, depth + 1, nextSeen, baseUrl);
  }
  if (Array.isArray(schema.oneOf) && schema.oneOf.length) {
    return await makeExample(schema.oneOf[0], resolveRef, depth + 1, nextSeen, baseUrl);
  }

  if (Array.isArray(schema.allOf) && schema.allOf.length) {
    const out = {};
    for (const part of schema.allOf) {
      const ex = await makeExample(part, resolveRef, depth + 1, nextSeen, baseUrl);
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
      if (props[k]) obj[k] = await makeExample(props[k], resolveRef, depth + 1, nextSeen, baseUrl);
      else obj[k] = null;
    }
    return obj;
  }

  if (t === "array" || schema.items) {
    const itemSchema = schema.items || {};
    return [await makeExample(itemSchema, resolveRef, depth + 1, nextSeen, baseUrl)];
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
  const size = JSON.stringify(example).length;
  if (size > 200_000) throw new Error(`${verb} example too large (${size} bytes)`);
}

function ajvForContractCheck() {
  const ajv = new Ajv({
    allErrors: true,
    strict: false,
    validateSchema: false,
    loadSchema: async (uri) => await fetchSchema(uri, `ajv loadSchema ${uri}`),
  });
  addFormats(ajv);
  return ajv;
}

function schemaUrl(verb, kind) {
  return `${SCHEMA_HOST}/schemas/v1.0.0/commercial/${verb}/${kind}/${verb}.${kind.slice(0, -1)}.schema.json`;
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

async function main() {
  ensureSigningKeys();
  process.env.PORT = String(PORT);
  process.env.SCHEMA_HOST = SCHEMA_HOST;

  const { start } = await import("../src/commercial.server.mjs");
  const server = start();
  await new Promise((r) => setTimeout(r, 250));

  try {
    for (const verb of VERBS) {
      const requestUrl = schemaUrl(verb, "requests");
      const receiptUrl = schemaUrl(verb, "receipts");

      const requestSchema = await fetchSchema(requestUrl, `${verb} request schema`);
      const receiptSchema = await fetchSchema(receiptUrl, `${verb} receipt schema`);

      const reqResolver = makeResolver(requestSchema, requestUrl);
      const payloadSchema = requestSchema?.properties?.payload || {};
      const x402Schema = requestSchema?.properties?.x402 || {};
      const traceSchema = requestSchema?.properties?.trace || {};

      const payload = await makeExample(payloadSchema, reqResolver, 0, new Set(), requestUrl);
      const x402 = await makeExample(x402Schema, reqResolver, 0, new Set(), requestUrl);
      const trace = await makeExample(traceSchema, reqResolver, 0, new Set(), requestUrl);

      const requestBody = {
        x402: x402 ?? {},
        trace: trace ?? {},
        payload: payload ?? {},
      };

      ensureExampleSize(verb, requestBody);

      const reqAjv = ajvForContractCheck();
      const validateReq = await reqAjv.compileAsync(requestSchema);
      if (!validateReq(requestBody)) {
        throw new Error(`${verb} request example schema-invalid: ${JSON.stringify(simplifyErrors(validateReq.errors))}`);
      }

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

      const receiptAjv = ajvForContractCheck();
      const validateReceipt = await receiptAjv.compileAsync(receiptSchema);
      if (!validateReceipt(receipt)) {
        throw new Error(`${verb} receipt schema-invalid: ${JSON.stringify(simplifyErrors(validateReceipt.errors))}`);
      }

      console.log(`ok ${verb}`);
    }

    console.log("contract check passed");
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

main().catch((e) => {
  console.error("contract check failed:", e?.message || e);
  process.exit(1);
});
