import { API_VERSION_DEFAULT } from "../runtime-version.mjs";
import Ajv from "ajv";
import addFormats from "ajv-formats";

const SCHEMA_HOST = (process.env.SCHEMA_HOST || "https://www.commandlayer.org").replace(/\/+$/, "");
const FETCH_TIMEOUT_MS = Number(process.env.SCHEMA_FETCH_TIMEOUT_MS || 15000);
const COMPILE_TIMEOUT_MS = Number(process.env.SCHEMA_VALIDATE_BUDGET_MS || 15000);
const SCHEMA_VERSION = process.env.SCHEMA_VERSION || API_VERSION_DEFAULT;

const schemaCache = new Map(); // url -> { t, json }
const validatorCache = new Map(); // verb -> validate

function normalizeUrl(url) {
  let u = String(url || "");

  // force https
  if (!/^http:\/\/127\.0\.0\.1(?::\d+)?\//i.test(u) && !/^http:\/\/localhost(?::\d+)?\//i.test(u)) {
    u = u.replace(/^http:\/\//i, "https://");
  }

  // unify host (avoid redirects / host mismatch across $id and refs)
  u = u.replace(/^https:\/\/commandlayer\.org/i, "https://www.commandlayer.org");
  u = u.replace(/^https:\/\/www\.commandlayer\.org\/+/, "https://www.commandlayer.org/");

  return u;
}

async function withTimeout(p, ms, label) {
  if (!ms || ms <= 0) return await p;
  return await Promise.race([
    p,
    new Promise((_, rej) => setTimeout(() => rej(new Error(label || "timeout")), ms)),
  ]);
}

async function fetchJson(url) {
  const u = normalizeUrl(url);
  const hit = schemaCache.get(u);
  if (hit) return hit.json;

  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), FETCH_TIMEOUT_MS);

  try {
    const resp = await fetch(u, {
      method: "GET",
      headers: { accept: "application/json" },
      signal: ac.signal,
      redirect: "follow",
    });
    if (!resp.ok) throw new Error(`schema fetch failed: ${resp.status} ${resp.statusText}`);

    const json = await resp.json();
    schemaCache.set(u, { t: Date.now(), json });
    return json;
  } finally {
    clearTimeout(t);
  }
}

function makeAjv() {
  const ajv = new Ajv({
    allErrors: true,
    strict: false,
    validateSchema: false,
    loadSchema: async (uri) => await fetchJson(uri),
  });
  addFormats(ajv);
  return ajv;
}

export function receiptSchemaUrlForVerb(verb) {
  return `${SCHEMA_HOST}/schemas/v${SCHEMA_VERSION}/commercial/${verb}/receipts/${verb}.receipt.schema.json`;
}

async function preloadSharedSchemas() {
  const shared = [
    `${SCHEMA_HOST}/schemas/v${SCHEMA_VERSION}/_shared/receipt.base.schema.json`,
    `${SCHEMA_HOST}/schemas/v${SCHEMA_VERSION}/_shared/x402.schema.json`,
    `${SCHEMA_HOST}/schemas/v${SCHEMA_VERSION}/_shared/identity.schema.json`,
    `${SCHEMA_HOST}/schemas/v${SCHEMA_VERSION}/_shared/trace.schema.json`,
    `${SCHEMA_HOST}/schemas/v${SCHEMA_VERSION}/commercial/_shared/payment.amount.schema.json`,
    `${SCHEMA_HOST}/schemas/v${SCHEMA_VERSION}/commercial/_shared/payment.settlement.schema.json`,
  ];
  await Promise.all(shared.map((u) => fetchJson(u).catch(() => null)));
}

export async function getValidatorForVerb(verb) {
  if (!verb) throw new Error("missing verb");
  if (validatorCache.has(verb)) return validatorCache.get(verb);

  const ajv = makeAjv();

  await preloadSharedSchemas();

  const schema = await fetchJson(receiptSchemaUrlForVerb(verb));
  const validate = await withTimeout(ajv.compileAsync(schema), COMPILE_TIMEOUT_MS, "ajv_compile_timeout");

  validatorCache.set(verb, validate);
  return validate;
}

export function ajvErrorsToSimple(errors) {
  if (!Array.isArray(errors)) return null;
  return errors.slice(0, 25).map((e) => ({
    instancePath: e.instancePath,
    schemaPath: e.schemaPath,
    keyword: e.keyword,
    message: e.message,
    params: e.params,
  }));
}

export function debugState() {
  return {
    schema_host: SCHEMA_HOST,
    cached_validators: Array.from(validatorCache.keys()),
    cached_schemas: schemaCache.size,
  };
}
