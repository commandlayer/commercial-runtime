import crypto from "crypto";

const VERBS = ["authorize", "checkout", "purchase", "ship", "verify"];
const PORT = Number(process.env.PORT || 8099);
const BASE = process.env.CONTRACT_CHECK_BASE_URL || `http://127.0.0.1:${PORT}`;
const SCHEMA_HOST = (process.env.SCHEMA_HOST || "https://www.commandlayer.org").replace(/\/+$/, "");

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

function chooseType(schema) {
  if (!schema) return "string";
  if (Array.isArray(schema.type)) return schema.type.find((t) => t !== "null") || schema.type[0];
  if (schema.type) return schema.type;
  if (schema.const !== undefined) return typeof schema.const;
  if (schema.enum) return typeof schema.enum[0];
  if (schema.properties || schema.required) return "object";
  if (schema.items) return "array";
  return "string";
}

function fromSchema(schema, root, seen = new Set()) {
  if (!schema || typeof schema !== "object") return null;
  if (schema.$ref) {
    const ref = schema.$ref;
    if (!ref.startsWith("#/$defs/")) return {};
    if (seen.has(ref)) return {};
    seen.add(ref);
    const key = ref.replace("#/$defs/", "");
    return fromSchema(root?.$defs?.[key], root, seen);
  }
  if (schema.const !== undefined) return schema.const;
  if (Array.isArray(schema.enum) && schema.enum.length) return schema.enum[0];
  if (Array.isArray(schema.oneOf) && schema.oneOf.length) return fromSchema(schema.oneOf[0], root, seen);
  if (Array.isArray(schema.anyOf) && schema.anyOf.length) return fromSchema(schema.anyOf[0], root, seen);
  if (Array.isArray(schema.allOf) && schema.allOf.length) {
    const out = {};
    for (const child of schema.allOf) {
      const value = fromSchema(child, root, seen);
      if (value && typeof value === "object" && !Array.isArray(value)) Object.assign(out, value);
    }
    return Object.keys(out).length ? out : fromSchema(schema.allOf[0], root, seen);
  }

  const type = chooseType(schema);
  if (type === "object") {
    const out = {};
    const props = schema.properties || {};
    const required = Array.isArray(schema.required) ? schema.required : [];
    for (const key of required) out[key] = fromSchema(props[key], root, new Set(seen));
    return out;
  }
  if (type === "array") {
    return [fromSchema(schema.items || {}, root, new Set(seen))];
  }
  if (type === "number" || type === "integer") return 1;
  if (type === "boolean") return true;
  return "sample";
}

function maybeSwapSchemaHost(url) {
  if (url.includes("://www.commandlayer.org")) return url.replace("://www.commandlayer.org", "://commandlayer.org");
  if (url.includes("://commandlayer.org")) return url.replace("://commandlayer.org", "://www.commandlayer.org");
  return null;
}

async function fetchJsonFailLoud(url, label) {
  const attempts = [url, maybeSwapSchemaHost(url)].filter(Boolean);
  let lastError = null;

  for (const u of attempts) {
    try {
      const resp = await fetch(u, { headers: { accept: "application/json" } });
      if (!resp.ok) throw new Error(`${label} fetch failed: ${u} -> ${resp.status} ${resp.statusText}`);
      return await resp.json();
    } catch (e) {
      lastError = e;
    }
  }

  throw new Error(lastError?.message || `${label} fetch failed: ${url}`);
}

async function main() {
  ensureSigningKeys();
  process.env.PORT = String(PORT);
  process.env.SCHEMA_HOST = SCHEMA_HOST;

  const { start } = await import("../src/commercial.server.mjs");
  const { getRequestValidator, requestSchemaUrlForVerb, formatAjvErrors } = await import("../src/requests/schema.mjs");
  const { getValidatorForVerb, receiptSchemaUrlForVerb, ajvErrorsToSimple } = await import("../src/receipts/schema.mjs");

  const server = start();
  await new Promise((r) => setTimeout(r, 250));

  try {
    for (const verb of VERBS) {
      const reqUrl = requestSchemaUrlForVerb(verb);
      const receiptUrl = receiptSchemaUrlForVerb(verb);
      await fetchJsonFailLoud(reqUrl, `${verb} request schema`);
      await fetchJsonFailLoud(receiptUrl, `${verb} receipt schema`);

      const requestSchema = await fetchJsonFailLoud(reqUrl, `${verb} request schema`);
      const payloadSchema = requestSchema?.properties?.payload || {};
      const payload = fromSchema(payloadSchema, requestSchema);

      const requestBody = {
        x402: {
          verb,
          version: "1.0.0",
          entry: `x402://${verb}agent.eth/${verb}/v1.0.0`,
        },
        trace: {
          trace_id: `trace_contract_${verb}`,
          started_at: new Date().toISOString(),
          completed_at: new Date().toISOString(),
          duration_ms: 1,
          provider: "contract-check",
        },
        payload,
      };

      const reqValidate = await getRequestValidator(verb);
      if (!reqValidate(requestBody)) {
        throw new Error(
          `${verb} request invalid before POST: ${JSON.stringify(formatAjvErrors(reqValidate.errors))}`
        );
      }

      const resp = await fetch(`${BASE}/${verb}/v1.0.0`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(requestBody),
      });

      const text = await resp.text();
      let json;
      try {
        json = JSON.parse(text);
      } catch {
        throw new Error(`${verb} route returned non-JSON (${resp.status}): ${text.slice(0, 500)}`);
      }
      if (!resp.ok) {
        throw new Error(`${verb} route failed: HTTP ${resp.status} body=${JSON.stringify(json).slice(0, 2000)}`);
      }

      const receiptValidate = await getValidatorForVerb(verb);
      if (!receiptValidate(json)) {
        throw new Error(`${verb} receipt invalid: ${JSON.stringify(ajvErrorsToSimple(receiptValidate.errors) || [])}`);
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
