// src/commercial.server.mjs
// CommandLayer — Commercial Runtime (edge-safe)
// Verbs: authorize, checkout, purchase, ship, verify
//
// Start (local):  PORT=8090 node src/commercial.server.mjs
// Start (Railway): uses PORT + HOST=0.0.0.0

import express from "express";
import crypto from "crypto";

import { makeReceipt } from "./receipts/sign.mjs";
import { loadPricing } from "./billing/facilitator.mjs";
import { applyLimits } from "./middleware/limits.mjs";
import { resolveActor } from "./middleware/auth.mjs";

import authorize from "./verbs/authorize.mjs";
import checkout from "./verbs/checkout.mjs";
import purchase from "./verbs/purchase.mjs";
import ship from "./verbs/ship.mjs";
import verifyVerb from "./verbs/verify.mjs";

const handlers = {
  authorize,
  checkout,
  purchase,
  ship,
  verify: verifyVerb,
};

function nowIso() {
  return new Date().toISOString();
}

function randId(prefix = "trace_") {
  return prefix + crypto.randomBytes(6).toString("hex");
}

function parseEnabledVerbs() {
  return (process.env.ENABLED_VERBS || "authorize,checkout,purchase,ship,verify")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function respondNoStore(res) {
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
}

function requireJsonBody(req, res) {
  if (!req.body || typeof req.body !== "object") {
    respondNoStore(res);
    res.status(400).end(JSON.stringify({ status: "error", code: 400, message: "Invalid JSON body" }));
    return false;
  }
  return true;
}

function safeErrObj(e, verb) {
  return {
    code: String(e?.code || "INTERNAL_ERROR"),
    message: String(e?.message || "unknown error").slice(0, 2048),
    retryable: Boolean(e?.retryable),
    details: { verb },
  };
}

function b64ToPem(b64) {
  if (!b64 || typeof b64 !== "string") return null;
  // remove whitespace/newlines just in case Railway/UI inserted them
  const cleaned = b64.replace(/\s+/g, "");
  if (!cleaned) return null;
  const pem = Buffer.from(cleaned, "base64").toString("utf8");
  const head = (pem.split("\n")[0] || "").trim();
  if (!head.includes("BEGIN")) return null;
  return pem;
}

function safeHead(s, n = 24) {
  return String(s || "").slice(0, n);
}
function safeTail(s, n = 24) {
  return String(s || "").slice(-n);
}

// IMPORTANT: never let receipt signing failures prevent an HTTP response.
// This converts signing problems into a normal JSON error you can see.
function safeMakeReceipt(args) {
  try {
    return makeReceipt(args);
  } catch (e) {
    return {
      status: "error",
      x402: args?.x402 || null,
      trace: args?.trace || null,
      error: {
        code: "RECEIPT_SIGNING_FAILED",
        message: String(e?.message || e).slice(0, 2048),
        retryable: false,
        details: { signer_id: args?.signer_id || null },
      },
      actor: args?.actor || null,
      metadata: {
        proof: {
          alg: "ed25519-sha256",
          canonical: "json-stringify",
          signer_id: args?.signer_id || null,
          hash_sha256: null,
          signature_b64: null,
        },
        receipt_id: null,
      },
    };
  }
}

// -----------------------
// Optional: schema warm queue (best-effort)
// -----------------------
const warmQueue = new Set();
let warmRunning = false;

function startWarmWorker() {
  if (warmRunning) return;
  warmRunning = true;

  setTimeout(async () => {
    try {
      const { getValidatorForVerb } = await import("./receipts/schema.mjs");
      const MAX_PER_RUN = Number(process.env.PREWARM_MAX_VERBS || 25);
      let n = 0;

      while (warmQueue.size > 0 && n < MAX_PER_RUN) {
        const verb = warmQueue.values().next().value;
        warmQueue.delete(verb);
        n++;

        try {
          await getValidatorForVerb(verb);
        } catch {
          // best-effort only
        }
      }
    } finally {
      warmRunning = false;
      if (warmQueue.size > 0) startWarmWorker();
    }
  }, 0);
}

function keyHealth() {
  // We do NOT log the keys; just report presence + parsability.
  const privB64 = process.env.RECEIPT_SIGNING_PRIVATE_KEY_PEM_B64 || "";
  const pubB64 = process.env.RECEIPT_SIGNING_PUBLIC_KEY_PEM_B64 || "";

  const out = {
    has_priv_b64: !!privB64,
    has_pub_b64: !!pubB64,
    priv_ok: false,
    pub_ok: false,
    error: null,
  };

  try {
    if (privB64) {
      const pem = b64ToPem(privB64);
      if (!pem) throw new Error("decoded private key missing PEM header");
      crypto.createPrivateKey(pem);
      out.priv_ok = true;
    }
  } catch (e) {
    out.error = `private_key_invalid: ${String(e?.message || e)}`;
  }

  try {
    if (pubB64) {
      const pem = b64ToPem(pubB64);
      if (!pem) throw new Error("decoded public key missing PEM header");
      crypto.createPublicKey(pem);
      out.pub_ok = true;
    }
  } catch (e) {
    out.error = out.error || `public_key_invalid: ${String(e?.message || e)}`;
  }

  return out;
}

export function buildApp() {
  const app = express();
  app.use(express.json({ limit: "2mb" }));

  // CORS (no dependency)
  app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    if (req.method === "OPTIONS") return res.status(204).end();
    next();
  });

  const PORT = Number(process.env.PORT || 8080);

  // Identity
  const SERVICE_NAME = process.env.SERVICE_NAME || "commandlayer-commercial-runtime";
  const SERVICE_VERSION = process.env.SERVICE_VERSION || "1.0.0";
  const API_VERSION = process.env.API_VERSION || "1.0.0";

  // Canonical base:
  const railwayBase = process.env.RAILWAY_PUBLIC_DOMAIN ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}` : null;
  const CANONICAL_BASE = (process.env.CANONICAL_BASE_URL || railwayBase || `http://localhost:${PORT}`).replace(
    /\/+$/,
    ""
  );

  const ENABLED_VERBS = parseEnabledVerbs();
  const enabled = (verb) => ENABLED_VERBS.includes(verb);

  // Receipt signer label (not the key itself)
  const SIGNER_ID = process.env.RECEIPT_SIGNER_ID || process.env.ENS_NAME || "commercial-runtime";

  // Pricing rules (static JSON + env overrides handled inside facilitator)
  const pricing = loadPricing();

  async function handleVerb(verb, req, res) {
    if (!enabled(verb)) {
      respondNoStore(res);
      return res.status(404).end(JSON.stringify({ status: "error", code: 404, message: `Verb not enabled: ${verb}` }));
    }
    if (!handlers[verb]) {
      respondNoStore(res);
      return res
        .status(404)
        .end(JSON.stringify({ status: "error", code: 404, message: `Verb not supported: ${verb}` }));
    }
    if (!requireJsonBody(req, res)) return;

    const started = Date.now();

    // parent trace id allowed if provided (string + non-empty)
    const rawParent = req.body?.trace?.parent_trace_id ?? req.body?.x402?.extras?.parent_trace_id ?? null;
    const parent_trace_id = typeof rawParent === "string" && rawParent.trim().length ? rawParent.trim() : null;

    const trace = {
      trace_id: randId("trace_"),
      ...(parent_trace_id ? { parent_trace_id } : {}),
      started_at: nowIso(),
      completed_at: null,
      duration_ms: null,
      provider: process.env.RAILWAY_SERVICE_NAME || "commercial-runtime",
    };

    // Default x402 if caller omitted
    const x402 = req.body?.x402 || {
      verb,
      version: "1.0.0",
      entry: `x402://${verb}agent.eth/${verb}/v1.0.0`,
    };

    try {
      const actor = resolveActor(req);

      // Decide free vs paid + enforce limits
      const decision = await applyLimits({ req, verb, pricing, actor });

      // Execute verb deterministically (verb modules may call Stripe/crypto later)
      const result = await handlers[verb]({ body: req.body, actor, pricing, decision });

      trace.completed_at = nowIso();
      trace.duration_ms = Date.now() - started;

      const receipt = safeMakeReceipt({
        signer_id: SIGNER_ID,
        x402,
        trace,
        status: "success",
        result,
        actor,
        metadata_patch: {
          usage: {
            verb,
            units: 1,
            duration_ms: trace.duration_ms,
            ts: nowIso(),
            path: decision?.paid ? "paid" : "free",
          },
          billing: decision?.billing || null,
          limits: decision?.limits || null,
        },
      });

      respondNoStore(res);
      return res.status(200).end(JSON.stringify(receipt));
    } catch (e) {
      trace.completed_at = nowIso();
      trace.duration_ms = Date.now() - started;

      const actor = resolveActor(req);
      const err = safeErrObj(e, verb);

      const receipt = safeMakeReceipt({
        signer_id: SIGNER_ID,
        x402,
        trace,
        status: "error",
        error: err,
        actor,
        metadata_patch: {
          usage: { verb, units: 1, duration_ms: trace.duration_ms, ts: nowIso(), path: "error" },
        },
      });

      const http = Number(e?.http_status || e?.status || 500);
      respondNoStore(res);
      return res.status(http).end(JSON.stringify(receipt));
    }
  }

  // -----------------------
  // Index / Health / Debug
  // -----------------------
  app.get("/", (req, res) => {
    respondNoStore(res);
    res.status(200).end(
      JSON.stringify({
        ok: true,
        service: SERVICE_NAME,
        version: SERVICE_VERSION,
        api_version: API_VERSION,
        base: CANONICAL_BASE,
        health: "/health",
        pricing: "/.well-known/pricing.json",
        verify: "/verify",
        debug_env: "/debug/env",
        debug_signer: "/debug/signer",
        debug_keylens: "/debug/keylens",
        debug_validators: "/debug/validators",
        debug_prewarm: "/debug/prewarm",
        verbs: (ENABLED_VERBS || []).map((v) => `/${v}/v${API_VERSION}`),
        time: nowIso(),
      })
    );
  });

  app.get("/health", (req, res) => {
    const kh = keyHealth();
    respondNoStore(res);
    res.status(200).end(
      JSON.stringify({
        ok: true,
        service: SERVICE_NAME,
        version: SERVICE_VERSION,
        api_version: API_VERSION,
        base: CANONICAL_BASE,
        node: process.version,
        port: PORT,
        enabled_verbs: ENABLED_VERBS,
        signer_id: SIGNER_ID,
        signer_ok: !!kh.priv_ok,
        keys: { has_priv_b64: kh.has_priv_b64, has_pub_b64: kh.has_pub_b64, priv_ok: kh.priv_ok, pub_ok: kh.pub_ok },
        time: nowIso(),
      })
    );
  });

  app.get("/.well-known/pricing.json", (req, res) => {
    respondNoStore(res);
    res.status(200).end(JSON.stringify(pricing));
  });

  app.get("/debug/env", (req, res) => {
    const kh = keyHealth();
    respondNoStore(res);
    res.status(200).end(
      JSON.stringify({
        ok: true,
        node: process.version,
        port: PORT,
        service: process.env.RAILWAY_SERVICE_NAME || "commercial-runtime",
        enabled_verbs: ENABLED_VERBS,
        signer_id: SIGNER_ID,
        canonical_base_url: CANONICAL_BASE,
        schema_host: process.env.SCHEMA_HOST || "https://www.commandlayer.org",
        billing_provider: process.env.BILLING_PROVIDER || "none",
        verifier_ens_name: process.env.VERIFIER_ENS_NAME || null,
        ens_pubkey_text_key: process.env.ENS_PUBKEY_TEXT_KEY || "cl.receipt.pubkey.pem",
        keys: kh,
        time: nowIso(),
      })
    );
  });

  // Key lens: does NOT reveal keys, just lengths + decoded PEM headers + tiny b64 head/tail
  app.get("/debug/keylens", (req, res) => {
    respondNoStore(res);

    const privB64 = process.env.RECEIPT_SIGNING_PRIVATE_KEY_PEM_B64 || "";
    const pubB64 = process.env.RECEIPT_SIGNING_PUBLIC_KEY_PEM_B64 || "";

    const decodeHeader = (b64) => {
      try {
        const pem = b64ToPem(b64);
        if (!pem) return null;
        return (pem.split("\n")[0] || "").trim();
      } catch {
        return null;
      }
    };

    res.status(200).end(
      JSON.stringify({
        ok: true,
        priv: {
          b64_len: privB64.length,
          b64_head: safeHead(privB64),
          b64_tail: safeTail(privB64),
          decoded_header: decodeHeader(privB64),
        },
        pub: {
          b64_len: pubB64.length,
          b64_head: safeHead(pubB64),
          b64_tail: safeTail(pubB64),
          decoded_header: decodeHeader(pubB64),
        },
      })
    );
  });

  // signer self-test: proves keys are usable (no secrets)
  app.get("/debug/signer", async (req, res) => {
    respondNoStore(res);

    const msg = "ping:" + nowIso();
    const sha = crypto.createHash("sha256").update(msg).digest("hex");

    const privB64 = process.env.RECEIPT_SIGNING_PRIVATE_KEY_PEM_B64 || "";
    const pubB64 = process.env.RECEIPT_SIGNING_PUBLIC_KEY_PEM_B64 || "";

    const out = {
      ok: false,
      signer_id: SIGNER_ID,
      has_priv_b64: !!privB64,
      has_pub_b64: !!pubB64,
      sign_ok: false,
      verify_ok_env_pub: false,
      error: null,
      values: { msg, sha256: sha },
    };

    try {
      const privPem = b64ToPem(privB64);
      const pubPem = b64ToPem(pubB64);

      if (!privPem) throw new Error("private key decode failed (bad base64 or missing PEM header)");
      if (!pubPem) throw new Error("public key decode failed (bad base64 or missing PEM header)");

      const priv = crypto.createPrivateKey(privPem);
      const pub = crypto.createPublicKey(pubPem);

      const sig = crypto.sign(null, Buffer.from(sha, "utf8"), priv);
      out.sign_ok = true;

      const ok = crypto.verify(null, Buffer.from(sha, "utf8"), pub, sig);
      out.verify_ok_env_pub = !!ok;

      out.ok = out.sign_ok && out.verify_ok_env_pub;
      return res.status(out.ok ? 200 : 500).end(JSON.stringify(out));
    } catch (e) {
      out.error = String(e?.message || e).slice(0, 2048);
      out.ok = false;
      return res.status(500).end(JSON.stringify(out));
    }
  });

  app.get("/debug/validators", async (req, res) => {
    respondNoStore(res);
    try {
      const { debugState } = await import("./receipts/schema.mjs");
      res
        .status(200)
        .end(JSON.stringify({ ok: true, ...debugState(), warm_queue_size: warmQueue.size, warm_running: warmRunning }));
    } catch (e) {
      res.status(500).end(JSON.stringify({ ok: false, error: e?.message || "debug failed" }));
    }
  });

  // Fire-and-forget warm (safe endpoint to call after deploy)
  app.post("/debug/prewarm", async (req, res) => {
    const verbs = Array.isArray(req.body?.verbs) ? req.body.verbs : [];
    const cleaned = verbs.map((v) => String(v || "").trim()).filter(Boolean);
    const supported = cleaned.filter((v) => enabled(v));

    for (const v of supported) warmQueue.add(v);

    respondNoStore(res);
    res.status(200).end(
      JSON.stringify({
        ok: true,
        queued: supported,
        queue_size: warmQueue.size,
        note: "Warm runs after response; poll /debug/validators.",
      })
    );

    startWarmWorker();
  });

  // -----------------------
  // Verb routes
  // -----------------------
  for (const v of Object.keys(handlers)) {
    app.post(`/${v}/v1.0.0`, (req, res) => handleVerb(v, req, res));
  }

  // -----------------------
  // Verify (receipt hash+sig + optional schema + optional ens)
  // -----------------------
  app.post("/verify", async (req, res) => {
    respondNoStore(res);

    try {
      const wantEns = String(req.query.ens || "0") === "1";
      const refresh = String(req.query.refresh || "0") === "1";
      const wantSchema = String(req.query.schema || "0") === "1";

      const receipt = req.body;

      // 1) hash+sig (optionally ENS)
      const sigOut = await makeReceipt.verify({ receipt, wantEns, refresh });

      // 2) schema (commercial)
      let schemaOk = true;
      let schemaErrors = null;

      if (wantSchema) {
        schemaOk = false;
        const { getValidatorForVerb, ajvErrorsToSimple } = await import("./receipts/schema.mjs");
        const verb = String(receipt?.x402?.verb || "").trim();

        if (!verb) {
          schemaErrors = [{ message: "missing receipt.x402.verb" }];
        } else {
          try {
            const validate = await getValidatorForVerb(verb);
            const ok = validate(receipt);
            schemaOk = !!ok;
            if (!ok) schemaErrors = ajvErrorsToSimple(validate.errors) || [{ message: "schema validation failed" }];
          } catch (e) {
            schemaOk = false;
            schemaErrors = [{ message: e?.message || "schema validation error" }];
          }
        }
      }

      const ok = !!sigOut.ok && !!schemaOk;

      return res.status(ok ? 200 : 400).end(
        JSON.stringify({
          ok,
          checks: {
            hash_matches: sigOut?.checks?.hash_matches ?? false,
            signature_valid: sigOut?.checks?.signature_valid ?? false,
            schema_valid: schemaOk,
          },
          values: {
            verb: receipt?.x402?.verb ?? null,
            signer_id: receipt?.metadata?.proof?.signer_id ?? null,
            claimed_hash: receipt?.metadata?.proof?.hash_sha256 ?? null,
            recomputed_hash: sigOut?.values?.recomputed_hash ?? null,
            pubkey_source: sigOut?.values?.pubkey_source ?? null,
          },
          errors: {
            signature_error: sigOut?.errors?.signature_error ?? null,
            schema_errors: schemaErrors,
          },
        })
      );
    } catch (e) {
      return res.status(500).end(JSON.stringify({ ok: false, error: e?.message || "verify failed" }));
    }
  });

  return { app, PORT };
}

export function start() {
  const { app, PORT } = buildApp();
  const host = process.env.HOST || "0.0.0.0";

  console.log("boot: commandlayer-commercial-runtime");
  const server = app.listen(PORT, host, () => {
    console.log(`commercial runtime listening on http://${host}:${PORT}`);
  });

  server.on("error", (e) => console.error("listen_error:", e?.message || e));
  return server;
}

// If run directly: node src/commercial.server.mjs
if (import.meta.url === new URL(process.argv[1], "file:").href) {
  start();
}
