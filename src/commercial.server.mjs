// src/commercial.server.mjs
// CommandLayer — Commercial Runtime
// Verbs: authorize, checkout, purchase, ship, verify
//
// Start: PORT=8090 node src/commercial.server.mjs

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

function requireJsonBody(req, res) {
  if (!req.body || typeof req.body !== "object") {
    res.status(400).json({ status: "error", code: 400, message: "Invalid JSON body" });
    return false;
  }
  return true;
}

function safeJson(res, http, payload) {
  try {
    return res.status(http).json(payload);
  } catch {
    return res.status(http).end(JSON.stringify(payload));
  }
}

function safeMakeReceipt(args) {
  try {
    return { ok: true, receipt: makeReceipt(args) };
  } catch (e) {
    return { ok: false, error: e };
  }
}

// -----------------------
// Optional: schema warm queue (edge-safe-ish)
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
          // best-effort warm
        }
      }
    } finally {
      warmRunning = false;
      if (warmQueue.size > 0) startWarmWorker();
    }
  }, 0);
}

export function buildApp() {
  const app = express();
  app.use(express.json({ limit: "2mb" }));

  // ---- basic CORS (no dependency)
  app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    if (req.method === "OPTIONS") return res.status(204).end();
    next();
  });

  const PORT = Number(process.env.PORT || 8080);

  // ---- service identity / discovery
  const SERVICE_NAME = process.env.SERVICE_NAME || "commandlayer-commercial-runtime";
  const SERVICE_VERSION = process.env.SERVICE_VERSION || "1.0.0";
  const API_VERSION = process.env.API_VERSION || "1.0.0";

  // Canonical base:
  // - On Railway, RAILWAY_PUBLIC_DOMAIN is the best default
  // - Otherwise local
  const railwayBase = process.env.RAILWAY_PUBLIC_DOMAIN ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}` : null;
  const CANONICAL_BASE = (process.env.CANONICAL_BASE_URL || railwayBase || `http://localhost:${PORT}`).replace(
    /\/+$/,
    ""
  );

  // ---- runtime config
  const ENABLED_VERBS = parseEnabledVerbs();
  const enabled = (verb) => ENABLED_VERBS.includes(verb);

  // Receipt signer label (not the key itself)
  const SIGNER_ID = process.env.RECEIPT_SIGNER_ID || process.env.ENS_NAME || "commercial-runtime";

  // Pricing rules (static JSON + env overrides handled inside facilitator)
  const pricing = loadPricing();

  async function handleVerb(verb, req, res) {
    if (!enabled(verb)) {
      return res.status(404).json({ status: "error", code: 404, message: `Verb not enabled: ${verb}` });
    }
    if (!handlers[verb]) {
      return res.status(404).json({ status: "error", code: 404, message: `Verb not supported: ${verb}` });
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

    // Resolve actor once; reuse on both success/error
    const actor = resolveActor(req);

    try {
      // Decide free vs paid + enforce limits
      const decision = await applyLimits({ req, verb, pricing, actor });

      // Execute verb deterministically (your verb modules can call Stripe/crypto later)
      const result = await handlers[verb]({ body: req.body, actor, pricing, decision });

      trace.completed_at = nowIso();
      trace.duration_ms = Date.now() - started;

      const out = safeMakeReceipt({
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

      if (!out.ok) {
        console.error("receipt_sign_failed(success):", out.error?.stack || out.error);
        return safeJson(res, 500, {
          status: "error",
          code: 500,
          message: "receipt signing failed",
          details: { verb, where: "success" },
          time: nowIso(),
        });
      }

      return res.json(out.receipt);
    } catch (e) {
      trace.completed_at = nowIso();
      trace.duration_ms = Date.now() - started;

      const err = {
        code: String(e?.code || "INTERNAL_ERROR"),
        message: String(e?.message || "unknown error").slice(0, 2048),
        retryable: Boolean(e?.retryable),
        details: { verb },
      };

      const out = safeMakeReceipt({
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

      const http = Number(e?.http_status || 500);

      if (!out.ok) {
        console.error("receipt_sign_failed(error):", out.error?.stack || out.error);
        return safeJson(res, http, {
          status: "error",
          code: http,
          message: err.message,
          details: err.details,
          note: "also failed to sign receipt",
          time: nowIso(),
        });
      }

      return res.status(http).json(out.receipt);
    }
  }

  // -----------------------
  // Index / Health / Debug
  // -----------------------
  app.get("/", (req, res) => {
    res.json({
      ok: true,
      service: SERVICE_NAME,
      version: SERVICE_VERSION,
      api_version: API_VERSION,
      base: CANONICAL_BASE,
      health: "/health",
      pricing: "/.well-known/pricing.json",
      verify: "/verify",
      debug_env: "/debug/env",
      debug_validators: "/debug/validators",
      debug_prewarm: "/debug/prewarm",
      verbs: (ENABLED_VERBS || []).map((v) => `/${v}/v${API_VERSION}`),
      time: nowIso(),
    });
  });

  app.get("/health", (req, res) => {
    res.json({
      ok: true,
      service: SERVICE_NAME,
      version: SERVICE_VERSION,
      api_version: API_VERSION,
      base: CANONICAL_BASE,
      node: process.version,
      port: PORT,
      enabled_verbs: ENABLED_VERBS,
      signer_id: SIGNER_ID,
      time: nowIso(),
    });
  });

  app.get("/.well-known/pricing.json", (req, res) => res.json(pricing));

  app.get("/debug/env", (req, res) => {
    res.json({
      ok: true,
      node: process.version,
      port: PORT,
      service: process.env.RAILWAY_SERVICE_NAME || "commercial-runtime",
      enabled_verbs: ENABLED_VERBS,
      signer_id: SIGNER_ID,
      schema_host: process.env.SCHEMA_HOST || "https://www.commandlayer.org",
      billing_provider: process.env.BILLING_PROVIDER || "none",
      verifier_ens_name: process.env.VERIFIER_ENS_NAME || null,
      ens_pubkey_text_key: process.env.ENS_PUBKEY_TEXT_KEY || "cl.receipt.pubkey.pem",
      canonical_base_url: CANONICAL_BASE,
      time: nowIso(),
    });
  });

  app.get("/debug/validators", async (req, res) => {
    try {
      const { debugState } = await import("./receipts/schema.mjs");
      res.json({ ok: true, ...debugState(), warm_queue_size: warmQueue.size, warm_running: warmRunning });
    } catch (e) {
      res.status(500).json({ ok: false, error: e?.message || "debug failed" });
    }
  });

  // Fire-and-forget warm (safe endpoint to call after deploy)
  app.post("/debug/prewarm", async (req, res) => {
    const verbs = Array.isArray(req.body?.verbs) ? req.body.verbs : [];
    const cleaned = verbs.map((v) => String(v || "").trim()).filter(Boolean);
    const supported = cleaned.filter((v) => enabled(v));

    for (const v of supported) warmQueue.add(v);

    res.json({
      ok: true,
      queued: supported,
      queue_size: warmQueue.size,
      note: "Warm runs after response; poll /debug/validators.",
    });

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

      return res.status(ok ? 200 : 400).json({
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
      });
    } catch (e) {
      return res.status(500).json({ ok: false, error: e?.message || "verify failed" });
    }
  });

  return { app, PORT };
}

export function start() {
  const { app, PORT } = buildApp();

  // IMPORTANT: Railway needs 0.0.0.0 binding
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
