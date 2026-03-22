// src/commercial.server.mjs
// CommandLayer — Commercial Runtime (edge-safe)
// Verbs: authorize, checkout, purchase, ship, verify
//
// Start (local):  PORT=8090 node src/commercial.server.mjs
// Start (Railway): uses PORT + HOST=0.0.0.0

import express from "express";
import crypto from "crypto";

import { buildUnsignedReceipt, makeReceipt, signUnsignedReceipt } from "./receipts/sign.mjs";
import { getPublicKeyObject, getPublicKeySource, pemFromB64 } from "./receipts/keys.mjs";
import { ajvErrorsToSimple, getValidatorForVerb } from "./receipts/schema.mjs";
import { formatAjvErrors, getRequestValidator } from "./requests/schema.mjs";
import { normalizeProtocolRequest } from "./requests/normalize.mjs";
import { API_VERSION_DEFAULT, SERVICE_VERSION_DEFAULT } from "./runtime-version.mjs";
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

function logVerbStage({ level = "log", debug_id, verb, stage, ts = nowIso(), extra = undefined } = {}) {
  const payload = { ts, debug_id, verb, stage, ...(extra && typeof extra === "object" ? extra : {}) };
  console[level](JSON.stringify(payload));
}

function startStageGuard({ debug_id, verb, stage, timeoutMs = Number(process.env.DEBUG_STAGE_TIMEOUT_MS || 5000) } = {}) {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) return () => {};
  const started = Date.now();
  const timer = setTimeout(() => {
    logVerbStage({
      level: "warn",
      debug_id,
      verb,
      stage: `${stage}:slow`,
      extra: { elapsed_ms: Date.now() - started, timeout_ms: timeoutMs },
    });
  }, timeoutMs);

  return () => clearTimeout(timer);
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

function safeHead(s, n = 24) {
  return String(s || "").slice(0, n);
}
function safeTail(s, n = 24) {
  return String(s || "").slice(-n);
}

async function buildValidateSignReceipt({ verb, signer_id, x402, trace, result, status = "success", error = null, actor = null, metadata_patch = null } = {}) {
  const unsigned = buildUnsignedReceipt({ signer_id, x402, trace, result, status, error, actor, metadata_patch });
  let validate;
  try {
    validate = await getValidatorForVerb(verb);
  } catch (e) {
    return {
      ok: false,
      http_status: 500,
      body: {
        ok: false,
        error: "receipt_schema_invalid",
        kind: "receipt",
        verb,
        message: "Failed to load receipt schema validator",
        details: [{ message: String(e?.message || e) }],
      },
    };
  }

  const ok = validate(unsigned);
  if (!ok) {
    return {
      ok: false,
      http_status: 500,
      body: {
        ok: false,
        error: "receipt_schema_invalid",
        kind: "receipt",
        verb,
        details: ajvErrorsToSimple(validate.errors) || [],
      },
    };
  }

  try {
    return { ok: true, body: signUnsignedReceipt(unsigned) };
  } catch (e) {
    return {
      ok: false,
      http_status: 500,
      body: {
        ok: false,
        error: "receipt_signing_failed",
        verb,
        message: String(e?.message || e).slice(0, 2048),
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
  const pubPemB64 = process.env.RECEIPT_SIGNING_PUBLIC_KEY_PEM_B64 || "";
  const pubRawB64 = process.env.RECEIPT_SIGNING_PUBLIC_KEY_B64 || "";

  const out = {
    has_priv_b64: !!privB64,
    has_pub_b64: !!(pubPemB64 || pubRawB64),
    has_pub_pem_b64: !!pubPemB64,
    has_pub_raw_b64: !!pubRawB64,
    priv_ok: false,
    pub_ok: false,
    error: null,
  };

  try {
    if (privB64) {
      const pem = pemFromB64(privB64);
      if (!pem) throw new Error("decoded private key missing PEM header");
      crypto.createPrivateKey(pem);
      out.priv_ok = true;
    }
  } catch (e) {
    out.error = `private_key_invalid: ${String(e?.message || e)}`;
  }

  try {
    if (pubPemB64 || pubRawB64) {
      getPublicKeyObject();
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
  const SERVICE_VERSION = process.env.SERVICE_VERSION || SERVICE_VERSION_DEFAULT;
  const API_VERSION = process.env.API_VERSION || API_VERSION_DEFAULT;

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
    const debug_id = randId("dbg_");
    let stage = "entry";
    logVerbStage({ debug_id, verb, stage: "handleVerb:entry", extra: { method: req.method, path: req.path } });

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

    stage = "normalize:before";
    logVerbStage({ debug_id, verb, stage });
    const normalized = normalizeProtocolRequest(req.body, { verb, apiVersion: API_VERSION });
    stage = "normalize:after";
    logVerbStage({ debug_id, verb, stage, extra: { has_x402: normalized?.x402 != null, has_trace: normalized?.trace != null, has_payload: normalized?.payload != null } });

    // parent trace id allowed if provided (string + non-empty)
    const rawParent = normalized?.trace?.parent_trace_id ?? req.body?.x402?.extras?.parent_trace_id ?? req.body?.parent_trace_id ?? req.body?.input?.parent_trace_id ?? null;
    const parent_trace_id = typeof rawParent === "string" && rawParent.trim().length ? rawParent.trim() : null;
    const normalizedTraceId = typeof normalized?.trace?.trace_id === "string" && normalized.trace.trace_id.trim().length ? normalized.trace.trace_id.trim() : null;

    const trace = {
      ...(normalized?.trace && typeof normalized.trace === "object" ? normalized.trace : {}),
      trace_id: normalizedTraceId || randId("trace_"),
      ...(parent_trace_id ? { parent_trace_id } : {}),
      started_at: nowIso(),
      completed_at: null,
      duration_ms: null,
      provider: process.env.RAILWAY_SERVICE_NAME || "commercial-runtime",
    };
    const missing = ["x402", "trace", "payload"].filter((k) => normalized[k] == null);
    if (missing.length) {
      logVerbStage({ debug_id, verb, stage: "request:missing_fields", extra: { missing } });
      respondNoStore(res);
      return res.status(400).end(
        JSON.stringify({
          ok: false,
          error: "invalid_request",
          message: "Request must include x402, trace, and payload",
          missing,
        })
      );
    }

    let validateReq;
    try {
      stage = "validator:before";
      logVerbStage({ debug_id, verb, stage });
      validateReq = await getRequestValidator(verb);
      stage = "validator:after";
      logVerbStage({ debug_id, verb, stage });
    } catch (e) {
      logVerbStage({ debug_id, verb, stage: "catch", level: "error", extra: { failed_stage: stage, message: String(e?.message || e).slice(0, 512) } });
      respondNoStore(res);
      return res.status(500).end(
        JSON.stringify({
          ok: false,
          error: "request_schema_unavailable",
          kind: "request",
          verb,
          details: [{ message: String(e?.message || e) }],
        })
      );
    }

    stage = "request_validation:run";
    const reqSchemaOk = validateReq(normalized);
    logVerbStage({ debug_id, verb, stage: "request_validation:after", extra: { ok: reqSchemaOk, error_count: Array.isArray(validateReq.errors) ? validateReq.errors.length : 0 } });
    if (!reqSchemaOk) {
      respondNoStore(res);
      return res.status(400).end(
        JSON.stringify({
          ok: false,
          error: "schema_validation_failed",
          kind: "request",
          verb,
          details: formatAjvErrors(validateReq.errors),
        })
      );
    }

    const x402 = normalized.x402;

    try {
      stage = "resolve_actor:before";
      logVerbStage({ debug_id, verb, stage });
      const actor = resolveActor(req);
      stage = "resolve_actor:after";
      logVerbStage({ debug_id, verb, stage, extra: { actor_present: actor != null } });

      // Decide free vs paid + enforce limits
      stage = "apply_limits:before";
      logVerbStage({ debug_id, verb, stage });
      const stopApplyLimitsGuard = startStageGuard({ debug_id, verb, stage: "apply_limits" });
      let decision;
      try {
        decision = await applyLimits({ req, verb, pricing, actor });
      } finally {
        stopApplyLimitsGuard();
      }
      stage = "apply_limits:after";
      logVerbStage({ debug_id, verb, stage, extra: { paid: Boolean(decision?.paid) } });

      // Execute verb deterministically (verb modules may call Stripe/crypto later)
      stage = "handler:before";
      logVerbStage({ debug_id, verb, stage });
      const stopHandlerGuard = startStageGuard({ debug_id, verb, stage: "handler" });
      let result;
      try {
        result = await handlers[verb]({ body: normalized, actor, pricing, decision });
      } finally {
        stopHandlerGuard();
      }
      stage = "handler:after";
      logVerbStage({ debug_id, verb, stage });

      trace.completed_at = nowIso();
      trace.duration_ms = Date.now() - started;

      stage = "receipt:before";
      logVerbStage({ debug_id, verb, stage, extra: { duration_ms: trace.duration_ms } });
      const receiptOut = await buildValidateSignReceipt({
        verb,
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
      stage = "receipt:after";
      logVerbStage({ debug_id, verb, stage, extra: { receipt_ok: receiptOut.ok } });

      stage = "response:before_send";
      logVerbStage({ debug_id, verb, stage, extra: { http_status: receiptOut.ok ? 200 : receiptOut.http_status || 500 } });
      respondNoStore(res);
      return res.status(receiptOut.ok ? 200 : receiptOut.http_status || 500).end(JSON.stringify(receiptOut.body));
    } catch (e) {
      trace.completed_at = nowIso();
      trace.duration_ms = Date.now() - started;

      logVerbStage({ debug_id, verb, stage: "catch", level: "error", extra: { failed_stage: stage, message: String(e?.message || e).slice(0, 512), duration_ms: trace.duration_ms } });

      let actor = null;
      try {
        actor = resolveActor(req);
      } catch {
        // best-effort only for error receipt
      }
      const err = safeErrObj(e, verb);

      stage = "receipt_error:before";
      logVerbStage({ debug_id, verb, stage });
      const receiptOut = await buildValidateSignReceipt({
        verb,
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
      stage = "receipt_error:after";
      logVerbStage({ debug_id, verb, stage, extra: { receipt_ok: receiptOut.ok } });

      const http = receiptOut.ok ? Number(e?.http_status || e?.status || 500) : receiptOut.http_status || 500;
      stage = "response:before_send";
      logVerbStage({ debug_id, verb, stage, extra: { http_status: http } });
      respondNoStore(res);
      return res.status(http).end(JSON.stringify(receiptOut.body));
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
        keys: {
          has_priv_b64: kh.has_priv_b64,
          has_pub_b64: kh.has_pub_b64,
          has_pub_pem_b64: kh.has_pub_pem_b64,
          has_pub_raw_b64: kh.has_pub_raw_b64,
          priv_ok: kh.priv_ok,
          pub_ok: kh.pub_ok,
        },
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
    const pubPemB64 = process.env.RECEIPT_SIGNING_PUBLIC_KEY_PEM_B64 || "";
    const pubRawB64 = process.env.RECEIPT_SIGNING_PUBLIC_KEY_B64 || "";

    const decodeHeader = (b64) => {
      try {
        const pem = pemFromB64(b64);
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
          pem_b64_len: pubPemB64.length,
          pem_b64_head: safeHead(pubPemB64),
          pem_b64_tail: safeTail(pubPemB64),
          decoded_header: decodeHeader(pubPemB64),
          raw_b64_len: pubRawB64.length,
          raw_b64_head: safeHead(pubRawB64),
          raw_b64_tail: safeTail(pubRawB64),
          source: getPublicKeySource(),
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
    const pubPemB64 = process.env.RECEIPT_SIGNING_PUBLIC_KEY_PEM_B64 || "";
    const pubRawB64 = process.env.RECEIPT_SIGNING_PUBLIC_KEY_B64 || "";

    const out = {
      ok: false,
      signer_id: SIGNER_ID,
      has_priv_b64: !!privB64,
      has_pub_b64: !!(pubPemB64 || pubRawB64),
      has_pub_pem_b64: !!pubPemB64,
      has_pub_raw_b64: !!pubRawB64,
      sign_ok: false,
      verify_ok_env_pub: false,
      error: null,
      values: { msg, sha256: sha },
    };

    try {
      const privPem = pemFromB64(privB64);

      if (!privPem) throw new Error("private key decode failed (bad base64 or missing PEM header)");

      const priv = crypto.createPrivateKey(privPem);
      const pub = getPublicKeyObject();

      const sig = crypto.sign(null, Buffer.from(sha, "utf8"), priv);
      out.sign_ok = true;

      const ok = crypto.verify(null, Buffer.from(sha, "utf8"), pub, sig);
      out.verify_ok_env_pub = !!ok;
      out.public_key_source = getPublicKeySource();

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
    app.post(`/${v}/v${API_VERSION}`, (req, res) => handleVerb(v, req, res));
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
