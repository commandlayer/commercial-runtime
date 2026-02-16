import { Buffer } from "buffer";
import { ethers } from "ethers";

const ETH_RPC_URL = process.env.ETH_RPC_URL || "";
const VERIFIER_ENS_NAME =
  process.env.VERIFIER_ENS_NAME ||
  process.env.ENS_NAME ||
  process.env.RECEIPT_SIGNER_ID ||
  "";

const LEGACY_PEM_KEY = process.env.ENS_PUBKEY_TEXT_KEY || "cl.receipt.pubkey.pem";

let ensCache = {
  fetched_at: 0,
  ttl_ms: 10 * 60 * 1000,
  pem: null,
  signer_id: null,
  canonical: null,
  kid: null,
  pubkey_source: null,
  error: null,
  source: null,
};

function normalizePem(text) {
  if (!text) return null;
  const cleaned = String(text).replace(/\\n/g, "\n").replace(/\s+$/g, "").trim();
  if (!cleaned.includes("BEGIN") || !cleaned.includes("END")) return null;
  return cleaned;
}

function joinTxtFragments(text) {
  if (text == null) return null;
  const raw = String(text).trim();
  if (!raw) return null;

  const parts = Array.from(raw.matchAll(/"([^"\\]*(?:\\.[^"\\]*)*)"/g)).map((m) => m[1]);
  if (parts.length) {
    return parts.join("").replace(/\\n/g, "\n").trim() || null;
  }
  return raw.replace(/\\n/g, "\n").trim() || null;
}

function decodeBase64Url(input) {
  const normalized = String(input || "").trim().replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  if (!normalized) return null;
  const pad = normalized.length % 4;
  const padded = normalized + (pad ? "=".repeat(4 - pad) : "");
  return Buffer.from(padded, "base64");
}

function rawEd25519ToPem(raw32) {
  if (!Buffer.isBuffer(raw32) || raw32.length !== 32) return null;
  const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
  const der = Buffer.concat([spkiPrefix, raw32]);
  const b64 = der.toString("base64");
  const lines = b64.match(/.{1,64}/g) || [];
  return `-----BEGIN PUBLIC KEY-----\n${lines.join("\n")}\n-----END PUBLIC KEY-----`;
}

function parseSigPubToPem(value) {
  const text = joinTxtFragments(value);
  if (!text) return null;
  const [algRaw, dataRaw] = text.split(":", 2);
  const alg = String(algRaw || "").trim().toLowerCase();
  const data = String(dataRaw || "").trim();
  if (alg !== "ed25519" || !data) return null;

  const raw = decodeBase64Url(data);
  if (!raw || raw.length !== 32) return null;
  return rawEd25519ToPem(raw);
}

async function withTimeout(promise, ms, label = "timeout") {
  if (!ms || ms <= 0) return await promise;
  return await Promise.race([
    promise,
    new Promise((_, rej) => setTimeout(() => rej(new Error(label)), ms)),
  ]);
}

async function getTxt(resolver, key) {
  const value = await withTimeout(resolver.getText(key), 6000, `ens_text_timeout:${key}`);
  return joinTxtFragments(value);
}

export function hasRpc() {
  return !!ETH_RPC_URL;
}

export async function fetchEnsSignerInfo({ refresh = false } = {}) {
  const now = Date.now();

  if (!refresh && ensCache.pem && now - ensCache.fetched_at < ensCache.ttl_ms) {
    return {
      ok: true,
      ...ensCache,
      ens_name: VERIFIER_ENS_NAME || null,
      cache: { ...ensCache },
    };
  }

  if (!VERIFIER_ENS_NAME) {
    ensCache = { ...ensCache, fetched_at: now, pem: null, error: "Missing VERIFIER_ENS_NAME", source: null };
    return { ok: false, ...ensCache, ens_name: null, cache: { ...ensCache } };
  }

  if (!ETH_RPC_URL) {
    ensCache = { ...ensCache, fetched_at: now, pem: null, error: "Missing ETH_RPC_URL", source: null };
    return { ok: false, ...ensCache, ens_name: VERIFIER_ENS_NAME, cache: { ...ensCache } };
  }

  try {
    const provider = new ethers.JsonRpcProvider(ETH_RPC_URL);
    const resolver = await withTimeout(provider.getResolver(VERIFIER_ENS_NAME), 6000, "ens_resolver_timeout");
    if (!resolver) throw new Error("No resolver for ENS name");

    const sigPubTxt = await getTxt(resolver, "cl.sig.pub");
    const sigSignerId = await getTxt(resolver, "cl.sig.signer_id");
    const receiptSignerId = await getTxt(resolver, "cl.receipt.signer_id");
    const sigKid = await getTxt(resolver, "cl.sig.kid");
    const sigCanonical = await getTxt(resolver, "cl.sig.canonical");

    let pem = parseSigPubToPem(sigPubTxt);
    let pubkey_source = pem ? "cl.sig.pub" : null;

    if (!pem) {
      const legacyPemTxt = await getTxt(resolver, LEGACY_PEM_KEY);
      pem = normalizePem(legacyPemTxt);
      if (pem) pubkey_source = LEGACY_PEM_KEY;
    }

    if (!pem) throw new Error("ENS TXT missing valid cl.sig.pub and fallback PEM key");

    const signer_id = sigSignerId || receiptSignerId || VERIFIER_ENS_NAME;

    ensCache = {
      ...ensCache,
      fetched_at: now,
      pem,
      signer_id,
      canonical: sigCanonical || null,
      kid: sigKid || null,
      pubkey_source,
      error: null,
      source: "ens",
    };

    return {
      ok: true,
      ...ensCache,
      ens_name: VERIFIER_ENS_NAME,
      cache: { ...ensCache },
    };
  } catch (e) {
    ensCache = {
      ...ensCache,
      fetched_at: now,
      pem: null,
      signer_id: null,
      canonical: null,
      kid: null,
      pubkey_source: null,
      error: e?.message || "ens fetch failed",
      source: null,
    };
    return { ok: false, ...ensCache, ens_name: VERIFIER_ENS_NAME, cache: { ...ensCache } };
  }
}

export async function fetchEnsPubkeyPem({ refresh = false } = {}) {
  const out = await fetchEnsSignerInfo({ refresh });
  return {
    ok: out.ok,
    pem: out.pem,
    source: out.source,
    ens_name: out.ens_name,
    txt_key: out.pubkey_source || LEGACY_PEM_KEY,
    signer_id: out.signer_id || null,
    canonical: out.canonical || null,
    kid: out.kid || null,
    error: out.error || null,
    cache: out.cache,
  };
}
