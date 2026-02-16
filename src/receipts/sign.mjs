import crypto from "crypto";

function stableStringify(value) {
  const seen = new WeakSet();
  const helper = (v) => {
    if (v === null || typeof v !== "object") return v;
    if (seen.has(v)) return "[Circular]";
    seen.add(v);
    if (Array.isArray(v)) return v.map(helper);
    const out = {};
    for (const k of Object.keys(v).sort()) out[k] = helper(v[k]);
    return out;
  };
  return JSON.stringify(helper(value));
}

function sha256Hex(str) {
  return crypto.createHash("sha256").update(str).digest("hex");
}

function pemFromB64(b64) {
  if (!b64) return null;
  const pem = Buffer.from(b64, "base64").toString("utf8");
  return pem.includes("BEGIN") ? pem : null;
}

function signEd25519Base64(messageUtf8) {
  const pem = pemFromB64(process.env.RECEIPT_SIGNING_PRIVATE_KEY_PEM_B64 || "");
  if (!pem) throw new Error("Missing RECEIPT_SIGNING_PRIVATE_KEY_PEM_B64");
  const key = crypto.createPrivateKey(pem);
  const sig = crypto.sign(null, Buffer.from(messageUtf8, "utf8"), key);
  return sig.toString("base64");
}

function verifyEd25519Base64(messageUtf8, signatureB64, pubPem) {
  const key = crypto.createPublicKey(pubPem);
  return crypto.verify(null, Buffer.from(messageUtf8, "utf8"), key, Buffer.from(signatureB64, "base64"));
}

export function makeReceipt({ signer_id, x402, trace, result, status = "success", error = null, actor = null, metadata_patch = null } = {}) {
  const unsigned = buildUnsignedReceipt({ signer_id, x402, trace, result, status, error, actor, metadata_patch });
  return signUnsignedReceipt(unsigned);
}

export function buildUnsignedReceipt({
  signer_id,
  x402,
  trace,
  result,
  status = "success",
  error = null,
  actor = null,
  metadata_patch = null,
} = {}) {
  return {
    status,
    x402,
    trace,
    ...(error ? { error } : {}),
    ...(status === "success" ? { result } : {}),
    metadata: {
      ...(actor ? { actor } : {}),
      ...(metadata_patch && typeof metadata_patch === "object" ? metadata_patch : {}),
      proof: {
        alg: "ed25519-sha256",
        canonical: "json-stringify",
        signer_id: signer_id || "runtime",
        hash_sha256: null,
        signature_b64: null,
      },
      receipt_id: "",
    },
  };
}

export function signUnsignedReceipt(unsignedReceipt) {
  const receipt = structuredClone(unsignedReceipt);
  const unsigned = structuredClone(unsignedReceipt);

  if (!unsigned?.metadata?.proof) throw new Error("unsigned receipt missing metadata.proof");
  unsigned.metadata.proof.hash_sha256 = "";
  unsigned.metadata.proof.signature_b64 = "";
  if (unsigned?.metadata) unsigned.metadata.receipt_id = "";

  const canonical = stableStringify(unsigned);
  const hash = sha256Hex(canonical);
  const sigB64 = signEd25519Base64(hash);

  receipt.metadata.proof.hash_sha256 = hash;
  receipt.metadata.proof.signature_b64 = sigB64;
  receipt.metadata.receipt_id = hash;

  return receipt;
}

makeReceipt.verify = async function verify({ receipt, wantEns = false, refresh = false } = {}) {
  const proof = receipt?.metadata?.proof;
  if (!proof?.signature_b64 || !proof?.hash_sha256) {
    return { ok: false, http_status: 400, error: "missing metadata.proof.signature_b64 or hash_sha256" };
  }

  const unsigned = structuredClone(receipt);
  unsigned.metadata.proof.hash_sha256 = "";
  unsigned.metadata.proof.signature_b64 = "";
  if (unsigned?.metadata) unsigned.metadata.receipt_id = "";
  const canonical = stableStringify(unsigned);
  const recomputed = sha256Hex(canonical);
  const hashMatches = recomputed === proof.hash_sha256;

  let pubPem = pemFromB64(process.env.RECEIPT_SIGNING_PUBLIC_KEY_PEM_B64 || "");
  let pubSrc = pubPem ? "env-b64" : null;

  let ensMeta = null;
  if (wantEns) {
    const { fetchEnsSignerInfo } = await import("./ens.mjs");
    const ensOut = await fetchEnsSignerInfo({ refresh });
    if (ensOut.ok && ensOut.pem) {
      pubPem = ensOut.pem;
      pubSrc = `ens:${ensOut.pubkey_source || "unknown"}`;
      ensMeta = ensOut;
    }
  }

  if (!pubPem) {
    return {
      ok: false,
      http_status: 400,
      checks: { hash_matches: hashMatches, signature_valid: false },
      values: { recomputed_hash: recomputed, pubkey_source: pubSrc },
      error: "no public key available (set RECEIPT_SIGNING_PUBLIC_KEY_PEM_B64 or use ens=1)",
    };
  }

  let sigOk = false;
  let sigErr = null;
  try {
    sigOk = verifyEd25519Base64(proof.hash_sha256, proof.signature_b64, pubPem);
  } catch (e) {
    sigOk = false;
    sigErr = e?.message || "signature verify failed";
  }

  let canonicalOk = true;
  let canonicalErr = null;
  if (ensMeta?.canonical) {
    canonicalOk = String(proof?.canonical || "") === String(ensMeta.canonical);
    if (!canonicalOk) canonicalErr = `canonical mismatch: receipt=${proof?.canonical || null} ens=${ensMeta.canonical}`;
  }

  let signerIdOk = true;
  let signerIdErr = null;
  if (ensMeta?.signer_id) {
    signerIdOk = String(proof?.signer_id || "") === String(ensMeta.signer_id);
    if (!signerIdOk) signerIdErr = `signer_id mismatch: receipt=${proof?.signer_id || null} ens=${ensMeta.signer_id}`;
  }

  let kidOk = true;
  let kidErr = null;
  if (ensMeta?.kid && proof?.kid) {
    kidOk = String(proof.kid) === String(ensMeta.kid);
    if (!kidOk) kidErr = `kid mismatch: receipt=${proof.kid} ens=${ensMeta.kid}`;
  }

  const allOk = hashMatches && sigOk && canonicalOk && signerIdOk && kidOk;

  return {
    ok: allOk,
    http_status: allOk ? 200 : 400,
    checks: {
      hash_matches: hashMatches,
      signature_valid: sigOk,
      canonical_valid: canonicalOk,
      signer_id_valid: signerIdOk,
      kid_valid: kidOk,
    },
    values: {
      recomputed_hash: recomputed,
      pubkey_source: pubSrc,
      ens_signer_id: ensMeta?.signer_id || null,
      ens_canonical: ensMeta?.canonical || null,
      ens_kid: ensMeta?.kid || null,
    },
    errors: {
      signature_error: sigErr,
      canonical_error: canonicalErr,
      signer_id_error: signerIdErr,
      kid_error: kidErr,
      ens_error: wantEns && !ensMeta ? "ens key unavailable" : null,
    },
  };
};
