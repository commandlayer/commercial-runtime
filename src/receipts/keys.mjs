import crypto from "crypto";

const ED25519_SPKI_PREFIX_HEX = "302a300506032b6570032100";

export function pemFromB64(b64) {
  if (!b64 || typeof b64 !== "string") return null;
  const cleaned = b64.replace(/\s+/g, "");
  if (!cleaned) return null;
  const pem = Buffer.from(cleaned, "base64").toString("utf8");
  return pem.includes("BEGIN") ? pem : null;
}

export function publicKeyFromRawB64(b64) {
  if (!b64 || typeof b64 !== "string") throw new Error("missing raw public key base64");
  const cleaned = b64.replace(/\s+/g, "");
  if (!cleaned) throw new Error("missing raw public key base64");

  const raw = Buffer.from(cleaned, "base64");
  if (raw.length !== 32) {
    throw new Error(`raw Ed25519 public key must decode to 32 bytes (got ${raw.length})`);
  }

  const spkiDerBuffer = Buffer.concat([Buffer.from(ED25519_SPKI_PREFIX_HEX, "hex"), raw]);
  return crypto.createPublicKey({
    key: spkiDerBuffer,
    format: "der",
    type: "spki",
  });
}

export function getPublicKeyObject() {
  const pemB64 = process.env.RECEIPT_SIGNING_PUBLIC_KEY_PEM_B64 || "";
  if (pemB64) {
    const pem = pemFromB64(pemB64);
    if (!pem) throw new Error("decoded public key missing PEM header");
    return crypto.createPublicKey(pem);
  }

  const rawB64 = process.env.RECEIPT_SIGNING_PUBLIC_KEY_B64 || "";
  if (rawB64) return publicKeyFromRawB64(rawB64);

  throw new Error("missing RECEIPT_SIGNING_PUBLIC_KEY_PEM_B64 or RECEIPT_SIGNING_PUBLIC_KEY_B64");
}

export function getPublicKeySource() {
  if (process.env.RECEIPT_SIGNING_PUBLIC_KEY_PEM_B64) return "env-pem-b64";
  if (process.env.RECEIPT_SIGNING_PUBLIC_KEY_B64) return "env-raw-b64";
  return null;
}
