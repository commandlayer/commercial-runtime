import crypto from "crypto";

import { API_VERSION_DEFAULT, COMMERCIAL_CLASS, buildCommercialEntry } from "../runtime-version.mjs";

function randId(prefix = "trace_") {
  return prefix + crypto.randomBytes(6).toString("hex");
}

function nonEmptyString(value) {
  return typeof value === "string" && value.trim().length ? value.trim() : null;
}

function stripCompatibilityTraceFields(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) return input ?? null;
  const payload = { ...input };
  delete payload.trace_id;
  delete payload.parent_trace_id;
  return payload;
}

export function normalizeProtocolRequest(body, { verb, apiVersion = API_VERSION_DEFAULT } = {}) {
  const hasNormalizedEnvelope = body?.x402 != null || body?.trace != null || body?.payload != null;
  if (hasNormalizedEnvelope) {
    return {
      x402: body?.x402 ?? null,
      trace: body?.trace ?? null,
      payload: body?.payload ?? body?.input ?? null,
    };
  }

  if (body?.input != null) {
    const input = body.input;
    const topLevelParent = nonEmptyString(body?.parent_trace_id);
    const inputParent = nonEmptyString(input?.parent_trace_id);
    const parentTraceId = topLevelParent ?? inputParent;
    const traceId = nonEmptyString(body?.trace_id) ?? nonEmptyString(input?.trace_id) ?? randId("trace_");

    return {
      x402: {
        verb,
        version: apiVersion,
        class: COMMERCIAL_CLASS,
        entry: buildCommercialEntry(verb, apiVersion),
      },
      trace: {
        trace_id: traceId,
        ...(parentTraceId ? { parent_trace_id: parentTraceId } : {}),
      },
      payload: stripCompatibilityTraceFields(input),
    };
  }

  return { x402: null, trace: null, payload: null };
}
