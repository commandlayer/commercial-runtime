export function normalizeProtocolRequest(body) {
  return {
    x402: body?.x402 ?? null,
    trace: body?.trace ?? null,
    payload: body?.payload ?? body?.input ?? null,
  };
}
