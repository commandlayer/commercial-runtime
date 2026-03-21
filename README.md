# commercial-runtime

CommandLayer commercial runtime for the commercial verbs `authorize`, `checkout`, `purchase`, `ship`, and `verify`.

## Live HTTP surface

### Commercial verb routes

The live commercial verb surface is versioned at `v1.1.0`:

- `POST /authorize/v1.1.0`
- `POST /checkout/v1.1.0`
- `POST /purchase/v1.1.0`
- `POST /ship/v1.1.0`
- `POST /verify/v1.1.0`

### Receipt verification route

`POST /verify` is a separate receipt verification endpoint.

- `POST /verify/v1.1.0` = commercial business-flow `verify` verb
- `POST /verify` = receipt signature verification, with optional schema verification

The index (`GET /`) and health (`GET /health`) metadata report the runtime as service version `1.1.0` and API version `1.1.0` by default.

## Request contract

The runtime still accepts the full normalized commercial envelope:

```json
{
  "x402": {
    "verb": "authorize",
    "version": "1.1.0",
    "class": "commercial",
    "entry": "x402://authorizeagent.eth/authorize/v1.1.0"
  },
  "trace": {
    "trace_id": "trace_explicit",
    "parent_trace_id": "trace_parent"
  },
  "payload": {
    "buyer": "0xBEEF"
  }
}
```

For browser pages and demos, the runtime also accepts a compatibility input adapter:

```json
{
  "input": {
    "buyer": "0xBEEF",
    "chain_id": "eip155:84532",
    "amount": { "value": "0.0001", "currency": "ETH" },
    "payment_method": "demo"
  }
}
```

When the adapter is used, the runtime normalizes the request internally before schema validation and execution:

- `x402.verb` is derived from the matched route verb.
- `x402.version` defaults to `1.1.0`.
- `x402.class` remains `commercial`.
- `x402.entry` is built as `x402://<verb>agent.eth/<verb>/v1.1.0`.
- `trace.trace_id` is auto-generated if the caller did not supply one.
- `trace.parent_trace_id` is preserved when provided at the top level or inside `input`.
- `payload` is derived from `input`.

This adapter is only a frontend convenience layer. The internal commercial contract still uses explicit `x402`, `trace`, and `payload` fields.

## Commercial semantics kept intact

This change does **not** remove or replace commercial protocol behavior:

- x402 request semantics are still preserved internally.
- request schema validation is still enforced.
- receipt schema validation is still enforced.
- receipt signing is still enforced.
- receipt verification remains available at `POST /verify`.
- CORS headers remain enabled for browser callers.

## Configuration

Environment defaults:

- `SERVICE_VERSION=1.1.0`
- `API_VERSION=1.1.0`
- `SCHEMA_VERSION` defaults to `API_VERSION`

## Checks

- `npm run contract-check`
- `node --test test/commercial-runtime.test.mjs`
