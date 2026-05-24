# Deprecated: CommandLayer Commercial Runtime

This repository is deprecated and should be treated as an archived historical source.

Commercial runtime and backend work has moved to the private `commandlayer/commercial` repo.

## Current direction

CommandLayer is consolidating around CLAS and verifiable action receipts.

Going forward:

- canonical CLAS/spec work lives in `commandlayer/clas`
- active SDK work lives in `commandlayer/agent-sdk`
- public verification/docs live in `commandlayer/commandlayer-org`
- private commercial/admin/payment/backend work lives in `commandlayer/commercial`
- execution/runtime infrastructure remains private until intentionally published

Do not use this repository as the active runtime for new CommandLayer integrations.

## Why this repo is being archived

This repository previously represented an experimental commercial runtime surface for commercial verbs, x402-oriented flows, and receipt verification behavior.

That public surface is being retired. Payment flows, admin operations, checkout/session creation, webhooks, card publication internals, and commercial execution rails are now private backend concerns.

This repository is retained only so older references and historical runtime experiments remain understandable.

## Historical scope

This repository previously contained or described:

- commercial verb HTTP routes
- x402-oriented execution envelopes
- checkout/purchase/ship/verify-style route experiments
- receipt signing and verification behavior for commercial flows
- frontend compatibility adapters for demos

New integrations should not target this runtime.

## Recommended path

Use the current CommandLayer repos instead:

- CLAS/spec: https://github.com/commandlayer/clas
- Agent SDK: https://github.com/commandlayer/agent-sdk
- Public verifier/docs: https://github.com/commandlayer/commandlayer-org
- VerifyAgent reference: https://github.com/commandlayer/verifyagent

Private commercial backend/runtime work remains in `commandlayer/commercial`.

## Status

- Repository status: deprecated / archive candidate
- New development: no
- New integrations: use CLAS + Agent SDK
- Commercial backend/runtime: private `commandlayer/commercial`
