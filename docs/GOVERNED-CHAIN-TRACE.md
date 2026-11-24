# Governed chain-trace operations

ChineScan exposes two engagement-scoped chain-trace operations through the existing durable execution worker. The standalone `chain trace` command and legacy web job API remain separate and do not gain engagement provenance.

## Local import analysis

Use the existing governed log-evidence registration flow to register a CSV or JSON explorer export from an operator-allowed local source. The governed `chain-engagement --operation import` command then binds the evidence snapshot, selected chain, normalized seed address, depth, authorization context, and request digest to one durable job. The snapshot must contain exactly one CSV or JSON file. Each imported row must name the selected chain and contain valid chain-specific transaction and address identifiers. Invalid or mismatched input fails closed. The worker verifies the registered snapshot and does not resolve a live source path.

Local import analysis is passive and does not perform network access or consume an approval. The source data remains an operator-supplied claim about a chain; syntax validation does not independently prove that the source originated from that network.

## Configured provider lookup

Provider lookup supports only the built-in Etherscan V2 endpoint for built-in EVM chains. A `chain_address` target has the canonical form `chain:<chain>:etherscan-v2:<address>`. Arbitrary RPC endpoints, provider URLs, chains, and caller parameters are rejected. Provider lookup is classified as sensitive and requires an existing one-use approval bound to the policy operation. Approval is consumed by the worker immediately before each outbound request, after policy revalidation. The trace is limited to the registered root address; it does not follow discovered recipients as new external lookup targets.

The API key is read from the existing `CHINESCAN_ETHERSCAN_KEY` environment variable and is never returned in job results. Requests use the existing provider transport, HTTPS host allowlist, response bounds, timeout, and redirect protections. Automated tests inject a fake transport and perform no external requests.

## Results and limits

The existing chain-trace service stores scans, findings, and graph records. When called by the governed worker, scan and finding records receive the established job provenance and tenant ownership; graphs are linked by scan ID and inherit tenant ownership. Provider-reported information remains provider data and heuristic findings are not proof of attribution. Cancellation is cooperative at wallet boundaries and is also checked before each provider request. A request already in flight may run until the configured transport timeout.

Standalone chain-trace behavior is unchanged. Neither standalone jobs nor any other CLI scan path is implicitly governed by these operations.
