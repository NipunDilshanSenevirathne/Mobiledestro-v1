# Engine 04: Transport, APIs, and business logic

Research reviewed: 2026-10-13. Backend scope is independent of APK scope. Use explicitly authorized hosts, two owned accounts, seeded records, fixed request budgets, and reversible staging operations. Do not infer authorization from an endpoint appearing in the app.

## Trust model

| Stage | Record |
| --- | --- |
| Entry | Mobile request, synchronization, upload, GraphQL operation, WebSocket message, webhook registration |
| Source | Token, object ID, tenant, role, field, price/quantity, sequence number, idempotency key |
| Transform | Serialization, signing, canonicalization, gateway rewrite, resolver, background job |
| Check | TLS identity, authenticated principal, object/field/function policy, state transition, atomicity |
| Sink | Record disclosure, state change, entitlement, payment simulation, export, notification |

Define an oracle before sending a mutation: a known seeded value, independent read-back, test audit event, or documented business invariant. HTTP success alone is insufficient.

## Source-backed facts

Android network-security configuration can express trust anchors, cleartext policy, and debug-only overrides. Test the effective configuration for the exact domain and distributed build. [Network security configuration](https://developer.android.com/privacy-and-security/security-config)

Object authorization governs whether a principal may operate on a specific record, while property authorization governs exposed or writable fields. Neither can be established from object-ID unpredictability alone. [OWASP API1](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/), [OWASP API3](https://api-security.owasp.org/editions/2023/en/0xa3-broken-object-property-level-authorization/)

Business-sensitive flows need rules beyond ordinary endpoint access. Explicit state transitions and atomic enforcement are central to preventing invalid sequences and races. [OWASP API6](https://api-security.owasp.org/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/), [Business logic guidance](https://cheatsheetseries.owasp.org/cheatsheets/Business_Logic_Security_Cheat_Sheet.html)

## Decisive tests

1. Map actual mobile operations to endpoint, method, serializer, principal, object, role, and transition. Include legacy versions only when their hosts and paths are authorized. Inspect native/framework network stacks as well as Java clients.
2. Establish baseline A-to-A and B-to-B access using unique synthetic markers. Test A-to-B and B-to-A for one known object each, then anonymous access if permitted. Preserve every credential location, including cookies, headers, and query tokens; do not accidentally retain B's authority in A's request.
3. For field and function policy, choose one harmless restricted field or staging operation. Verify whether the server ignores, rejects, or persists it through independent read-back. Inspect GraphQL nested resolvers, batch wrappers, and subscription filters for the same policy.
4. Model a transaction as states and allowed transitions. Compare normal order with one skipped, duplicated, replayed, expired, or reversed step. Use a fake inventory, payment sandbox, or disposable entitlement with no real financial effect.
5. For race hypotheses, first prove a check/use separation in code or traces. In an approved local/staging fixture, use a single bounded pair of requests, then compare to sequential controls. Record committed effects, not timing alone. Stop on the first violated invariant.
6. Test transport using an owned endpoint and an untrusted test certificate without trust-bypassing hooks. Capture which connection succeeds and what data crosses it. If instrumentation is required solely to observe API traffic, label that setup separately from the transport finding.
7. Test server fetches or importers only against an owned benign destination. Do not probe metadata services, internal address ranges, or unrelated infrastructure. Trace redirects and destination policy without using them to expand scope.
8. Compare offline queue replay and reconnect with fresh authorization; transfer account-switch or stale-work findings to Engine 09.

## Negative controls and disqualifiers

- A `200`, different body length, public object, intentionally shared tenant resource, predictable ID, or client-visible role flag does not prove BOLA.
- Missing certificate pinning and successful pinning bypass are not transport vulnerabilities by themselves.
- Cached responses, eventual consistency, stale tokens, request signing failures, and proxy cookie contamination can imitate authorization results.
- Client-calculated prices are harmless if the server recomputes them. A duplicated response is harmless if only one committed effect exists.
- Do not infer missing rate limits from a small sample; document an untested policy question instead of increasing volume.

## Version and precondition caveats

Record release build, API version, tenant policy, feature flags, token scopes, gateway, server build if known, cache headers, test environment, and transport stack. Confirm whether debug CAs or modified trust stores altered results. Native and cross-platform stacks may not follow every Java network setting.

## Chain edges and artifacts

Candidate edges: mobile disclosure to usable session; object access to unauthorized property; stale approval to invalid transition; queue replay to cross-account effect. Link each to one independently observed server outcome.

Save a redacted request inventory, principal/object/operation matrix, seeded-data map, policy statement, raw response hashes, canonical response diff, commit oracle, sequence diagram, timing for bounded race tests, controls, and cleanup verification.
