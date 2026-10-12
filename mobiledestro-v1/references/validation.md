# Validation, severity and evidence

## Five result states

- `hypothesis`: plausible path with an unresolved link or invariant.
- `static-supported`: code and control-flow support a defect, with runtime assumptions stated.
- `dynamic-confirmed`: the claimed attacker behavior and impact were reproduced with discriminating controls and a clean replay.
- `refuted`: evidence contradicts the claim in the tested context; record why.
- `blocked`: a concrete missing dependency prevents the next meaningful test.

A missing tool is not a negative test. A scanner alert is not static support by itself. A crash is not code execution. A response status code is not a cross-account data oracle.

## Minimal experimental design

Before execution write the invariant, independent variable, fixed state, attacker capabilities, expected allowed result, expected forbidden result, positive oracle, negative control, and cleanup action. Use deterministic synthetic markers.

For an object-authorization test create distinct objects under owned accounts A and B. Establish correct ownership and baseline access first. Change only the principal/object relationship. Verify the returned canary and actual object state, not body length or HTTP 200. Try the forbidden direction separately; symmetry is not guaranteed. Do not enumerate unrelated user IDs.

For a WebView/IPC test record the external app UID, component resolution, permissions, link verification, exact WebView instance/origin, and which method sees the input. ADB shell can have privileges an ordinary app lacks; use a minimal ordinary companion app where this distinction matters.

For client-authentication bypass distinguish changing a screen from access to a protected operation. Trace key usage or the resulting backend request. Record both instrumentation-enabled and unmodified behavior. A hook that replaces a failed authorization result is not evidence that a normal attacker can perform the same transition.

For native failures minimize the input, preserve its hash, symbolize the stack with the exact library build, and demonstrate app-level reachability. Record sanitizer/release differences. Establish impact separately from crash uniqueness.

## Evidence packet

Store a restricted raw packet and a redacted review packet. Include build identity, test-account aliases, exact test setup, command/tool versions, request and response structure, environment, timestamp, positive and negative observations, clean replay, root-cause citations, cleanup, and remediation. Redaction must preserve the object relationship and causal sequence.

Hash files after capture and preserve originals. The core helper verifies relative paths and content hashes for ledger evidence. Hashes prove content consistency, not that the content is truthful or that a claim follows from it. Human/agent semantic review is required.

If a positive, negative-control, or clean-replay artifact is absent or changed, the report helper downgrades a dynamic claim. A staged or replayed synthetic fixture demonstrates the helper only and must never be presented as a real app finding.

## Severity and standards

Assign severity after reachability, required privileges, interaction, affected data/actions, persistence, scope, and realistic impact are established. If a CVSS vector is used, state its version, every metric rationale, and calculation source; do not improvise a numeric score. Business priority may differ from technical severity and should be labeled separately.

Use MASVS for control groups, MASWE for weaknesses, and MASTG for verification methods. The [MASTG test index](https://mas.owasp.org/MASTG/tests/) now contains current and deprecated entries, so verify status and exact applicability rather than hardcoding old IDs. Review date: 2026-10-13. These mappings organize evidence; they do not certify compliance or prove coverage.

## Regression and final challenge

Reproduce the failing case and a benign control against the fix using the same attacker model. Check adjacent canonicalization, session, tenant, lifecycle, and API-version paths. If no patched build exists, propose a precise regression test and mark it unexecuted.

The final reviewer must ask: did the experiment require tester-only privilege, silently change principal, omit a server check, use stale evidence, mistake shared content for private data, or assume an unknown graph binding? Unresolved answers lower confidence or split the report into demonstrated and hypothetical portions.
