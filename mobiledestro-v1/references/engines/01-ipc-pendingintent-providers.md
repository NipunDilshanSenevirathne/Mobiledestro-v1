# Engine 01: IPC, PendingIntent, and providers

Research reviewed: 2026-10-13. Apply only to the authorized package, its declared test components, and synthetic data. The procedures below are Mobiledestro's testing design; platform facts are cited separately.

## Trust model

| Stage | Record |
| --- | --- |
| Entry | Exported activity, alias, receiver, bound service, provider, or legitimately obtained PendingIntent |
| Source | Calling UID and signature, action, extras, ClipData, URI, grant flags, Binder arguments |
| Transform | Unparceling, nested-intent extraction, URI decoding, path resolution, query assembly, asynchronous dispatch |
| Check | Component permission, caller identity, operation authorization, URI grant scope, argument allowlist |
| Sink | Internal component launch, privileged service operation, file descriptor, cursor, activity result, persistent state |

For every path distinguish an ordinary third-party app, shell UID, same-signature app, and instrumentation. A shell command is a discovery convenience; reproduce cross-app claims with a separate test APK that lacks the target's signature and privileged permissions.

## Source-backed platform facts

PendingIntents delegate the creator's authority for a defined operation; mutability concerns fields that a recipient can fill, while replay depends on lifecycle and one-shot semantics. A mutable token is not unrestricted authority by itself. [Android PendingIntent risks](https://developer.android.com/privacy-and-security/risks/pending-intent)

Providers can authorize access through component permissions or URI grants, including grants to otherwise unexported providers. Read, write, path, and general permissions must be resolved together. Older provider export defaults depend on both OS and target SDK. [Provider manifest reference](https://developer.android.com/guide/topics/manifest/provider-element)

Android 16 adds default intent-redirection hardening, with an explicit opt-out API. Validate actual behavior instead of assuming every nested-intent launch remains exploitable. [Intent redirection](https://developer.android.com/privacy-and-security/risks/intent-redirection)

## Decisive tests

1. Build a component table from the merged release manifest and runtime registration. Include aliases, enabled state, permission protection level, process, launch mode, and the code that actually handles incoming data.
2. Trace every externally supplied nested intent to its final destination. Compare an allowed internal test action with a harmless denied action. Record whether component, package, selector, data, ClipData, and grant flags survive sanitation. Observe the intended sink without disabling platform protections.
3. For Binder and Messenger, check caller validation before identity is cleared or work is moved to another thread. Invoke one read-only test operation from the separate APK. Compare the ordinary caller with an explicitly allowed caller.
4. Obtain a PendingIntent through the real feature being assessed. Do not synthesize possession through root. Change one fillable field, then test one legitimate replay on a reset lab state. Inspect token identity collisions, update/cancel behavior, user/account changes, and expiration.
5. Seed a provider with two harmless records and one sentinel file. Test authorized and unauthorized reads, path-boundary handling, projection/selection/sort constraints, and method-specific checks in `call`, `openFile`, `openAssetFile`, and batch entry points. Use a dry-run database clone for mutations.
6. For file handling, record canonical resolved paths and symlink policy; distinguish a path outside the intended share root from one merely containing unusual characters. Prove only access to the seeded sentinel.
7. Test activity-result delivery using the separate APK. Show that the returned value crosses the intended caller boundary; redacted screenshots alone do not establish result ownership.

## Negative controls and disqualifiers

- An exported component, normal permission, broad FileProvider root, unsafe-looking API, or application crash is a lead. Require a reachable sensitive operation or demonstrated boundary violation.
- A denied query, empty cursor, filtered row, exception, or legitimate user-approved grant does not prove unauthorized data access.
- A token captured only by instrumentation does not establish how another app obtains it.
- Compare identical requests with no grant, exact grant, unrelated URI, and revoked grant. Stop if a test would touch unrelated records.
- Missing `FLAG_ONE_SHOT` is not a flaw where repetition is intended and downstream authorization remains sound.

## Version and precondition caveats

Use Engine 09's matrix for target-SDK mutability requirements, implicit-intent restrictions, and background launches. Typed parcel APIs and StrictMode signals are useful evidence, not proofs of exploitability or complete protection. Record package visibility, managed-profile boundaries, caller foreground state, and any compatibility override.

## Chain edges and artifacts

Candidate edges: external caller to internal router; provider grant to sentinel file; result callback to session artifact; service operation to backend state. An edge is confirmed only when its output is usable by the next step under the same caller and state assumptions.

Save component and permission tables, caller APK hash/signature, manifest excerpts, source locations, before/after state, minimal invocation, UID observations, sanitized logs, grant lifetime, denied controls, and exact OS/target SDK. Route WebView sinks to Engine 02 and server effects to Engine 04.
