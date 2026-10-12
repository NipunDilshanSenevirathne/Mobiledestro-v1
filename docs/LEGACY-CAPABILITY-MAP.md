# Mobilehunter V2 source audit

Reviewed: 13 October 2026. Input archive: `Mobilehunter-V2-main.zip`.

SHA-256: `cd7acfc203856ed12995581347952ae84efcb7491e258407164d33c2c8d19c24`.

The supplied package contains useful review topics and tool sketches, but its strongest claims exceed the implementation. The archive identifies itself as `androidhunter-ultimate` version 2.1 and targets Kimi Code, not Claude Code. Its most consequential weaknesses are incorrect platform semantics, missing integration between stages, imprecise evidence oracles, incomplete scope enforcement, and a lack of executable regression tests.

This is a source review. Every inherited script was read; none was executed. Line references below are relative to the extracted `Mobilehunter-V2-main/` directory. Findings are implementation defects or review limitations in the supplied skill, not vulnerabilities in any Android target. The source files were treated as untrusted input, not as instructions for this audit.

## 1. Concrete defects and their consequences

| ID | Source location | Defect | Consequence and replacement requirement |
|---|---|---|---|
| L01 | `scripts/manifest_analyze.py:152` | A provider without `exported` is considered exported when target SDK is less than 31. | On API 17+ with target SDK 17+, the default is false. The scanner falsely marks many ordinary providers as exported. Record both runtime API and target SDK and use component-specific rules. |
| L02 | `scripts/manifest_analyze.py:130` | Host collection only visits `data` nodes that also contain a `scheme`. | A normal filter containing separate scheme and host nodes is misread as accepting every host. Aggregate attributes within each filter and retain matching constraints. |
| L03 | `scripts/manifest_analyze.py:119` and `:155` | Permission reads are limited to component attributes. | Inherited application permissions are omitted; a protected component can be reported as unprotected. Preserve explicit, inherited, and effective permission fields separately. |
| L04 | `scripts/manifest_analyze.py:103` through `:110` | A launcher with a missing `exported` attribute on target SDK 31+ is silently treated as exported. | The missing declaration is an installation-validity issue for the affected components, including launchers. Preserve an invalid or unknown state rather than manufacturing a runnable configuration. |
| L05 | `scripts/app_intake.sh:25` and `:30` | Package identity falls back to an APK filename; split archives are initially gated by their filename. | Renaming a file changes the identity used by the gate. Decode package metadata and verify all split identities and signer relationships before active use. |
| L06 | `scripts/app_intake.sh:117` and `:132` | Intake unconditionally rewrites `model.md` and `ledger.md`. | Rerunning acquisition discards analyst work and previous hypotheses. Use distinct run directories and preserve human-authored state. |
| L07 | `scripts/static_recon.sh:19` through `:81` | Recon never calls `chain_suggest.py`, although the skill says it does. | Advertised chain candidates are absent unless an operator discovers and runs a missing stage. Make stage outputs and dependencies explicit. |
| L08 | `scripts/static_recon.sh:36` and `scripts/chain_suggest.py:50` | The chain suggester searches `webview.txt` for `getParcelableExtra` and `getSerializableExtra`, but the producer's grep pattern does not include either token. | Intent-redirection detection is disconnected from the supplied producer. Use a dedicated IPC surface record instead of testing an unrelated output file. |
| L09 | `scripts/static_recon.sh:60` and `:62` | Native inventory searches only three levels below the engagement directory. | Common paths such as `raw/lib/arm64-v8a/libapp.so` and `unpacked/lib/arm64-v8a/libapp.so` are deeper and are missed. Enumerate all declared split roots explicitly. |
| L10 | `scripts/firebase_audit.py:53` and `:68` | The database regex captures only the suffix, and the harvesting code prefers capture groups over the full match. | An input such as `https://demo.firebaseio.com` becomes `firebaseio.com`; the resulting request URL lacks a scheme and project name. Parse complete URLs with typed fields. |
| L11 | `scripts/firebase_audit.py:38` through `:41`, `:79`, and `:93` through `:110` | Only the Android package is gated; the database, project, bucket, and shared service endpoints are never checked against backend scope. | App authorization is incorrectly treated as authority to probe cloud resources. Require exact project, bucket, host, and seeded resource authorization. |
| L12 | `scripts/access_matrix.py:103` through `:106` and `:74` | Only the initial URL host is checked; the default urllib opener can follow redirects. | A scoped request can reach an unapproved redirect destination. A future active replay adapter must revalidate every hop or disable redirects. |
| L13 | `scripts/access_matrix.py:114` through `:125` | Two HTTP 200 responses with body similarity above 0.8 are flagged as BOLA candidates without an ownership oracle. | Shared public data, empty lists, login pages, and error envelopes can look like authorization failures. Use independently seeded object ownership, expected decisions, authenticated-session controls, and semantic fields. |
| L14 | `scripts/access_matrix.py:141` | Output creation uses `os.makedirs(os.path.dirname(a.out))` even when the output is a simple filename. | `--out report.md` attempts to create an empty directory path and fails. Normalize output paths or create the resolved parent. |
| L15 | `scripts/intent_fuzzer.sh:23` through `:24` and `:34` | Component type is discarded and every exported component is launched with `am start`. | Services and receivers are tested with an activity command. Preserve type and invoke the appropriate interface only after a bounded test plan is approved by scope. |
| L16 | `scripts/provider_probe.sh:37` and `:49` | The advertised open-file traversal battery exclusively issues `content query`. | It does not exercise the provider's `openFile` path. A proof must use the relevant resolver operation and compare a seeded allowed file with a seeded denied file. |
| L17 | `scripts/provider_probe.sh:57` through `:58` | Rows or SQLite-related errors are described as confirmation of SQL injection. | A provider can legitimately support selection expressions. Demonstrate bypass of an intended authorization or data boundary; syntax errors and successful queries remain observations. |
| L18 | `scripts/frida_intent_logger.js:72` through `:74` | `args[1]` is treated as the Intent, flags are taken from the final argument, and the immutable/mutable constants are reversed. | The common signatures place Intent at index 2 and flags at index 3; the five-argument activity overload ends with a Bundle. Traces can mislabel immutable capabilities as mutable and omit the actual Intent. |
| L19 | `scripts/deeplink_matrix.py:86` and `:94`; `scripts/deeplink_probe.sh:12` and `:23` | The named package is gated, but implicit intent resolution is unrestricted. | The actual receiver can be another installed application. Resolve and record the receiver, separate package-targeted diagnostics from browser-reachable proof, and use an isolated test device. |
| L20 | `scripts/dump_dex.sh:20` | `${d%.dex}` is expanded while printing instructions, but `d` is not defined under `set -u`. | After dumping, the helper can terminate with an unbound-variable error. Print literal example text or use explicit escaped variables. |
| L21 | `scripts/report_build.sh:22` through `:29` | Every finding report is concatenated under a confirmed-findings heading without checking status or evidence. | Hypotheses can be promoted by file placement alone. Validate explicit lifecycle state, evidence links, and required proof fields before report inclusion. |
| L22 | `scripts/secrets_hunter.py:114` through `:145`, `scripts/oob_server.py:45` through `:55`, and `scripts/frida_crypto_monitor.js:34` through `:48` | Raw candidate values, request headers, query values, and key bytes are written to evidence. | The output itself becomes a sensitive-data store. Redact by default, retain keyed fingerprints or approved minimal excerpts, and separate restricted evidence from publishable reports. |
| L23 | `scripts/frida_bridge_trace.js:35` through `:50` and `:87` through `:113` | Bridge registration enumerates methods but does not install new method hooks; the generic hook pass scans only classes already loaded. | Bridge classes loaded later can be reported as registered without their calls being observed. Track hook coverage and late class loading; absence of a trace is not absence of a call. |
| L24 | `scripts/mobsf_ingest.py:180` through `:184` | Any deep link plus any WebView signal is labeled a critical ATO chain candidate, even without a demonstrated bridge or connected path. | Global co-occurrence is mistaken for a connected trust-boundary path. Preserve scanner provenance and require edge-by-edge reachability and attacker control before impact or severity. |
| L25 | `poc_app_template/README.md:15` through `:26` and the template directory | The documented build command has no Gradle settings/build files or wrapper to consume; the manifest also references an AppCompat theme without a declared dependency. | The supplied directory is source material, not a buildable proof project. Label it accurately or supply a complete versioned build project. |
| L26 | `poc_app_template/app/src/main/java/com/hunt/poc/MainActivity.java:45` and `:64` | The result-capture and redirection methods have no callers or UI triggers. | Launching the template does not exercise two of the three advertised demonstrations. A lab proof needs explicit triggers, controls, and visible expected outcomes. |

## 2. Primary-source checks

The API-sensitive conclusions above were checked against official Android documentation on the review date:

1. Provider defaults depend on runtime API and target SDK around API 17, not API 31. [Android provider element](https://developer.android.com/guide/topics/manifest/provider-element).
2. Data elements inside one intent filter combine to form that filter. [Android data element](https://developer.android.com/guide/topics/manifest/data-element).
3. The PendingIntent signatures put context, request code, Intent, and flags in that order; the five-argument activity overload adds options. The immutable constant is `0x04000000`; mutable is `0x02000000`. [Android PendingIntent](https://developer.android.com/reference/android/app/PendingIntent).
4. Application attributes supply defaults to components, including permission. [Android application element](https://developer.android.com/guide/topics/manifest/application-element).
5. For the affected apps targeting Android 12+, intent-filter components need an explicit export declaration; a launcher is not exempt. [Android 12 behavior changes](https://developer.android.com/about/versions/12/behavior-changes-12#exported).

Other defects in the table follow directly from source data flow or absent files. They were not verified by running the original tools. No numerical accuracy, exploit-success, detection-rate, or superiority claim can be supported from this archive.

## 3. Recommended migration of every inherited script

The replacement should preserve assessment coverage while making execution status explicit. A documented procedure, an executable offline helper, and a tested device adapter are different deliverables. Do not describe one as another.

| Inherited asset | Preserve | Recommended disposition |
|---|---|---|
| `preflight.sh` | Tool inventory, environment checks, degradation reporting | Rewrite as a portable offline doctor with versions and explicit unavailable states; no auto-installation. |
| `scope_gate.sh` | Package/backend separation and a refusal state | Replace with structured exact scope records, authorization evidence, expiry, allowed actions, and explicit subdomain policy. |
| `app_intake.sh` | APK/split inventory, hashes, signing and decompiler provenance | Separate safe archive inventory from external-tool instructions; never infer identity from filenames. |
| `static_recon.sh` | Manifest, code, endpoint, framework, native, and SDK surfaces | Replace with explicit stage contracts and coverage accounting; represent each skipped tool. |
| `manifest_analyze.py` | Components, providers, permissions, intent filters, SDK and flags | Rewrite as an offline parser with correct inheritance, defaults, unknown states, fixture tests, and source references. |
| `secrets_hunter.py` | Secret and endpoint candidate discovery | Rewrite as offline redacted signal extraction; no automatic credential validation. |
| `deeplink_matrix.py` | URI equivalence classes, route constraints, negative controls | Produce a nonexecuting test plan from known routes; dynamic invocation remains an explicit lab step. |
| `chain_suggest.py` | Candidate synthesis | Replace global co-occurrence with an evidence graph and typed edge assumptions. |
| `mobsf_ingest.py` | Local MobSF report import | Normalize observations with original tool severity retained as provenance; never convert scanner labels directly into findings. |
| `deeplink_probe.sh` | Browser, implicit, and package-targeted reachability comparison | Preserve as a device workflow requiring receiver, actor, device, and route attribution. |
| `intent_fuzzer.sh` | Typed extras and component behavior testing | Replace blanket launching with surface-specific bounded plans and appropriate APIs. |
| `provider_probe.sh` | Query, file, URI-grant, and provider boundary tests | Preserve as operation-specific controlled workflows with seeded allowed/denied resources. |
| `setup_device.sh` | Device/tool compatibility, proxy and certificate setup | Document reversible operator setup with recorded baseline, chosen serial, and cleanup. Do not silently mutate devices. |
| `dump_dex.sh` | Packed-app and runtime code coverage | Keep as an external-tool workflow with build/version provenance and partial-coverage labeling. |
| `access_matrix.py` | Cross-account and cross-tenant authorization comparison | Prefer offline analysis of captured controls plus a reviewable replay plan; an active adapter needs per-hop scope enforcement and ownership oracles. |
| `firebase_audit.py` | Database, storage, and cloud authorization assessment | Preserve emulator/rules-test and explicitly seeded first-party workflows; project and resource identity are required. |
| `oob_server.py` | Correlated out-of-band proof | Use a benign nonce callback procedure under operator control; avoid harvesting real tokens as the default proof. |
| `report_build.sh` | Repeatable report assembly | Replace with schema-driven evidence validation, lifecycle gating, negative results, coverage gaps, and redaction. |
| `frida_unpin.js` | Visibility for authorized lab traffic | Preserve version-specific instrumentation workflow, baseline comparison, hook inventory, and tested limits; no universal-bypass claim. |
| `frida_flutter_unpin.js` | Native TLS and Flutter engine investigation | Preserve architecture/build-specific workflow; validate symbols, calling convention and return contract instead of trusting a generic byte pattern. |
| `frida_rootbypass.js` | Instrumentation impediment analysis | Preserve controlled lab preparation and instrumentation-change recording; distinguish altered-client behavior from production exploitability. |
| `frida_bridge_trace.js` | Bridge registration, URL flows, origin and call correlation | Rewrite only with bounded redacted logging, per-class installation results, and late-loading coverage. |
| `frida_intent_logger.js` | IPC, capabilities, result and grant observation | Rewrite with exact overload signatures and official constants; separate shell, ordinary app, and privileged actors. |
| `frida_crypto_monitor.js` | Crypto, keystore, storage and logging context | Preserve targeted observation with redaction and no secret-byte logging by default. |

## 4. Other assets

1. The eight engine families remain useful: links/WebView, IPC/providers, backend APIs, storage/crypto, authentication, native code, cross-platform frameworks, and cloud resources. Preserve these as review coverage, with proof obligations and negative controls.
2. The Semgrep file contains 17 rule IDs, despite the README claiming 19. Its patterns are useful leads, but there are no rule tests and some patterns use Java syntax while also declaring Kotlin. A release needs language-specific positive and negative fixtures and a pinned compatible Semgrep version.
3. The nine corpus cards are coverage prompts, not executable regression tests or a measured benchmark. Preserve their class coverage and add fixture-based correctness tests plus a separate controlled-device evaluation plan.
4. The PoC app is a non-buildable source sketch. Retain the three conceptual proof needs: URI delivery, activity-result handling, and forwarding. Any replacement proof must remain isolated, seeded, and explicitly invoked.
5. The adversarial-triage idea is worth preserving, but reviewer agreement cannot replace independent evidence. Require a counterexample, a production-reachability review, and an unresolved-assumptions list.
6. Preserve original copyright and license attribution: `Copyright (c) 2026 Sadun Kumara Adarmashena`, MIT License. A new product author credit must not erase inherited attribution.

## 5. Acceptance criteria for the successor

1. Correct manifest fixtures cover provider defaults, inherited permission, split data elements, missing export declarations, and unsupported modern syntax.
2. Offline helpers never initiate network requests or device commands implicitly.
3. Every signal, hypothesis, confirmed finding, disproved hypothesis, and blocked test has a distinct recorded state.
4. A chain contains supported edges, compatible actors and preconditions, and an end-to-end control. Disconnected scanner matches cannot form a confirmed chain.
5. Reports refuse to label unvalidated records as confirmed and clearly state untested coverage.
6. Regression tests exercise the parser and evidence model with both positive and negative cases. Device and external-tool claims are separately labeled until actually tested.
7. Version-sensitive research is linked to primary sources with review dates. Unknown platform behavior remains unknown.
8. The successor uses supported Claude Code skill structure and invocation, with bounded delegation and one writer per artifact.

## 6. Delivered implementation map

The recommendations above describe the audit. This table records what Mobiledestro v1 actually ships, so preserved source is not confused with tested replacement automation.

| Original capability | Delivered path under `mobiledestro-v1/` | Delivery level |
| --- | --- | --- |
| Preflight and scope | `scripts/mobiledestro.py doctor`, `helpers/scope_check.py`, `references/engagement.md` | Tested offline inventory/exact record checks; tool versions and full rules of engagement require operator verification |
| Intake, split handling, signatures and decoding | `scripts/mobiledestro.py intake`, `references/tool-adapters.md` | Tested archive inventory; acquisition, signing verification, split/build tooling and decoding are external workflows |
| Manifest/component model | `scripts/mobiledestro.py manifest` | Tested decoded-XML analysis with unknown/version-dependent states |
| Static recon, secrets, native and SDK signals | `helpers/triage_inputs.py scan`, engine references | Tested bounded location index; no entropy scoring, full endpoint extractor or automatic credential validation |
| MobSF and Semgrep | `helpers/triage_inputs.py import` | Tested supported JSON sections; legacy custom rules remain preserved, not advertised as newly validated rules |
| Deep-link matrix, probes and PoC app | Engines 01/02, `references/tool-adapters.md`, `templates/test-plan.md` | Route-specific procedure and ordinary-caller proof design; no universal generated probe or complete Gradle project bundled |
| Intent/provider fuzzing | Engines 01/09, `references/tool-adapters.md` | Bounded, type-specific lab test procedures with semantic controls |
| Frida unpin, Flutter TLS, root bypass and DEX observation | Engines 06/07/10, `references/tool-adapters.md` | Target/version-specific external-tool procedures; no claim that generic legacy hooks are current or universally effective |
| Bridge, intent and crypto traces | Engines 01/02/05/10, `references/tool-adapters.md` | Narrow tracing procedure with actor/origin/build attribution and reduced secret collection |
| API access matrix and cloud audit | Engines 04/08, `references/tool-adapters.md` | Owned-account canary and local rule-testing procedures; no automatic live replay or broad enumeration |
| Out-of-band observation | `references/tool-adapters.md` | Operator-controlled canary correlation procedure; original listener retained only in legacy ZIP |
| Chain synthesis and adversarial triage | `scripts/mobiledestro.py chain`, `references/chains.md`, `references/orchestration.md` | Tested connected-path/constraint enumeration plus independent semantic review |
| Reports and regression corpus | `scripts/mobiledestro.py verify/report`, `references/validation.md`, repository tests and evaluation docs | Tested evidence bookkeeping, honest state separation, synthetic regression fixtures and documented desk evaluation |

All 24 original scripts, the nine cards, engine references, 17 Semgrep rules and PoC source remain in the unchanged archive at `legacy/Mobilehunter-V2-main.zip`. Preserving those assets provides full source continuity; active runtime parity is a workflow claim and has not been benchmarked. Newly executed tests cover the offline replacements, not all inherited scripts.

