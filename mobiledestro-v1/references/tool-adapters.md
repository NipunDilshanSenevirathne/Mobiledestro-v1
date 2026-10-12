# Tool adapters and practical execution

The skill provides investigation procedures and offline helpers. The operator supplies external tools, binaries, devices, accounts, and active-testing scope. Record command versions and local `--help` output before depending on version-specific flags. Never treat this file as proof that an adapter ran.

## Acquisition and identity

1. Prefer a supplied APK/APK set, source checkout, or artifact from an authorized device/build system. A store URL is an identity hint, not an APK.
2. Use the core `intake` helper to hash and inventory the container without extraction. Verify signatures with `apksigner verify --verbose --print-certs` and retain output separately. For split APKs check consistent package, version, and signing identity.
3. Use official `bundletool` when an AAB needs an APK set for the selected device; retain the original bundle and generated-set provenance. Do not concatenate ZIPs or call that a signed release.
4. Decode with JADX and apktool into new derived directories. Record decode failures, obfuscated methods, multidex/split coverage, native ABIs, resource references, and dynamic feature modules. Isolate decompilers from sensitive host files when processing untrusted packages.
5. If an authorized packed app only exposes a loader, use targeted runtime class/Dex observation on the lab device and retain provenance. Do not label a partial memory dump complete or equivalent to the original signed APK.

## Static analysis

Run the decoded-manifest helper, then index sources with `helpers/triage_inputs.py scan`. The index locates candidate APIs without printing raw secrets. It is a bounded text heuristic, not dataflow analysis; inspect each source/sink and its guards manually.

Use MobSF for broad configuration findings and Semgrep for code-pattern candidates when available. Import saved JSON through `helpers/triage_inputs.py import --format mobsf|semgrep`. Schema drift may require a reviewed adapter change. Keep original report hashes. Do not infer that an unrecognized report with zero imported entries has no issues.

For a rule candidate trace attacker-controlled data through decoding, normalization, origin/permission checks, helper calls, asynchronous callbacks, and the final operation. Compare decompiled code to smali/original code for branches that determine authorization. For dependencies verify artifact identity, version/build, affected configuration, and reachable vulnerable code before linking a published advisory.

Source scanning should include manifest XML, network-security configuration, resource aliases, Java/Kotlin/smali, JavaScript/Dart bundles, JNI registrations, SQL construction, serialization, archive extraction, dynamic loading, and privacy-sensitive SDK flows. Generated code and obfuscation are coverage gaps, not reasons to assume safety.

## Lab setup and instrumentation

Choose an explicit device serial and snapshot baseline state. Confirm package/version and process before attaching. Record device API, ABI, app target SDK, WebView package/version, Frida client/server versions and privilege. Do not automatically install a CA, change system stores, root a device, disable detection, or patch an APK just because static analysis started.

Use Frida/objection to answer a specific question: which input reaches which method, what validation occurs, and what effect follows? Observe identifiers, lengths, types, hashes, and canaries where sufficient; avoid logging all keys, plaintext, tokens, preferences, and SQL arguments by default. Capture a narrow time window and explicitly stop hooks.

When required for an authorized lab assessment, interception and root/emulator checks can be adapted to the exact app implementation. Generic pinning/root bypass scripts and native byte-pattern hooks can miss paths, hook the wrong function, or change the behavior under test. Validate the hook on the exact build and retain unmodified controls. A bypass is an observation aid, not automatically a product vulnerability.

Frida's [JavaScript API](https://frida.re/docs/javascript-api/) is the authoritative API reference; inspect the installed runtime's Java bridge support and exact overload signatures. Review date: 2026-10-13. Do not assume a legacy script loads unchanged on a current runtime.

## Deep links, IPC and providers

Build a finite test matrix from actual route parsing: scheme/host/path, verified App Link state, encoded versus decoded value, redirect behavior, component dispatch, and login/lifecycle state. Use owned canary URLs. Test one parser ambiguity at a time, with a benign control.

Use ADB for lab setup and observation. Where shell identity can distort the result, use an ordinary companion app with the exact required action, URI, extras, caller identity, and grant flags. An exported service, receiver, activity, and provider require different invocation mechanisms. Do not route every component through `am start`.

Provider query tests need their own allowed/forbidden row oracle. File-provider tests need the actual open/read path and seeded canary files; a query call does not test `openFile`. Record inherited and operation-specific permissions, path permissions, grants, and canonical path behavior. Do not dump entire databases.

The inherited PoC source is a starting reference, not a buildable guarantee. For a new PoC construct a minimal Android project using the operator's installed Gradle/SDK versions. Declare only needed permissions/queries. Compile locally, keep signing/test-device identity, and document installation, launch, expected observation, and uninstall. Do not request powerful unrelated permissions just to make a demonstration work.

## Backend and cloud

Use captured request templates from owned accounts. Before replay, validate origin, method, path class, request budget, test-data ownership, and mutation impact. Disable automatic redirects or revalidate every hop; never carry Authorization/Cookie headers to a different origin. Scope validation must occur on the final request, not only a textual URL substring.

Prepare a role/account/object matrix with a semantic canary oracle. Replay only selected cases; an equal response body is not proof of forbidden access. Keep secrets in session storage rather than command-line arguments or public files. Test receipts, rewards, quotas, and payments in an approved sandbox with no real value movement.

For Firebase prefer local Emulator Suite/rule tests with the real proposed rules and two synthetic tenants. Production reads/writes need explicit project/backend scope. A Firebase configuration/API key alone is generally not proof of authorization. Never turn discovered bucket names into permission to enumerate them.

## Fuzzing, races and native code

Specify harness entry, input grammar, seed corpus, sanitizer/coverage mode, maximum cases, timeout, memory, concurrency, restart policy, and cleanup. Prefer isolated parser or rule harnesses before device/system-wide runs. Repeatedly crash only a disposable authorized lab environment.

Use libFuzzer or another installed harness for source-available native parsing and minimize unique crashes; use stable stack/build signatures for deduplication. The [AOSP libFuzzer guide](https://source.android.com/docs/security/test/libfuzzer) supplies build integration context, not evidence that an arbitrary APK can be fuzzed without a harness. Review date: 2026-10-13.

Race testing requires a precise forbidden state transition, a small bounded schedule, and a canonical final-state oracle. Increase concurrency only when evidence justifies it and scope permits it. Avoid unbounded loops or claims that single-packet synchronization automatically makes a valid exploit.

## Canaries and out-of-band observation

Use a local or operator-controlled listener for a narrow synthetic marker. Record destination ownership, correlation ID, timestamp, originating request, and cleanup. A callback proves a request reached the listener; it does not prove token exposure, account takeover, or data access. Avoid automatic bridge-calling HTML that guesses method names or captures real secrets.

## External tools inventory

| Capability | Typical tool | Evidence of success |
| --- | --- | --- |
| Decode APK/source | JADX, apktool, Android SDK | Version, exit status, decoded scope, errors |
| Signature/build identity | apksigner, aapt2, bundletool | Verification output and exact artifact hashes |
| Broad static leads | MobSF, Semgrep, APKiD | Report hash, rules/tool versions, known limits |
| Runtime tracing | ADB, Frida, objection | Target process/build, validated hook, trace/control |
| Interception | Burp, mitmproxy | Controlled test traffic and lab configuration |
| Native review | Ghidra, radare2, debugger | Correct architecture and symbol/build provenance |
| Native fuzzing | libFuzzer, sanitizers | Harness, corpus, coverage, minimized crash |
| Cloud rules | Firebase Emulator Suite | Rules version, actor fixtures, expected outcomes |

Installation is operator-specific. No installer in this package downloads or executes remote scripts. The `doctor` command inventories availability only; it does not establish tool compatibility.
