# Mobiledestro v1: detailed architecture and operating manual

**Author:** Nipun Dilshan Seneviurathne  
**Release:** 1.0.0  
**Research date:** 13 October 2026  
**Target environment:** Claude Code terminal; Android application assessments with explicit scope

## 1. Purpose and realistic performance

Mobiledestro v1 is a reusable investigation skill, supported by deterministic offline utilities. Its primary improvement is how it moves from a clue to a verified security claim. It directs Claude to reconstruct code and runtime relationships, choose discriminating tests, track missing evidence, and reject chains whose prerequisites cannot coexist.

No skill can make a language model omniscient, guarantee all Android vulnerabilities, or establish superiority without measurement. More prompt text, more agents and more hooks do not automatically increase detection quality. This release therefore distinguishes implementation features from evaluated outcomes. Its offline tests establish specific helper behavior. Its forward evaluation checks selected reasoning failures. Neither is a live-app penetration-test benchmark.

## 2. Why rebuild the supplied package

The supplied archive is named Mobilehunter V2, but its entrypoint and coordination instructions target Kimi Code. It references a Kimi skill directory and AgentSwarm instead of a portable Claude workflow. Inspection also found concrete correctness issues in provider-export interpretation, static feature collection, component invocation, cloud target checks, instrumentation signatures, and report confirmation.

The [capability map](LEGACY-CAPABILITY-MAP.md) records every inherited script and its migration. The new package retains the original archive without running it. This preserves access to all prior source material while preventing known fragile implementations from becoming an implicit default in the new workflow.

## 3. Architecture

```text
User objective + supplied authority + target artifacts
                       |
             Scope and capability discovery
                       |
     Build identity -> application model -> coverage plan
                       |
           Focused independent static workers
                       |
           Hypotheses + contrary observations
                       |
      Coordinator selects a decisive bounded experiment
                       |
     Lab / app / API tools available to the operator
                       |
          Evidence + controls + clean replay
                       |
        Context-compatible chain composition
                       |
          Independent challenge and fix review
                       |
       Report + unresolved questions + checkpoint
```

The entrypoint remains compact enough to load without the entire library. Shared references describe scope, orchestration, evidence and chain rules. Engine references are loaded only when the app contains the relevant surface. Script documentation defines machine contracts. Templates carry explanations too nuanced for a JSON schema.

There is no hidden service, agent daemon, automatic exfiltration endpoint, scheduled scanner, or background updater. Tools never appear merely because a prompt mentions them. Missing capabilities become explicit coverage limits.

## 4. Installation and loading in Claude Code

The repository contains a portable skill folder named `mobiledestro-v1`. Install it with the supplied Python installer or copy that entire folder into a Claude skill location. The installer requires an existing project directory and refuses to overwrite an existing installation. A personal installation is available as an explicit option.

```text
python tools/install_skill.py --project /path/to/assessment-project
python tools/install_skill.py --personal
```

Choose one of these commands; there is no need to install twice. Start Claude Code in the assessment directory, then invoke `/mobiledestro-v1`. If it is not recognized, verify the exact `SKILL.md` path and check the installed Claude version's skill discovery behavior. Restarting the session is a practical first check after a manual copy.

The skill's frontmatter contains a name, description, license, author and version metadata. It does not preapprove arbitrary shell commands or embed dynamic shell execution. Model and reasoning settings remain the user's choice; the skill does not claim to unlock undocumented capabilities.

Official source: [Claude Code skills](https://code.claude.com/docs/en/skills), reviewed 2026-10-13. Installation/invocation details in this release are based on this documentation; cloud/Cowork distribution can differ from local terminal installation.

## 5. Select the operating mode

| Available resources | Start with | What remains unverified |
| --- | --- | --- |
| Source only | Source paths, invariants, fix analysis | Release binary and runtime behavior |
| APK, no device | Identity, decoding, component model, static leads | Attacker execution and device-specific gates |
| Rooted instrumented emulator | Trace data/control flow and design decisive controls | Ordinary stock-device attacker reachability |
| Stock test device and owned accounts | Reproduce actor-specific app behavior | Backends not explicitly authorized |
| Authorized staging API and multiple roles | Account/object/tenant and logic matrix | Untested roles, versions and production differences |

The modes are descriptive, not barriers to useful work. Claude should continue static analysis while a device or scope question is unresolved. It should not label unavailable tests successful.

## 6. Initialize an engagement

Use Python 3.10 or newer. Run helper commands from the installed skill directory; replace example paths with the actual paths. All helpers are offline.

```text
python scripts/mobiledestro.py doctor
python scripts/mobiledestro.py init --out /path/to/new-engagement
python scripts/mobiledestro.py intake --input /path/to/app.apk --out /path/to/new-engagement/intake.json
```

The parent directory for a new engagement must already exist. The core command reference in [scripts/README.md](../mobiledestro-v1/scripts/README.md) is authoritative for options and output schemas. Record existing user authorization in the generated scope; a scope file does not create permission. The archive inventory does not extract, execute, decode or verify signatures.

Place decoded outputs in separate derived directories. Verify binary identity with actual Android tooling. Copy the model template and fill it with package/version, signatures, target SDK, device version, principals, entry points, transformations, validation, and privileged effects.

## 7. Produce leads without confusing them with findings

```text
python helpers/triage_inputs.py scan --source /path/to/decoded --out /path/to/new-engagement/source-index.json
python helpers/triage_inputs.py import --input /path/to/mobsf.json --format mobsf --out /path/to/new-engagement/mobsf-leads.json
```

The source index locates relevant APIs and credential-like assignments. It does not perform taint analysis, prove a secret is live, or verify a cloud privilege. Scanner imports retain source provenance and severity claims while keeping every entry a hypothesis. Unsupported report sections remain unassessed.

For each useful lead, write an invariant. For example: "An unprivileged app must not make this component open another tenant's export file." Then trace the actual input path, guards and object identity. Mark exactly where evidence becomes uncertain. Choose the test that could falsify the claim with minimum side effects.

## 8. Advanced engine coverage

| Engine | High-value investigation |
| --- | --- |
| IPC and capabilities | Caller identity, exported resolution, permission inheritance, URI grants, PendingIntent mutability, deputy behavior |
| Links and WebViews | Parser disagreement, verified routing, origin transitions, frame and bridge reachability, same-instance proof |
| Authentication and sessions | Request binding, OAuth/PKCE, step-up checks, token lifecycle, biometric-bound keys, account/device transitions |
| Backend and logic | Role/object/tenant invariants, state-machine transitions, replay/idempotency, sandbox transaction integrity |
| Storage/crypto/privacy | Actual sensitive-data movement, key lifecycle, backup/device-transfer behavior, logs, notifications and telemetry |
| Native and fuzzing | JNI ownership/length handling, parser reachability, harness coverage, sanitizers, minimized crash triage |
| Cross-platform | Dart/JavaScript/native boundaries, framework registration, update bundles, bridge arguments and origins |
| Cloud and supply chain | Rule enforcement, SDK initialization and data flows, dependency reachability, dynamic code trust |
| State/races/platform | Process death, resume, logout/account switching, grant lifetime, bounded concurrency, API/target differences |
| UI/permissions/observation | Overlay and screenshot distinctions, permission state, sensitive UI, targeted runtime tracing |

The scope is Android applications and their explicitly authorized supporting services. Kernel, baseband, browser-engine or OS exploit development is not supplied as an automated capability. App-level evidence may identify a dependency requiring separate specialist research.

## 9. Chain reasoning that preserves context

A chain is a sequence of compatible transitions, not a list of alarming APIs. Each edge has a concrete source and destination, its required facts, established facts, and bindings such as build, principal, session, object, origin or WebView instance. The helper rejects explicit conflicts and unsatisfied prerequisites.

```text
python scripts/mobiledestro.py chain --graph /path/to/new-engagement/graph.json --out /path/to/new-engagement/chain-candidates.json
```

This operation enumerates candidates in a supplied graph. It does not discover edges in code or prove missing context. The investigator is responsible for completeness and evidence of each edge. A path whose edges are all labeled confirmed still needs an end-to-end clean replay and semantic impact review before becoming a dynamically confirmed finding.

A practical review starts with the strongest claim and asks whether the weakest edge is real. If a bridge exists only in a trusted bundled WebView and the deep link opens a native screen, there is no chain between them. If a lab hook manufactures an authorization result but the server rejects the protected operation, report that distinction.

## 10. Runtime and backend execution

Runtime work uses available external tools with an explicit lab state. Keep the device serial, app identity, API level, ABI, WebView version, instrumentation changes, test accounts and request limits in the test plan. Serialize device/account mutations under one coordinator.

Pinning/root bypass, runtime DEX observation, OOB canaries, provider probes, component dispatch, companion-app PoCs and fuzzing remain supported investigation workflows. They require target-specific setup and verification. Generic inherited code is not an assertion that an operation works on a current app.

Before active backend replay, validate the exact origin and reviewed method/path, account ownership, allowed operation and bounded request count. Disable automatic redirect following or recheck every hop. Do not move credentials across origins. Do not use response similarity as an authorization oracle: verify a seeded object or protected state transition.

## 11. Evidence and status

The canonical ledger distinguishes `hypothesis`, `static-supported`, `dynamic-confirmed`, `refuted` and `blocked`. For dynamic confirmation the core report tool checks recorded scope, actor identity and evidence artifacts for positive observation, negative control and clean replay. See the script contract for exact requirements.

```text
python scripts/mobiledestro.py verify --engagement /path/to/new-engagement
python scripts/mobiledestro.py report --engagement /path/to/new-engagement --out /path/to/new-engagement/report.md
```

Hash and path verification protects evidence integrity. It cannot determine whether a screenshot or transcript actually proves the claim. Semantic review remains mandatory. Missing or altered evidence lowers the reported status instead of silently preserving confidence.

Use standard Markdown findings with impact, affected versions, attacker prerequisites, root-cause citations, minimal reproduction, controls, evidence, remediation and untested assumptions. Findings should be useful to an engineer who did not watch the assessment.

## 12. Coverage and research

Coverage records what was tested, blocked, not applicable or not tested. A tested area means specific recorded tests ran in specified contexts; it does not mean the area contains no vulnerabilities. Do not compute a security percentage by counting checklist items.

MASVS identifies control areas; MASWE describes weaknesses; MASTG supplies verification guidance. The mapping helps organize an assessment but cannot replace app-specific reasoning. Verify current test status and IDs before citing them. See [research notes](RESEARCH.md) and each engine's source list.

## 13. Parallel workers and long investigations

Use narrowly scoped workers for independent static questions. Each gets absolute file paths, a build hash, scope, actor model, an engine reference, known hypotheses, an exclusive output directory and a concrete budget. Workers do not overwrite a shared ledger or mutate a shared test device.

Merge their evidence centrally, deduplicate root causes, and assign an independent reviewer to challenge severe claims. Record disagreements and resolve them with new evidence. Where subagents are unavailable, execute the same roles sequentially.

After a context reset resume from scope, identity, model, ledger, graph, coverage and checkpoint. Recheck stale builds, expiring sessions and mutable server behavior. Preserve cleanup obligations for proxies, CAs, installed test apps, listeners and instrumentation.

## 14. Evaluation and improvement

This release includes automated adversarial input tests and reasoning scenarios for common overclaiming failures. Run both Python suites after changing the helpers. For workflow changes, evaluate with vulnerable and corrected examples, independent raw evidence and a reviewer who does not receive the intended answer.

For a real comparative benchmark, select authorized test applications, blind seeded vulnerabilities, patched controls, reproducible device images and a fixed time budget. Measure true/false findings, missed seeded issues, reproducibility, time to decisive evidence and token/tool cost. Do not substitute the number of prompts, scripts or pages for detection quality.

## 15. Distribution and maintenance

The full repository ZIP contains the installable skill, documentation, tests, CI, installation tools and attributed legacy source ZIP. The smaller skill ZIP contains the skill and supporting resources for manual installation. GitHub users should upload/extract the repository contents and keep engagement evidence outside the repository.

Review source links and Android/Claude/Frida behavior before a new major assessment or release. Record tested versions rather than pinning an unverified "latest" label. Changes to a checker need regression cases showing the intended behavioral difference. Changes to reference prose need source or observed assessment evidence.

Use the author name exactly as supplied for this release. Preserve the original Mobilehunter credit and license in any redistribution containing inherited material.
