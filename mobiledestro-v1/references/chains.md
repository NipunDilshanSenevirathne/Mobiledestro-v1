# Evidence-driven chain composition

## Edge contract

A graph node is a concrete capability or security-relevant state, not a technology name. An edge must explain a transition with entry point, attacker authority, input provenance, transformation, gate, sink, observable effect, evidence citation, and version/state constraints.

Examples of meaningful nodes: external caller controls the `next` URI of Activity A; the same URI is used by WebView instance W; a bridge method on W returns a seeded account identifier to that origin. A separate unrelated WebView elsewhere in the APK cannot connect these nodes.

The offline graph schema and traversal behavior are in [scripts/README.md](../scripts/README.md). Represent facts with `prerequisites` and `establishes`; shared constraints use `bindings`. Use consistent keys such as `build`, `device_api`, `principal`, `tenant`, `session`, `webview_instance`, `origin`, `object`, and `attacker_model`.

Missing bindings are unknown, not proof of compatibility. The helper prevents explicit binding conflicts; it cannot infer the complete context. A reviewer must reject a proposed composition if a relevant binding was simply omitted.

## Composition procedure

1. Pick a meaningful terminal effect and work backward to the minimum required capability.
2. Identify where that capability can actually be obtained by the same attacker, without inserting tester privileges.
3. Join compatible edges and list all prerequisites absent from the initial state.
4. Test the weakest unsupported edge before spending time on the rest of the chain.
5. Replay the connected path from a clean state using the same build, actor, object, and session constraints.
6. Remove one edge or apply the proposed control. The terminal effect should disappear while the benign workflow remains possible.
7. Report the demonstrated impact once; describe component root causes without double-counting severity.

## Useful chain families

| Candidate path | Decisive missing proof | Common invalid composition |
| --- | --- | --- |
| Link -> internal route -> privileged action | External route reaches action under attacker's authority | Only an authenticated first-party navigation can reach it |
| Link -> WebView -> bridge capability | Same attacker content shares the bridge-bearing instance and can call a sensitive method | Bridge exists only in an unrelated trusted WebView |
| Provider -> granted file -> backend authorization | Exact grant exposes a canary; backend accepts the resulting authority | Lab root reads file or backend enforces object ownership |
| OAuth callback -> account binding | Callback binds the wrong identity/session without valid request binding | Intercepted code cannot be redeemed due to verifier binding |
| PendingIntent -> deputy -> sensitive operation | Attacker can obtain and influence the precise capability used by deputy | Token is immutable or bound to a harmless fixed operation |
| Native parser -> controlled crash -> security impact | Untrusted input reaches native defect in release configuration | Offline harness crash cannot be reached through the app |
| Offline cache -> state race -> unauthorized outcome | Forbidden server or local protected-state transition survives replay | UI changes temporarily but canonical server state rejects it |
| Cloud rule gap -> cross-tenant access | Two owned tenants show a forbidden canary read/write | Public configuration value is mistaken for privileged access |

These are hypothesis families, not guaranteed vulnerabilities or automated payload recipes. Instrumentation may help trace a transition but does not replace an external-attacker proof.

## Novelty and variants

Novelty is a research question, not a severity field. Compare root cause, prerequisite, affected build, and invariant with previous reports. After confirming a defect, search sibling handlers, alternative data encodings, protocol states, feature modules, and platform versions that share the faulty check. Bound the variant search and document negative results. Do not claim a zero-day based only on absent search results.
