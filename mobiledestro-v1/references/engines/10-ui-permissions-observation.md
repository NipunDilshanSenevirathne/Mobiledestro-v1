# Engine 10: UI trust, permissions, and runtime observation

Research reviewed: 2026-10-13. Use a disposable test device and obvious lab-only UI. Do not collect credentials, impersonate a real service, or persuade real users to grant accessibility/overlay permissions.

## Trust model

| Stage | Record |
| --- | --- |
| Entry | Sensitive screen, permission prompt, notification, clipboard action, accessibility or overlay interaction |
| Source | User gesture, overlay state, caller/task identity, external content, permission result |
| Transform | Navigation, rendering, event dispatch, accessibility projection, copied text, screenshot |
| Check | User intent, obscured-touch handling, current permission, data sensitivity, task identity |
| Sink | Privileged action, displayed or copied information, shared surface, backend transition |

Distinguish information protection, input integrity, user consent, and anti-tampering. Each requires its own attacker preconditions and outcome.

## Source-backed facts

`FLAG_SECURE` addresses screenshots and insecure displays; it is not an overlay defense by itself. Android documents overlay suppression separately. [Sensitive activities](https://developer.android.com/security/fraud-prevention/activities)

Full and partial occlusion are different tapjacking cases, with OS-dependent protections and exceptions. Evaluate the actual touch event and sensitive operation instead of checking for one flag. [Tapjacking guidance](https://developer.android.com/privacy-and-security/risks/tapjacking)

Permission-dependent features should handle runtime grants and denials. A permission declaration does not establish that access is currently authorized. [Runtime permissions](https://developer.android.com/training/permissions/requesting)

Frida 17 separates the Java bridge from the core GumJS runtime for compiled agents; the Frida REPL and frida-trace have their documented convenience behavior. Match the launch path and version before diagnosing missing Java APIs. [Frida JavaScript API](https://frida.re/docs/javascript-api/)

## Decisive tests

1. Inventory security-sensitive screens and operations with their required user confirmation, data policy, caller, and downstream server guard. Prioritize export approval, account linking, recovery, and credential display over ordinary navigation.
2. On an approved lab device, compare an unobscured interaction with bounded full and partial occlusion using a clearly labeled test overlay. Record granted overlay permission, opacity, touched view, event flags, and actual resulting action. Stop before real purchases or external notifications.
3. Inspect screenshot, screen-share, recent-task preview, notification, clipboard, autofill, keyboard, and accessibility exposure using synthetic markers. Identify the realistic recipient and permissions instead of assuming every app can read every surface.
4. Test permission denial, revocation, approximate/limited grants where applicable, and cancellation while the operation is pending. Verify the final use of data or sensor access, including background work and SDK behavior.
5. For task/launch hypotheses, capture the real task stack, activity identity, target SDK, OS patch, launch flags, and user-visible labeling. Do not assign a historical task-hijacking name from `taskAffinity` alone.
6. Establish a clean release-build baseline, then add the smallest observation hook at a known method boundary. Log only argument shape, redacted marker, caller, and outcome. Prefer tracing to changing return values.
7. If a diagnostic bypass is necessary to observe another surface, record the changed function, process, and assumption. Remove it and reproduce the final claimed boundary violation independently, or explicitly classify the result as conditional on in-process compromise.
8. Compare hook-on and hook-off behavior. A hook that alters scheduling, class loading, authentication, or error handling may change the behavior under investigation.

## Negative controls and disqualifiers

- Missing screenshot protection is not automatically a vulnerability; explain sensitivity, recipient capability, and applicable product requirement.
- Missing `FLAG_SECURE` does not establish tapjacking. A blocked or harmless touch does not establish privileged action.
- Root detection, emulator detection, or certificate-pinning bypass is not by itself an authorization defect or hardware-attestation bypass.
- A clipboard value seen only through shell/root does not prove ordinary background apps can read it on the tested OS.
- A permission prompt's existence does not prove informed consent, while a declined prompt followed by no access is a valid negative control.
- Accessibility access granted by the tester must be included in the attacker model; do not silently treat it as an unprivileged capability.

## Version and precondition caveats

Record Android API/patch, OEM, target SDK, UI toolkit, window type, overlay/accessibility permissions, foreground state, lock state, input method, and instrumentation versions. Clipboard, overlays, notifications, and task behavior are version-dependent; verify the specific platform reference before claims.

## Chain edges and artifacts

Candidate edges: misleading lab overlay to unauthorized confirmation; exposed test marker to concrete recipient; permission-state race to unintended collection; external task entry to privileged screen. Continue server and auth consequences in Engines 03 and 04.

Save a UI/permission matrix, before/after recording with synthetic data, event and task traces, recipient capability, release baseline, hook manifest, exact modified decisions, negative controls, and outcome evidence. Remove helper apps, hooks, and temporary grants after testing.
