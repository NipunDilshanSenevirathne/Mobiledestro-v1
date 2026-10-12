# Research basis and design decisions

Reviewed 13 October 2026. Sources are primary documentation, standards and source implementations. The linked pages were consulted to support platform facts and design choices; this is an engineering synthesis, not a systematic literature review or an empirical tool comparison.

## Core sources

| Source | How it informed this release |
| --- | --- |
| [Claude Code skills](https://code.claude.com/docs/en/skills) | Actual terminal skill packaging and invocation; supporting files loaded progressively |
| [Claude Code subagents](https://code.claude.com/docs/en/sub-agents) | Explicit worker context/tool contracts and availability-aware delegation |
| [OWASP MASVS](https://mas.owasp.org/MASVS/) | Control-area coverage vocabulary |
| [OWASP MASWE](https://mas.owasp.org/MASWE/) | Weakness classification, verified before mapping |
| [OWASP MASTG tests](https://mas.owasp.org/MASTG/tests/) | Test guidance and explicit checks for current/deprecated status |
| [Android security risks](https://developer.android.com/privacy-and-security/risks) | Platform-specific boundary review and mitigation context |
| [Frida API](https://frida.re/docs/javascript-api/) | Runtime API/version checks and observation limits |
| [AOSP libFuzzer](https://source.android.com/docs/security/test/libfuzzer) | Harness-oriented native testing rather than a universal APK fuzzer claim |

The [Android research index](ANDROID-RESEARCH.md) contains the engine-specific source list and major platform corrections. The engine files put citations beside the behavior they support. The core script reference links the Android manifest and AOSP parser sources used for its semantics.

## Independent design contributions

1. A graph edge must have connected source/destination behavior, satisfiable prerequisites, and compatible identity/state bindings. Tool co-occurrence is insufficient.
2. A positive result needs a negative control and fresh replay. Distinct evidence artifacts and hashes improve integrity but do not replace semantic review.
3. Static-supported analysis remains useful when runtime tools are missing, with explicit uncertainty rather than a false dynamic-confirmation label.
4. Tools imported from older workflows are evaluated against their actual code, not their marketing descriptions. Preserved source and current supported execution are documented separately.
5. Failure to cover an area is visible in the report. More pages, alerts, workers or fuzz cases are not evidence of better security.

## Research limits

- No claim of complete vulnerability coverage, benchmark leadership or a new zero-day is made.
- No real Android target, live API, cloud project, device or Claude Code session was tested in this build environment.
- The documentation was reviewed on the stated date and can change. Recheck exact API, target SDK, OEM, tool and framework behavior for each engagement.
- GitHub CI syntax follows the official [checkout](https://github.com/actions/checkout) and [setup-python](https://github.com/actions/setup-python) repositories. The workflow is supplied but has not run on GitHub as part of this delivery.
