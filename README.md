# Mobiledestro v1

By **Nipun Dilshan Seneviurathne**.

A Claude Code skill for authorized Android security research. It combines targeted static review, lab validation procedures, state-aware chain reasoning, independent challenge, and evidence-based reporting. Version 1.0.0; research reviewed 13 October 2026.

## Start here

1. Read [the detailed manual](docs/MOBILEDESTRO-V1-MANUAL.md).
2. Install Python 3.10 or newer for the optional offline helpers. Claude Code, Android tools and a lab device are separate prerequisites for their respective workflows.
3. From this repository, install into an assessment project:

   ```text
   python tools/install_skill.py --project /path/to/assessment-project
   ```

4. Start Claude Code in that project and invoke:

   ```text
   /mobiledestro-v1 Review the supplied APK for our authorized assessment. Start with identity, coverage and trust boundaries; prioritize deep connected paths and show evidence for every claim.
   ```

5. Provide the authorized artifact and scope. Natural language such as "load Mobiledestro v1" can also select it; the slash command is explicit.

For all projects, use `python tools/install_skill.py --personal`. The installer refuses to replace an existing skill. Manual installation is also possible: copy the complete `mobiledestro-v1` folder to `<project>/.claude/skills/mobiledestro-v1` or `~/.claude/skills/mobiledestro-v1`. Keep supporting folders beside `SKILL.md`.

Claude documents skill directories, `SKILL.md`, and command invocation in its [official skills guide](https://code.claude.com/docs/en/skills). This package grants no blanket tool permissions and does not change Claude settings.

## What is included

- Ten focused Android engine references and a shared investigation/validation workflow.
- A Claude-compatible coordinator and independent static-review worker contract.
- An offline Python toolkit with archive inventory, manifest semantics, context-constrained graph traversal, evidence checks and reports.
- Offline source indexing, MobSF/Semgrep lead import and exact package/origin scope checks.
- Engagement, test-plan, finding and checkpoint templates.
- Meaningful automated tests and a documented behavioral evaluation.
- Detailed migration notes and the original Mobilehunter ZIP with attribution, retained outside the installed skill as legacy reference material.

## Capability honesty

The helpers organize and validate evidence; they do not automatically discover every vulnerability. Active Android testing is executed through the operator's available tools using the documented workflows. The package does not bundle a decompiler, Android SDK, Frida server, universal bypass, complete Android PoC project, backend scanner or native fuzzing harness. Some Mobilehunter active scripts are replaced by reviewed procedures rather than advertised as drop-in executables. The complete original remains available in `legacy/` for comparison.

No comparative detection benchmark has established superiority over other products. No real target was tested during package creation. See [validation](docs/VALIDATION.md) for exact executed checks and limitations.

## Repository guide

| Path | Purpose |
| --- | --- |
| `mobiledestro-v1/` | Self-contained installable Claude skill |
| `docs/MOBILEDESTRO-V1-MANUAL.md` | Architecture, operation, scope and examples |
| `docs/LEGACY-CAPABILITY-MAP.md` | Full inherited capability mapping and concrete defects |
| `docs/RESEARCH.md` | Primary-source research and design implications |
| `docs/VALIDATION.md` | Executed validation and limits |
| `docs/EVALUATION.md` | Behavioral regression scenarios and rubric |
| `tests/`, `helper_tests/` | Offline regression suites |
| `tools/` | Installation and package checks |
| `legacy/` | Unmodified original archive and its license |

## Development

For a synthetic end-to-end walkthrough, run `python tools/run_demo.py --out /path/to/new-demo` with an existing parent directory. It produces a manifest inventory, source index, candidate graph and clearly labeled example report without contacting a target.

```text
python -m unittest discover -s tests -v
python -m unittest discover -s helper_tests -v
python tools/validate_package.py
```

Use the files as a new GitHub repository or upload the repository ZIP contents, including `.github/` and `.gitignore`. Do not upload engagement data, APKs, secrets or raw reports. This delivery does not create or publish a GitHub repository.

New work is MIT licensed. Mobilehunter's original MIT copyright notice is retained. See [LICENSE](LICENSE) and [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
