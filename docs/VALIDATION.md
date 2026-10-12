# Release validation

Validated on 13 October 2026 using Windows and Python 3.12.14. These are offline package checks, not an Android assessment or comparative detection benchmark.

## Executed checks

| Check | Result | Meaning |
| --- | --- | --- |
| Core toolkit suite | 45 tests: 44 passed, 1 skipped | Archive bounds/paths, manifest semantics, graph conditions, evidence integrity, state handling and output protection |
| Helper and installer suite | 22 tests passed | Exact scope boundaries, malformed inputs, bounded source scans, scanner imports, no raw snippet emission, installation and overwrite refusal |
| Synthetic end-to-end demo | Passed | CLI initialization, archive inventory, decoded manifest, candidate chain, source index, verification and Markdown report execute together |
| Independent behavioral review | Three scenarios completed | Rejects disconnected chains, inadequate BOLA evidence and untrusted asset instructions; separates hooked UI from backend impact |
| Package validation | Passed | Python 3.10 syntax compatibility parsing, restricted frontmatter structure, JSON readability, local links and required files |
| Archive packaging | ZIP member integrity and delivery hashes checked | Shipped files match the staged release; does not validate vulnerability discovery |

The skipped test creates a real filesystem symlink. This host did not permit creating the link. Synthetic ZIP symlink rejection was tested and passed. See the test output if running on a host that supports filesystem symlinks.

The synthetic demo creates a deliberately non-installable container, decoded manifest and graph. Its only ledger item remains a hypothesis with unrated severity; scope remains pending and every coverage area remains not tested. No sample output is presented as a real vulnerability.

## Validation tooling note

The skill-creator `quick_validate.py` was attempted but its host Python environment lacked PyYAML, so that external validator did not execute. The bundled dependency-free package validator checks this release's restricted frontmatter structure and names, supporting paths, Python syntax and JSON. It is deliberately not described as a general YAML validator or a Claude Code integration test.

## Unexecuted validation

- Loading and running the skill in an actual Claude Code terminal session.
- Android SDK/decompiler compatibility or APK signature verification.
- Physical device/emulator, Frida, proxy, provider, companion-app, native harness or backend testing.
- The GitHub Actions workflow on GitHub; Python 3.10 and Linux runtime execution are configured there but were not executed locally.
- Quantitative comparisons with Mobilehunter or any commercial/open-source scanner.

## Run locally

From the repository root:

```text
python -B -m unittest discover -s tests -v
python -B -m unittest discover -s helper_tests -v
python tools/validate_package.py
python tools/run_demo.py --out /path/to/new-demo
```

Use an existing parent directory and a new demo directory. The demo initializes only that new directory. Run engagement work outside the source repository and keep raw evidence private.

## Release interpretation

Passing tests establishes bounded helper behavior for the supplied cases. It does not establish that all archive formats, Android builds, report schemas or vulnerability classes are covered. The procedures require target-specific reasoning, current documentation and reproducible evidence. Changes to scripts need corresponding behavioral regression tests; claims about detection improvement need an actual blinded benchmark.
