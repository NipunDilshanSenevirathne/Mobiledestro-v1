# Offline input helpers

Requires Python 3.10 or newer; uses only the standard library. Run from the installed skill directory. All output paths must be new files. These helpers never execute ADB, replay requests, or load instrumentation.

## Exact recorded scope

```text
python helpers/scope_check.py --scope /path/to/engagement/scope.json --kind package --target com.example.lab
python helpers/scope_check.py --scope /path/to/engagement/scope.json --kind origin --target https://api.example.test/v1/me
```

Add `active_allowlist: {"packages": [], "origins": []}` to the generated scope. Populate only previously authorized entries. Authorization must be `approved` with a nonempty `reference`. Origins are exact HTTP/HTTPS scheme, IDNA hostname and port matches; default ports normalize. Subdomains are not implicitly allowed. Credentials, fragments, wildcards, ambiguous authority strings and allowlist paths fail. Exit 0 means a match to the recorded scope; 1 means denied; 2 means invalid input. No result grants authorization or enforces scope on another tool. DNS, redirects, methods, accounts, target ownership and allowed operations remain the active client's/operator's responsibility.

## Source index

```text
python helpers/triage_inputs.py scan --source /path/to/decoded --out /path/to/engagement/source-index.json
```

Indexes common Android boundary/API markers and credential-looking assignments into locations and categories. No source snippets or raw values are copied. It inspects at most 20,000 visited filesystem entries, 4 MiB per UTF-8 source file and 50,000 leads; reports truncation/skips and an ignored-directory count. Symlinks/reparse points, dependency directories, binary files and unsupported extensions are excluded. It has no interprocedural taint tracking, reachability engine or entropy-based credential verification. Names and paths can still be sensitive.

`source_text_sha256` hashes decoded text after newline normalization, useful for index provenance; it is deliberately different from the binary evidence hash used by the core toolkit.

## Scanner imports

```text
python helpers/triage_inputs.py import --input /path/to/mobsf.json --format mobsf --out /path/to/engagement/mobsf-leads.json
python helpers/triage_inputs.py import --input /path/to/semgrep.json --format semgrep --out /path/to/engagement/semgrep-leads.json
```

Supported shapes are Semgrep `results[]`; MobSF `code_analysis.findings`, `manifest_analysis` (list or `manifest_findings`), and `network_security` (list or `network_findings`). Other sections are not imported. Reports are limited to 32 MiB and 50,000 leads. An unrecognized schema fails instead of returning a misleading empty success. Messages and code snippets are omitted to reduce data exposure; preserve the original restricted report and its hash for manual review. Source severity is retained as an unverified claim. Every imported result remains `hypothesis`.

Outputs are sidecar lead inventories, not canonical ledger files. A coordinator promotes a lead into the ledger only after adding the exact invariant, reachable path, actor and decisive test.

All helpers reject duplicate JSON keys, non-finite numbers, input/output symlinks and reparse-point paths. Use a stable local workspace; these checks do not create a filesystem-race isolation boundary. Source paths and imported rule identifiers remain untrusted data.
