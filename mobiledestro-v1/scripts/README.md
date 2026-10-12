# Mobiledestro v1 offline toolkit

This directory contains a Python 3.10+ standard-library CLI. It organizes supplied evidence and checks specific static declarations. It does not connect to a device, execute installed tools, extract archives, send network requests, discover vulnerabilities automatically, or establish that an exploit works. The skill supplies the analyst workflow; this helper supplies reproducible local bookkeeping.

Run commands from the repository root. Replace `python` with your installed Python executable where required.

```text
python mobiledestro-v1/scripts/mobiledestro.py --help
python mobiledestro-v1/scripts/mobiledestro.py doctor
python mobiledestro-v1/scripts/mobiledestro.py init --out engagements/lab-001
python mobiledestro-v1/scripts/mobiledestro.py intake --input sample.apk --out engagements/lab-001/analysis/intake.json
python mobiledestro-v1/scripts/mobiledestro.py manifest --input decoded/AndroidManifest.xml --device-api 35 --out engagements/lab-001/analysis/manifest.json
python mobiledestro-v1/scripts/mobiledestro.py chain --graph engagements/lab-001/graph.json --out engagements/lab-001/analysis/chains.json
python mobiledestro-v1/scripts/mobiledestro.py verify --engagement engagements/lab-001
python mobiledestro-v1/scripts/mobiledestro.py report --engagement engagements/lab-001 --out engagements/lab-001/reports/report.md
```

Create the parent `engagements` directory yourself first. `init` requires a new directory and an existing parent. It creates `inputs`, `evidence`, `analysis`, `reports`, and the four JSON files described below. Other commands require an existing output parent. All output files use exclusive creation: an existing output is an error. Choose a new filename for each run. `doctor` and `verify` write JSON to stdout unless `--out` is supplied; other analysis commands require `--out`.

Exit codes:

1. `0`: command completed. A completed report can include downgraded findings and integrity issues; check its contents.
2. `1`: `verify` completed but found evidence or confirmation issues.
3. `2`: invalid arguments, malformed/unsupported input, unsafe path, filesystem error, or output collision. An explanation is written to stderr. No structured verification result is promised for a schema failure.

## Scope schema

`scope.json` is a JSON object. The fields in this example are required. A pending template is intentionally incomplete for active testing.

```json
{
  "schema_version": 1,
  "engagement_id": "lab-001",
  "authorization": {
    "status": "pending",
    "reference": ""
  },
  "targets": ["com.example.training / owned lab build"],
  "attacker_models": ["unprivileged companion app"],
  "exclusions": ["Production accounts and production endpoints"]
}
```

- `schema_version`: integer `1`.
- `engagement_id`: nonempty string, at most 200 characters.
- `authorization.status`: `pending` or `approved`.
- `authorization.reference`: string; nonempty when status is `approved`.
- `targets`, `attacker_models`, `exclusions`: arrays of strings, at most 2,000 items each and 500 characters per item.

The authorization reference is a human-maintained reference, not machine-verified permission. The helper does not parse target strings into endpoint allowlists. A listed attacker model is an exact string identifier; the same spelling is required in a dynamically confirmed finding. Authorization and runtime safety controls remain the responsibility of the engagement workflow.

## Finding ledger schema

`ledger.json` has integer `schema_version: 1` and an array `findings` of at most 2,000 objects. Each finding requires `id`, `title`, and `status`. The other fields below are optional with the documented defaults.

```json
{
  "schema_version": 1,
  "findings": [
    {
      "id": "F-001",
      "title": "Review external input at an owned test entry point",
      "status": "hypothesis",
      "severity": "unrated",
      "attacker_model": "unprivileged companion app",
      "description": "Trace the input to a security-relevant sink, then test reachability and controls in the authorized lab.",
      "evidence": [],
      "coverage_ids": ["ipc"]
    }
  ]
}
```

| Field | Supported values and limits |
| --- | --- |
| `id` | Nonempty string, 200 characters; unique within the ledger. |
| `title` | Nonempty string, 500 characters. |
| `status` | `hypothesis`, `static-supported`, `dynamic-confirmed`, `refuted`, `blocked`. |
| `severity` | `unrated` by default; or `informational`, `low`, `medium`, `high`, `critical`. Analyst supplied, never calculated. |
| `attacker_model` | Empty string by default; maximum 500 characters. Required for dynamic confirmation. |
| `description` | Empty string by default; maximum 20,000 characters. |
| `evidence` | Empty array by default; maximum 100 evidence objects. |
| `coverage_ids` | Empty array by default; maximum 100 strings referencing existing coverage IDs. |

An evidence object requires all three fields:

```json
{
  "role": "supporting",
  "path": "evidence/review-notes.txt",
  "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
}
```

The zero hash above is a placeholder and will fail verification unless it happens to be the real digest. Replace it with the actual file's SHA-256 digest. Supported roles are `positive`, `negative_control`, `clean_replay`, and `supporting`. Evidence paths are relative to the engagement directory. Use forward slashes for portability. The verifier rejects absolute paths, parent traversal, symlinks/reparse points, Windows device names, alternate data streams, ambiguous trailing dots/spaces, missing files and digest mismatches. Evidence contents are never executed or embedded in the report.

Dynamic confirmation is retained only when all of these integrity requirements hold:

1. The ledger already records `dynamic-confirmed`; the helper never promotes another state.
2. Scope authorization is recorded as approved with a nonempty reference.
3. The finding names an attacker model listed exactly in the scope file.
4. At least one verified artifact exists for each of `positive`, `negative_control`, and `clean_replay`.
5. A set containing one artifact per required role has three distinct relative paths and three distinct SHA-256 digests.
6. No evidence or coverage-reference integrity issue remains for that finding.

Failure downgrades the report's effective state to `hypothesis`, preserves the recorded state, and explains each issue. `static-supported` and `refuted` also downgrade to `hypothesis` when evidence is missing or an integrity issue exists. `hypothesis` and `blocked` are never upgraded. The source ledger is not modified.

Hashes and distinct role files establish bookkeeping integrity only. They do not prove that the contents are true, that a negative control is meaningful, or that a replay starts from clean state. A human reviewer must assess the artifacts. This distinction remains explicit in the report.

## Graph schema and chain enumeration

`graph.json` requires integer `schema_version: 1`, `nodes` and `edges`. `initial_facts` defaults to an empty array; `context` defaults to an empty object.

```json
{
  "schema_version": 1,
  "nodes": [
    {"id": "caller", "label": "Unprivileged test caller"},
    {"id": "entry", "label": "Reachable lab entry point"},
    {"id": "sink", "label": "Security-relevant operation"}
  ],
  "initial_facts": ["caller-can-invoke-entry"],
  "context": {"device": "lab-api-35", "build": "fixture-001"},
  "edges": [
    {
      "id": "E-1",
      "from": "caller",
      "to": "entry",
      "type": "entry",
      "status": "confirmed",
      "prerequisites": ["caller-can-invoke-entry"],
      "establishes": ["attacker-input-at-entry"],
      "bindings": {"principal": "unprivileged-test-app", "session": "run-001"}
    },
    {
      "id": "E-2",
      "from": "entry",
      "to": "sink",
      "type": "data-flow",
      "status": "candidate",
      "prerequisites": ["attacker-input-at-entry"],
      "establishes": [],
      "bindings": {"session": "run-001"}
    }
  ]
}
```

The example is a modeling demonstration, not evidence that a real app has a vulnerability.

- A node requires a unique nonempty `id` (maximum 200 characters). Optional `label` is a nonempty string of up to 500 characters. Maximum 2,000 nodes.
- An edge requires unique `id`, existing `from` and `to` node IDs, `type`, and `status`. Maximum 5,000 edges.
- Supported types: `entry`, `data-flow`, `control-flow`, `authority`, `state-transition`.
- Edge status is `candidate` or `confirmed`, supplied by the analyst. The graph does not verify edge evidence.
- `prerequisites` and `establishes` default to empty arrays, at most 128 strings each. Facts are exact positive string tokens of up to 500 characters.
- `bindings` and graph `context` are string-to-string maps with up to 50 entries. Keys are at most 100 characters and values at most 500. Existing bindings cannot change along one path. New keys bind on first encounter.
- Graph `initial_facts` accepts at most 2,000 fact strings.

An edge is traversed only when its source equals the current node, all prerequisites are in the path's current fact set, and its bindings do not contradict the path context. Its established facts then become available to following edges. Facts from another path do not leak into the path. Unknown facts are unsatisfied. Merely finding a WebView and a provider in the same app never creates an edge.

Bindings model invariant conditions such as build, device, session, principal and account. If an actual transition changes state, represent distinct state facts/nodes or distinct context keys and review the transition explicitly. Negation, wildcard matching, numeric comparisons, symbolic execution, temporal constraints, fact revocation and arbitrary condition expressions are not implemented.

All nodes are considered possible starts, subject to prerequisites and context. Enumeration emits each eligible simple path prefix of sufficient length. No node is revisited within a path; cycles are counted and skipped. Defaults are two to six edges and at most 1,000 results. Flags allow `1 <= --min-length <= --max-length <= 12` and `1 <= --max-results <= 10000`. A fixed 50,000-edge-expansion budget also applies. The output records limits, `skipped` reasons and `truncated`. Length-bound skips may omit longer paths even when `truncated` is false; always inspect both fields.

Output status `confirmed-edges` means every edge on that path was labeled confirmed in the input. It does not mean the composed chain has been replayed or confirmed. Any other emitted path is `candidate`. The helper never updates ledger findings from graph results.

## Coverage schema

`coverage.json` requires integer `schema_version: 1` and `areas`, an array of at most 2,000 objects.

```json
{
  "schema_version": 1,
  "areas": [
    {"id": "ipc", "status": "in-progress", "notes": "One owned activity reviewed; receiver tests remain."},
    {"id": "native", "status": "blocked", "notes": "Matching native symbols unavailable."}
  ]
}
```

Each area has a unique nonempty `id` of up to 200 characters and a required `status`: `not-tested`, `in-progress`, `tested`, `blocked`, or `not-applicable`. Optional `notes` defaults to an empty string and is limited to 20,000 characters. Coverage is analyst-maintained. `tested` does not mean secure or exhaustive, and the helper does not verify coverage notes against artifacts. Empty coverage means unknown coverage. The report displays all states and explains uncertainty.

## APK/ZIP inventory limits

`intake` accepts a local ZIP-compatible file, including an APK. It reads the ZIP directory and hashes the complete file. It does not decompress members, decode binary AXML, read DEX instructions, verify CRCs, verify signing schemes or certificate trust, or validate installation. `apk_structure_hint` means only that a root `AndroidManifest.xml` entry exists.

1. Maximum input size: 1 GiB.
2. Maximum directory size: 16 MiB; maximum entries: 20,000.
3. Maximum declared uncompressed member size: 128 MiB; total: 512 MiB.
4. Maximum declared compression ratio: 200:1, using a one-byte denominator for zero-size compressed entries.
5. STORE and DEFLATE only. ZIP64, encrypted entries, multi-disk archives, symlinks and special files are rejected.
6. Absolute paths, traversal, ambiguous portable paths and case-insensitive duplicate names are rejected conservatively.

The metadata itself is untrusted. Passing intake is not proof that an archive is safe to extract or install. Keep untrusted files in an isolated analysis environment. An archive with otherwise legitimate uncommon encodings or ZIP features may be rejected by this deliberately narrow helper.

## Decoded manifest semantics

`manifest` accepts bounded UTF-8 decoded XML, not binary Android XML. DTDs and entity declarations are rejected. Maximum file size is 8 MiB and maximum elements is 50,000. Resource references, unresolved build placeholders and unrecognized boolean values remain unresolved. The output is an inventory of declarations and caveats, not an Android package parser or a list of confirmed vulnerabilities.

1. Application `enabled=false` dominates component enablement. Unknown enabled values are not silently treated as true.
2. Activities, services and receivers inherit application permission unless their own attribute overrides it. An explicit empty permission clears the inherited value.
3. Providers report general, read and write permission separately, including inherited values, path permissions and URI grant declarations.
4. For a provider with no explicit `exported`, targetSdk below 17 implies true. Device API 16 or below also implies true. TargetSdk 17+ on device API 17+ implies false. Missing device API or unresolved target keeps relevant cases conditional; the helper never assumes the latest device version.
5. Other components use the presence of intent filters for the legacy implicit exported default. Missing explicit exported with filters and targetSdk 31+ is separately marked invalid under Android 12+ parsing/build rules. This includes the activity-alias activity family; the provider is excluded from that requirement.
6. An alias target must resolve to an activity declared before it. Alias enablement combines application and alias flags; target activity enablement is reported separately. Alias permissions follow modern Android semantics and do not inherit the target or application permission. Historical platform parsing requires separate review.
7. Data declarations from all `<data>` elements in one intent filter are aggregated, so split scheme/host declarations remain visible. The helper retains original data elements and relative groups; it does not generate purported exact accepted URI lists or verify domain association.
8. `manifest_external_candidate` reflects declared enabled/exported conditions only. Permissions, code checks, runtime component overrides, installed splits, OEM behavior, caller identity, URI grants and Android version behavior can change reachability. No runtime reachability is claimed.

Primary references checked for these semantics:

- [Android application element](https://developer.android.com/guide/topics/manifest/application-element)
- [Android provider element](https://developer.android.com/guide/topics/manifest/provider-element)
- [Android activity alias element](https://developer.android.com/guide/topics/manifest/activity-alias-element)
- [Android intent filter data element](https://developer.android.com/guide/topics/manifest/data-element)
- [Android 12 safer component exporting](https://developer.android.com/about/versions/12/behavior-changes-12#exported)
- [AOSP activity and alias parser](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/com/android/internal/pm/pkg/component/ParsedActivityUtils.java)

## Data integrity, resource limits and limitations

- All JSON inputs are bounded to 8 MiB, must be UTF-8, and must not contain duplicate keys, NaN or Infinity. Duplicate IDs and unknown enumerated states are errors. Unknown additional object fields are ignored and are not evaluated; they confer no capability or verification.
- Each evidence file is bounded to 256 MiB; one verification run hashes at most 1 GiB of unique evidence. SHA-256 compares file bytes, not semantic meaning or provenance. No secret values are searched for or printed.
- Existing symlinks and Windows reparse points in input/output paths are rejected. Use a stable analysis directory that untrusted actors cannot modify concurrently. This cross-platform helper is not a filesystem-race isolation boundary or a protection against a malicious local administrator.
- Reports escape untrusted text rather than interpreting Markdown links, HTML or embedded instructions. The analyst should still treat names, comments and evidence as untrusted data.
- `doctor` uses `shutil.which` only. Presence on PATH is not a version, signature, health, compatibility or authorization check.
- `verify` checks all four schemas plus evidence paths/hashes and state retention requirements. It does not verify authorization paperwork, device state, vulnerability truth, severity, graph-edge evidence, coverage completeness, or whether the supplied APK matches a live installation.
- No command changes a source APK, manifest, scope, ledger, graph or coverage file. `init` only creates a new engagement; reports and analysis use new output files.

## Tests

```text
python -B -m unittest discover -s tests -p test_toolkit.py -v
```

The suite uses synthetic ZIPs, XML manifests, graphs and evidence. It tests traversal and symlink policy, resource bounds, export/version rules, permission inheritance, alias behavior, aggregate intent data, context conflicts, graph prerequisites/cycles, missing/changed artifacts, non-promotion of findings and output protection. A real filesystem symlink test is skipped when the operating system does not permit creating one; ZIP symlink rejection is tested independently. Test fixtures are temporary subdirectories under `tests` and removed after each test.
