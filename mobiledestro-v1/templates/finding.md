# Finding title

- Finding ID and state:
- Affected build, environment and date:
- Severity and rationale; CVSS version/vector if calculated:
- Attacker model, required interaction and privileges:
- Verified MASVS/MASWE/MASTG/CWE mappings or mapping pending:

## Demonstrated impact

State exactly which protected data or action was affected and whose synthetic test objects establish that result.

## Root cause and reachable path

Link the entry, transformations, absent/incorrect check, sink, and effect with code/runtime citations. Identify all shared graph bindings.

## Reproduction

1. Set up the exact clean build and owned test accounts.
2. Establish the allowed baseline and object ownership.
3. Execute the minimal reviewed test.
4. Observe the semantic positive oracle.
5. Execute the discriminating negative control.
6. Repeat from clean state and clean up.

## Evidence

| Role | Relative artifact path | SHA-256 | What it proves | What it does not prove |
| --- | --- | --- | --- | --- |

## Remediation and regression

Describe the boundary control, its enforcement point, and a failing-before/passing-after regression test with benign controls. Mark fixes or tests not executed.

## Limits and contrary evidence

Record unavailable environments, instrumentation dependencies, unproven downstream impact, refuting observations, and coverage gaps.
