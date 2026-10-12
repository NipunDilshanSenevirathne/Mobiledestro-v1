# Engine 08: Cloud services, SDKs, and supply chain

Research reviewed: 2026-10-13. Discovering a project name, bucket, credential, or SDK does not authorize testing it. Prefer owner-provided configuration, emulators, dependency metadata, and seeded staging resources.

## Trust model

| Stage | Record |
| --- | --- |
| Entry | Firebase/other cloud SDK, analytics, push handling, remote config, update loader, build dependency |
| Source | Client identity, user token, object path, SDK event, remote manifest, package/artifact |
| Transform | SDK serialization, rules evaluation, cloud function, event enrichment, archive unpack/load |
| Check | User/object authorization, app attestation, IAM, consent, checksum/signature, provenance |
| Sink | Cloud record, storage object, push-driven action, telemetry recipient, app code, build output |

Separate project identification, user authentication, app attestation, resource authorization, and distribution integrity. One does not automatically replace another.

## Source-backed facts

Firebase API keys generally identify a project; database/storage protection comes from service authorization controls, and non-Firebase API restrictions still matter. Do not classify every embedded Firebase key as a credential leak. [Firebase API keys](https://firebase.google.com/docs/projects/api-keys)

App Check attests app/device authenticity and complements user authentication; it does not eliminate every abuse path. [Firebase App Check](https://firebase.google.com/docs/app-check)

Firestore's emulator supports rules tests with mocked identities. Server client libraries bypass Firestore Security Rules and require separate IAM/server authorization analysis. [Firestore rules testing](https://firebase.google.com/docs/firestore/security/test-rules-emulator)

Dependency verification can validate artifacts using checksums/signatures, but an approved verification policy still needs trusted review. Dynamic code loading introduces separate authenticity and storage concerns. [Gradle dependency verification](https://docs.gradle.org/current/userguide/dependency_verification.html), [Android dynamic code loading](https://developer.android.com/privacy-and-security/risks/dynamic-code-loading)

## Decisive tests

1. Build an asset table containing project/bucket/service, owning organization, explicit scope, environment, SDK version, credential type, and expected data policy. Keep unapproved assets in a passive inventory.
2. Obtain rules/configuration from the owner when available. Build a local rules matrix for anonymous, user A, user B, intended role, wrong tenant, and stale/custom claims using synthetic documents. Include document versus collection access and read/create/update/delete independently.
3. If live validation is authorized, access only an exact seeded resource. Compare owner and non-owner identities without broad listing or wildcard queries. A public product catalog and a private user document have different policies.
4. Test a cloud-function wrapper separately from its underlying datastore. Verify that administrative server access still enforces end-user identity, object ownership, allowed fields, and state transitions.
5. Examine App Check enforcement per product/environment. Distinguish a disabled staging policy, debug token, valid app token with wrong user, and invalid app token with valid user. Do not attempt to forge hardware attestation.
6. Inventory third-party SDK collection and initialization order. Compare synthetic event transmission before consent, after denial, after revocation, and after account switching; validate event destination and data classification.
7. Review push/deferred-link handlers as untrusted routing input. Trace message type, authenticated source, notification tap, account context, and final action. Sending messages requires an approved test project and owned recipient device.
8. From source/build metadata, create an SBOM with package identity, resolved version, artifact hash, source repository, and reachable usage. Match advisories using exact affected ranges and conditions. Presence alone is a candidate; demonstrate the affected path or state the evidence gap.
9. In a disposable build/update fixture, compare valid artifacts with one altered harmless artifact, wrong signer, stale manifest, and unexpected path. Review transitive dependencies, repository resolution, and verification metadata changes without modifying production pipelines.

## Negative controls and disqualifiers

- Project IDs, public API identifiers, intentionally public objects, inaccessible buckets, or an advisory name alone are not confirmed vulnerabilities.
- A `403` can reflect App Check, IAM, rules, region, or request format. Do not interpret every denial as proof all authorization is correct.
- Emulator results validate the supplied rules/configuration, not necessarily the deployed rules. Record the deployment match or uncertainty.
- A signature/checksum file is only meaningful if its trust source is protected independently from the artifact.
- Do not test a discovered privileged credential merely to demonstrate that it works; use owner-approved validation and avoid unrelated data access.

## Version and precondition caveats

Record SDK/service versions, rules hash, emulator version, deployment environment, project identity, enforcement settings, API restrictions, and test principals. Cloud behavior and dependency advisories change; refresh the official product/advisory source during each engagement.

## Chain edges and artifacts

Candidate edges: mobile configuration to scoped resource; cloud read to account-bound data; function wrapper to missing user policy; consent state to telemetry; approved update path to failed authenticity check. No edge grants permission to expand the asset list.

Save asset/scope mapping, redacted config, rules hash and test matrix, synthetic resource IDs, exact denied controls, deployment uncertainty, SDK data-flow table, SBOM, advisory applicability analysis, and disposable artifact-validation results.
