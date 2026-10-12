# Engine 05: Storage, cryptography, backups, and privacy

Research reviewed: 2026-10-13. Seed distinctive synthetic values, avoid collecting unrelated app data, and distinguish authorized forensic inspection from an ordinary attacker's access.

## Trust model

| Stage | Record |
| --- | --- |
| Entry | Login, local save, import/export, backup/restore, telemetry, cryptographic operation |
| Source | Sensitive field, token, key, document, consent state, attacker-controlled file |
| Transform | Serialization, caching, logging, compression, encryption, derivation, backup selection |
| Check | Sensitivity and purpose policy, file access, key authorization, nonce uniqueness, authenticity, retention |
| Sink | File, database, preference, cache, log, crash report, backup, third-party SDK, decrypted output |

Track data classes and intended lifetime. Separate key confidentiality, authorized key use, ciphertext integrity, and plaintext exposure; these are different properties.

## Source-backed facts

Android Keystore keeps key material non-exportable and can restrict key use. A compromised app process may still use an available key, so observing encryption/decryption does not prove extraction. Hardware support and enforcement vary by key/device. [Android Keystore](https://developer.android.com/privacy-and-security/keystore)

Backup rules depend on OS, target SDK, and transport. Some device-to-device transfer behavior differs from cloud backup even when `allowBackup` is false; modern data-extraction rules must be inspected by transfer type. [Auto Backup](https://developer.android.com/identity/data/autobackup)

Android's testing catalogue evolves and contains deprecated tests alongside their replacements. Map evidence to the current MASVS category and verified weakness/test reference rather than inventing a test identifier. [OWASP MASTG tests](https://mas.owasp.org/MASTG/tests/)

## Decisive tests

1. Create a data-lifecycle table: acquisition, processing, storage, sharing, backup, deletion. Give each synthetic marker a separate class so a cache hit is not mistaken for a production secret.
2. Compare state before login, after a sensitive operation, after logout/account switch, and after approved deletion. Inspect preferences, Room/SQLite and sidecar files, DataStore, WebView data, caches, external files, logs, analytics queues, and crash payloads accessible in the lab.
3. For every occurrence, identify the realistic reader: target process, ordinary app, granted provider recipient, backup recipient, physical-device holder, or root. Reproduce one permitted access path under the claimed model.
4. Map cryptographic calls to key origin, algorithm/mode, nonce/IV generation, associated data, and error handling. With a local fixture, compare repeated encryption and a one-byte ciphertext change. Determine whether invalid data is rejected before use and whether metadata is authenticated.
5. Check hardcoded material semantically. Classify public identifiers, certificates, test fixtures, static encryption keys, and service credentials separately. Validate privilege using owner-supplied configuration or an approved harmless test endpoint; do not submit discovered credentials to arbitrary services.
6. Inspect Keystore parameters and actual security level where available. Test canceled/expired authentication, key invalidation, missing key after restore, and fallback paths using developer fixtures. Never downgrade hardware claims based on emulator-only evidence.
7. Exercise backup and restore on two disposable lab instances using the relevant transport. Determine whether restored authority remains valid and whether excluded data is re-created elsewhere. Do not rely on manifest flags alone.
8. For privacy, compare observed collection/transmission with the app's declared purpose and consent state. Test pre-consent, denied, revoked, and account-switched states with synthetic data. Preserve only the minimum relevant payload fields.

## Negative controls and disqualifiers

- Readable data inside a protected sandbox is not automatically exposed to other apps. Identify the actual unauthorized reader or a documented at-rest requirement.
- A high-entropy string, Firebase configuration value, unused debug code, public certificate, or obsolete secret is not a confirmed credential leak.
- Encryption mode names alone do not establish practical compromise. Explain attacker control, repeated nonce/key conditions, authenticated context, and the affected asset.
- A plaintext value seen through a hook inside an already compromised process does not prove Keystore extraction.
- A sensitive artifact intentionally retained under an approved policy differs from failure to honor deletion or account boundaries.

## Version and precondition caveats

Record storage APIs, scoped-storage behavior, OS/target SDK, backup transport, OEM, lock state, Keystore security level, root/debug privileges, and installed app build. `adb backup` assumptions from older Android releases are unreliable. Treat dependency deprecations as maintenance context, not immediate vulnerabilities.

## Chain edges and artifacts

Candidate edges: provider/export to readable sentinel; stale restored token to valid session; cache crossing account boundary; unauthenticated metadata to unsafe import; telemetry to unapproved recipient. Prove the resulting capability with Engine 01, 03, or 04.

Save a redacted data-flow inventory, file locations and permissions, marker fingerprints, lifecycle diffs, key-policy summary without keys, crypto input/output metadata, backup rules and observed transport results, consent-state matrix, and cleanup record.
