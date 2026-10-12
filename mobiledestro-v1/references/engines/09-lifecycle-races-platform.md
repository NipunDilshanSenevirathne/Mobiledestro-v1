# Engine 09: Lifecycle, races, and platform differences

Research reviewed: 2026-10-13. Security properties may depend on time and state even when each individual function appears correct. Test a small hypothesis-driven state matrix on disposable instances; do not turn race analysis into uncontrolled request flooding.

## Trust model

| Stage | Record |
| --- | --- |
| Entry | Resume, process recreation, new intent, work retry, notification, permission change, account switch |
| Source | Saved state, stale callback, queued command, current principal, grant, pending transaction |
| Transform | Restoration, coroutine/thread dispatch, cache reuse, retry, migration, delayed commit |
| Check | Current identity, version/generation, freshness, authorization at commit, atomicity, cancellation |
| Sink | Rendered sensitive data, server commit, local file, permission use, replayed action |

Write temporal invariants, for example: a request created by account A must never commit using account B's authority, and a revoked grant must not authorize a newly opened resource.

## Source-backed platform facts

Android can destroy and recreate activities; callbacks, saved state, and process lifetime are distinct concerns. Test restored state through the supported lifecycle rather than assuming a foreground activity persists. [Activity lifecycle](https://developer.android.com/guide/components/activities/activity-lifecycle)

Background activity launches have conditional restrictions, including target-dependent PendingIntent creator/sender opt-ins. Capture both parties' state and SDKs before deciding whether a launch is reachable. [Activity security](https://developer.android.com/guide/components/activities/secure-bal)

## Platform checkpoint matrix

| Checkpoint | Consequence to verify |
| --- | --- |
| Android 12 / target 31 | Explicit exported declarations for filtered activities/services/receivers; explicit PendingIntent mutability; changed backup behavior |
| Android 14 / target 34 | Restrictions on implicit delivery to unexported components and mutable PendingIntents without a component/package |
| Android 15 / target 35 | PendingIntent creator background-launch privileges require the relevant opt-in |
| Android 16 | Default intent-redirection hardening; assess the actual nested-intent path |
| Android 16 strict intent matching | Separate receiver-side manifest opt-in; do not confuse it with default redirection hardening |

The table selects testing checkpoints, not a complete compatibility specification. Read the exact release, API reference, opt-outs, and OEM conditions for each build. [Android 12 target changes](https://developer.android.com/about/versions/12/behavior-changes-12), [Android 14 target changes](https://developer.android.com/about/versions/14/behavior-changes-14), [Android 15 target changes](https://developer.android.com/about/versions/15/behavior-changes-15), [Android 16 target changes](https://developer.android.com/about/versions/16/behavior-changes-16), [Intent redirection](https://developer.android.com/privacy-and-security/risks/intent-redirection)

## Decisive tests

1. Define the state tuple: installed version, process generation, active account, auth freshness, app foreground state, connectivity, permission/grant state, and queued work. Change one dimension at a time before combining states.
2. Begin a harmless owned-account operation, delay it with a developer-controlled barrier, switch account or revoke authority, then release it. Observe identity and authorization at the final commit rather than only at initial scheduling.
3. Compare normal resume, rotation/configuration recreation, background process death, cold start, and a new intent delivered to a warm instance. Check whether restored deep links, selected objects, and navigation arguments are revalidated.
4. Test one offline queued operation across logout and reconnect. Verify whether stored credentials, current credentials, or neither are used; confirm which account owns any resulting server change.
5. For a local check/use hypothesis, synchronize two controlled fixture operations around the suspected boundary. Compare sequential and paired runs with unique generation markers. Stop once the invariant violation is established; quantify reproducibility without mass attempts.
6. Exercise grant revocation, permission denial, lock/unlock, or key invalidation between check and use using the supported lab APIs. Distinguish already-open resource semantics from a fresh unauthorized access.
7. Compare supported OS/target combinations around the relevant checkpoint. Use the same APK where possible. When rebuilds change target SDK or code, record both changes and do not attribute all differences to OS alone.
8. Review migrations, reinstall/restore, work rescheduling, and retry idempotency using disposable data. Confirm the state after recovery and the fate of pending operations.

## Negative controls and disqualifiers

- A timing difference, duplicate UI event, stale screen, or canceled request is not a committed unauthorized effect.
- Artificially changing identity or authorization in hooks can manufacture a defect; use supported external transitions or disclose the diagnostic precondition.
- Process death differs from force-stop, and existing file descriptors differ from new opens. Preserve these distinctions.
- Compatibility overrides, shell privileges, root, debug builds, and manually approved links can invalidate ordinary-device claims.
- Failure on one emulator does not show all versions are safe or vulnerable.

## Version and precondition caveats

Record OS/API/patch, target SDK, OEM, WebView and service versions, process state, foreground state, and every compatibility override. Use the checkpoint matrix to choose comparisons, then verify each exact build. Permission/grant transitions, already-open handles, account changes, and cached authentication all have different lifetimes. Missing device coverage remains an explicit limitation.

## Chain edges and artifacts

Candidate edges: stale callback to wrong principal; revoked authorization to queued operation; process restoration to bypassed validation; mutable shared state to invalid commit. Every edge needs state before/after and a commit-time oracle.

Save a state machine, transition table, timing/barrier trace, process/account generation identifiers, OS/target/OEM matrix, permitted-versus-denied sequence, repeatability count, artifact hashes, and exact modifications made for observation.
