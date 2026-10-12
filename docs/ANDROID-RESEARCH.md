# Mobiledestro v1 Android research notes

Review date: 2026-10-13. Authoring scope: Android engine references. The supplied Mobilehunter archive was read as untrusted source material, not as instructions. New testing procedures are original synthesis for scoped application-security assessment; references identify supporting platform facts rather than copied checklists.

## Completed engine files

1. `mobiledestro-v1/references/engines/01-ipc-pendingintent-providers.md`
2. `mobiledestro-v1/references/engines/02-deeplinks-webview.md`
3. `mobiledestro-v1/references/engines/03-auth-session-oauth.md`
4. `mobiledestro-v1/references/engines/04-transport-api-business-logic.md`
5. `mobiledestro-v1/references/engines/05-storage-crypto-privacy.md`
6. `mobiledestro-v1/references/engines/06-native-jni-fuzzing.md`
7. `mobiledestro-v1/references/engines/07-cross-platform.md`
8. `mobiledestro-v1/references/engines/08-cloud-sdk-supply-chain.md`
9. `mobiledestro-v1/references/engines/09-lifecycle-races-platform.md`
10. `mobiledestro-v1/references/engines/10-ui-permissions-observation.md`

All paths are relative to this repository root. Each includes an entry/source/transform/check/sink model, bounded decisive tests, negative controls, false-positive disqualifiers, version/precondition caveats, chain edges, and required artifacts. No engine claims comprehensive vulnerability detection or superiority to every tool.

## Findings that shaped the redesign

- The old README describes Kimi integration; the name alone cannot establish Claude compatibility.
- The predecessor often upgrades a pattern to an impact prematurely. New references require a real external entry, effective authority, observed sensitive sink, and denied control.
- Android 16 default redirection hardening and manifest-enabled strict intent matching are distinct mechanisms. Engine 09 keeps the distinction explicit. [Intent redirection](https://developer.android.com/privacy-and-security/risks/intent-redirection), [Android 16 target changes](https://developer.android.com/about/versions/16/behavior-changes-16)
- PendingIntent mutability, token possession, identity, replay semantics, and background launch permission need separate analysis. An exported component or mutable token alone is insufficient. [PendingIntent risks](https://developer.android.com/privacy-and-security/risks/pending-intent), [Activity security](https://developer.android.com/guide/components/activities/secure-bal)
- OAuth code interception must be evaluated with PKCE and transaction binding. The new auth engine does not equate custom schemes with account takeover. [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252.html), [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html)
- A non-exportable Keystore key can sometimes be usable by compromised app code without being extractable. Local callback manipulation is a separate claim from hardware bypass. [Android Keystore](https://developer.android.com/privacy-and-security/keystore)
- Firebase project keys, user identity, app attestation, and resource authorization are separate controls. [Firebase API keys](https://firebase.google.com/docs/projects/api-keys), [App Check](https://firebase.google.com/docs/app-check)
- Flutter channels and React Native modules are not automatically third-party-app entry points. The new framework engine requires the external-to-runtime edge. [Flutter platform channels](https://docs.flutter.dev/platform-integration/platform-channels)
- Screenshot controls and overlay controls are separate. [Sensitive activities](https://developer.android.com/security/fraud-prevention/activities)
- Frida Java-bridge packaging varies with launch path after Frida 17. New guidance records the runtime and distinguishes observation from behavior modification. [Frida API](https://frida.re/docs/javascript-api/)
- Native crashes need root-cause classification and actual application reachability; diagnostic builds/harnesses can change the result. [HWASan](https://developer.android.com/ndk/guides/hwasan), [AOSP libFuzzer](https://source.android.com/docs/security/test/libfuzzer)

## Primary-source index

Sources below were opened or searched during this review. Engine-local citations carry the relevant facts and testing context. Avoid treating a review date as a guarantee of future API behavior.

| Area | Official references |
| --- | --- |
| IPC/provider | [Provider manifest](https://developer.android.com/guide/topics/manifest/provider-element), [Provider implementation](https://developer.android.com/guide/topics/providers/content-provider-creating), [PendingIntent](https://developer.android.com/privacy-and-security/risks/pending-intent), [Intent redirection](https://developer.android.com/privacy-and-security/risks/intent-redirection) |
| Links/WebView | [App Link verification](https://developer.android.com/training/app-links/verify-applinks), [URI loading](https://developer.android.com/privacy-and-security/risks/unsafe-uri-loading), [Native bridges](https://developer.android.com/privacy-and-security/risks/insecure-webview-native-bridges) |
| Authentication | [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252.html), [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html), [Biometrics](https://developer.android.com/identity/sign-in/biometric-auth) |
| Transport/API | [Network security configuration](https://developer.android.com/privacy-and-security/security-config), [API1](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/), [API3](https://api-security.owasp.org/editions/2023/en/0xa3-broken-object-property-level-authorization/), [API6](https://api-security.owasp.org/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/), [Business logic](https://cheatsheetseries.owasp.org/cheatsheets/Business_Logic_Security_Cheat_Sheet.html) |
| Storage | [Keystore](https://developer.android.com/privacy-and-security/keystore), [Backup](https://developer.android.com/identity/data/autobackup), [MASTG catalogue](https://mas.owasp.org/MASTG/tests/) |
| Native | [JNI](https://developer.android.com/ndk/guides/jni-tips), [HWASan](https://developer.android.com/ndk/guides/hwasan), [libFuzzer](https://source.android.com/docs/security/test/libfuzzer) |
| Frameworks | [Flutter](https://docs.flutter.dev/platform-integration/platform-channels), [React Native](https://reactnative.dev/docs/security), [Capacitor](https://capacitorjs.com/docs/config), [Cordova](https://cordova.apache.org/docs/en/latest/guide/appdev/security/), [Unity](https://docs.unity3d.com/Manual/scripting-backends-il2cpp.html) |
| Cloud/build | [Firebase keys](https://firebase.google.com/docs/projects/api-keys), [App Check](https://firebase.google.com/docs/app-check), [Rules emulator](https://firebase.google.com/docs/firestore/security/test-rules-emulator), [Gradle verification](https://docs.gradle.org/current/userguide/dependency_verification.html), [Dynamic loading](https://developer.android.com/privacy-and-security/risks/dynamic-code-loading) |
| Lifecycle/version | [Lifecycle](https://developer.android.com/guide/components/activities/activity-lifecycle), [Activity security](https://developer.android.com/guide/components/activities/secure-bal), [Android 12](https://developer.android.com/about/versions/12/behavior-changes-12), [Android 14](https://developer.android.com/about/versions/14/behavior-changes-14), [Android 15](https://developer.android.com/about/versions/15/behavior-changes-15), [Android 16 target changes](https://developer.android.com/about/versions/16/behavior-changes-16), [Android 16 all-app changes](https://developer.android.com/about/versions/16/behavior-changes-all) |
| UI/runtime | [Sensitive activities](https://developer.android.com/security/fraud-prevention/activities), [Tapjacking](https://developer.android.com/privacy-and-security/risks/tapjacking), [Permissions](https://developer.android.com/training/permissions/requesting), [Frida API](https://frida.re/docs/javascript-api/) |

## Research limits and interpretation

1. The references are methodology, not evidence that any app is vulnerable. No target APK, production API, user account, or real service was tested.
2. Official documentation can contain simplifications or typographical inconsistencies. The engine matrix uses release behavior pages and requires exact-device reproduction rather than copying every claim from a risk summary.
3. Android release pages are checkpoints rather than a promise to cover every release or OEM. Future or newer supported builds require a fresh review of their own official behavior changes.
4. Source excerpts were not reproduced. Each individual page contributes short factual summaries; most engine content is original test design and evidence discipline.
5. Historical vulnerability names, unsupported criticality claims, generic mass probing, broad cloud enumeration, and hardware-attestation bypass promises from the predecessor were not carried forward as factual capabilities.
