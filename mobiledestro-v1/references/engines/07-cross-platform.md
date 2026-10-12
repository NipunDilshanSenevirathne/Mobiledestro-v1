# Engine 07: Flutter, React Native, Unity, and hybrid apps

Research reviewed: 2026-10-13. Use the same authorization and proof requirements as native Android. Framework-specific tooling changes observability; it does not change the required attacker boundary.

## Trust model

| Stage | Record |
| --- | --- |
| Entry | Android component, framework route, web content, downloaded bundle, native plugin |
| Source | Intent/URI, JavaScript/Dart object, channel payload, asset, update metadata |
| Transform | Framework router, codec, generated binding, bridge dispatch, AOT/bytecode, native wrapper |
| Check | External reachability, origin, schema, account state, plugin permissions, update authenticity |
| Sink | Native capability, local storage, API request, WebView bridge, dynamic code execution |

Maintain one flow graph across languages. A channel is usually an in-process boundary; another app does not gain access merely because its name is discoverable.

## Source-backed facts

Flutter platform channels serialize messages between Dart and platform implementations; asynchronous communication and codecs must be included in the flow model. [Flutter platform channels](https://docs.flutter.dev/platform-integration/platform-channels)

React Native's AsyncStorage is unencrypted but remains within each app's sandbox. Sensitive values can also enter persisted state and telemetry. [React Native security](https://reactnative.dev/docs/security)

Capacitor exposes configurable server/navigation behavior, and Cordova's security guidance distinguishes navigation, network access, and content policies. Configuration must be interpreted for the actual version. [Capacitor configuration](https://capacitorjs.com/docs/config), [Cordova security](https://cordova.apache.org/docs/en/latest/guide/appdev/security/)

Unity's IL2CPP build path transforms managed code into native code; inventory the actual scripting backend before choosing analysis tools. [Unity IL2CPP](https://docs.unity3d.com/Manual/scripting-backends-il2cpp.html)

## Decisive tests

1. Identify the framework, exact version when supported by evidence, release/debug mode, shipped ABIs, bundles, source maps, plugins, and update mechanism. Hash artifacts before analysis. Treat a version guessed from strings as tentative.
2. Flutter: map platform-channel handlers, Pigeon bindings, plugin registration, Dart routes, FFI calls, and background isolates. Trace external Android input into each sensitive handler; inspect null/type/size checks and account context before asynchronous native work.
3. React Native: identify JavaScript versus Hermes bytecode and whether the app uses legacy modules, TurboModules, or JSI. Connect externally influenced values to native methods and persisted state. A `@ReactMethod` search alone is incomplete for newer architectures.
4. Unity: map Mono assemblies or IL2CPP metadata and native libraries to entry features. Review custom certificate handlers, import parsers, local entitlement state, and platform bridges; validate server authority before calling local state changes a privilege escalation.
5. Capacitor/Cordova: map main document origin, permitted navigations, popup handling, message dispatch, and plugin capabilities. Load a harmless owned-origin page through the actual route, then test only one bounded plugin operation against synthetic data.
6. For all frameworks, compare signed-out and account-switched execution while an asynchronous bridge result is pending. Determine whether the result is bound to the initiating identity or applied to the current identity.
7. For update packages, use a developer-controlled staging channel. Compare a valid signed fixture, an altered harmless bundle, stale version, and wrong-app metadata. Verify rejection before execution. Do not compromise or imitate a production update service.
8. Identify the networking implementation before observing traffic. Java TLS hooks may not cover native stacks. Any modified runtime or library must be recorded and confirmed against an unmodified control for the relevant claim.

## Negative controls and disqualifiers

- Bundle readability, source maps, native-module names, channel names, and lack of obfuscation do not independently prove sensitive capability exposure.
- A remote server URL is not automatically code execution by an attacker; establish control of delivered content and reachable plugin authority.
- Arbitrary instrumentation into a framework runtime does not establish an external JavaScript injection path.
- AsyncStorage plaintext requires an access path or relevant storage requirement, not a generic critical label.
- A modified TLS verifier is an observation aid, not proof the release app accepts invalid certificates.

## Version and precondition caveats

Record framework, plugin, bytecode, engine, WebView, ABI, and OTA-client versions. Decompilers and hardcoded native offsets can be version-specific. If symbols, mappings, compatible tools, or representative builds are missing, mark the unobserved edge and request the smallest useful developer artifact.

## Chain edges and artifacts

Candidate edges: external route to framework dispatcher; untrusted web content to plugin; pending callback to wrong account; unsafe update acceptance to execution of an approved marker; native plugin to provider/API effect.

Save a framework inventory, language-boundary graph, handler/signature map, bundle hashes, controlled-input/result pairs, update-validation matrix, network-stack identification, tool limitations, and stock-build controls. Continue each sink investigation in the matching native engine.
