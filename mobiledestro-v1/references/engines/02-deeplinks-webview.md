# Engine 02: Deep links, App Links, and WebView

Research reviewed: 2026-10-13. Use an owned test origin, a harmless page marker, and synthetic accounts. Do not register third-party domains or collect real tokens to prove a routing issue.

## Trust model

| Stage | Record |
| --- | --- |
| Entry | Browser link, exported router, notification, QR result, share/import flow |
| Source | Outer URI, nested URL, path, query, fragment, redirect response, frame or message sender |
| Transform | Decoding count, normalization, route extraction, redirect resolution, HTML construction |
| Check | Scheme/host/port/path policy, verification state, origin check, authentication and account binding |
| Sink | Navigation, WebView load, JavaScript evaluation, native bridge, file/network access, account mutation |

Keep the outer Android route, the final network origin, and each frame's origin separate. A verified outer link does not automatically authorize a nested destination.

## Source-backed platform facts

URI validation should examine parsed scheme and host; string prefix or substring checks can mistake untrusted destinations for trusted ones. [Unsafe URI loading](https://developer.android.com/privacy-and-security/risks/unsafe-uri-loading)

`addJavascriptInterface` objects are exposed to frames, while message-based bridges require sender/origin checks. An exposed method becomes a security issue when untrusted content can reach sensitive behavior. [WebView native bridges](https://developer.android.com/privacy-and-security/risks/insecure-webview-native-bridges)

App Link verification is asynchronous, and manual user associations affect routing. A pending verification result differs from verified, force-approved, or denied state. Android 11 and earlier use different multi-host verification behavior from Android 12 onward. [Verify App Links](https://developer.android.com/training/app-links/verify-applinks)

## Decisive tests

1. Build the route table from every relevant intent filter, alias, navigation definition, framework router, and runtime callback. Include `onCreate` and `onNewIntent`, authenticated and unauthenticated states, and redirect chains.
2. Trace one route to its final sink before generating cases. For each parser boundary, compare an exact permitted destination with one single-field mutation: scheme, authority, subdomain boundary, port, encoding depth, path segment, or duplicate parameter. Use owned hosts only.
3. Capture the value before validation and the value actually loaded. Distinguish parsing disagreement from a validation bypass that reaches a sensitive sink.
4. Test main-frame navigation, a harmless embedded frame, controlled redirect, and an application-triggered window separately. Record whether restrictions apply to all navigation paths, including client callbacks and resource loads.
5. Enumerate bridge methods and message handlers from native and framework code. Associate each with its required origin, argument schema, session state, and capability. Use a harmless marker-returning method or developer fixture; never infer sensitive access merely from enumeration.
6. If a bridge processes privileged commands, validate one bounded command against owned data and compare the same command from an allowed and denied origin. Trace any further server authorization.
7. Verify App Link behavior from an ordinary browser and separate APK on clean lab state. Save domain-verification output and chooser/default-app state. Explicit component launching is a separate reachability claim from opening a web link.
8. Inspect cookie, DOM storage, cache, certificate-error callbacks, mixed content, file/content access, and download handling only in relation to the proven route. Test whether logout and account switching remove the relevant authority.

## Negative controls and disqualifiers

- JavaScript enabled, WebView debugging, custom schemes, an unverified domain, permissive navigation, or a bridge name alone are not account takeover.
- An instrumented `loadUrl` replacement proves diagnostic reachability only; repeat through the real input path.
- A blocked redirect, absent sensitive bridge, different isolated WebView, or server rejection may break the proposed chain.
- Cookie presence does not prove that JavaScript can read it or that a request can exercise account authority. Record the actual observable capability.
- Missing App Links is not sufficient for an OAuth finding; apply Engine 03's transaction and PKCE tests.

## Version and precondition caveats

Record Android API, target SDK, Android System WebView package/version, framework/plugin version, browser, app install source/signing certificate, user defaults, and network state. Do not carry old file-URL or pre-annotation bridge behavior into modern builds without reproduction. Test the distributed release artifact as well as a diagnostic build if available.

## Chain edges and artifacts

Potential edges: accepted external route to owned origin; untrusted frame to bridge; bridge to file or account operation; callback to authenticated server transition. Confirm origin and authority continuity at every edge.

Save a route inventory, parser trace, URI cases with expected/observed outcomes, origin/frame timeline, bridge signature map, controlled-page hash, verification state, sanitized request logs, negative controls, and the smallest working sequence. Keep test hosting ephemeral and remove it after the engagement.
