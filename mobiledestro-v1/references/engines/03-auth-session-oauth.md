# Engine 03: Authentication, sessions, OAuth, and local gates

Research reviewed: 2026-10-13. Use only owned accounts and an approved identity-provider test tenant. Reset recovery and linking fixtures after every test. Do not attempt credential guessing or generate real-user messages.

## Trust model

| Stage | Record |
| --- | --- |
| Entry | Sign-in, OAuth callback, refresh, recovery, account linking, biometric prompt, device enrollment |
| Source | Browser response, code/token, state, nonce, verifier, account identifier, local callback |
| Transform | Callback parsing, transaction lookup, token exchange, claim mapping, session persistence |
| Check | Issuer/audience/signature, transaction binding, PKCE, replay/expiry, fresh authentication, server policy |
| Sink | Session creation, account association, privileged operation, release of protected key or data |

Model a login transaction separately from a user session. Record which identity owns the browser session, app session, authorization request, and final account.

## Source-backed protocol facts

Native public OAuth clients should use an external user agent and authorization-code flow with PKCE. Custom-scheme redirect interception must be evaluated together with code redemption protections. [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252.html)

Current OAuth security guidance addresses code injection, redirect validation, token replay, refresh-token protections, and transaction binding. A missing parameter is not by itself proof that every effective defense is absent. [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html)

Android biometric APIs can authorize cryptographic operations through a CryptoObject. The suitability of a prompt and fallback depends on the operation and authentication policy. [Biometric authentication](https://developer.android.com/identity/sign-in/biometric-auth)

## Decisive tests

1. Draw state transitions for signed out, login pending, signed in, step-up pending, linked, revoked, and recovered. Write each server invariant, such as a link requiring fresh authorization by both account owners.
2. Capture one complete owned-account login. Match the request, callback, and token exchange. Observe exact redirect handling, issuer, audience, state/nonce binding where applicable, PKCE method, and verifier origin. Redact live credentials in artifacts.
3. Within a test tenant, compare a valid transaction with a stale callback, a callback from a second simultaneous owned-account transaction, and a changed redirect. Change only one binding at a time; observe which account the server actually creates or associates.
4. For custom schemes, demonstrate interception using a separate lab APK only if scope allows installation. Determine whether the intercepted artifact is redeemable without the legitimate verifier; mere receipt of a code is not account takeover.
5. Test one refresh after logout, password reset, session revocation, or device removal according to the documented policy. Check both access and refresh tokens; distinguish a permitted short access-token lifetime from failed revocation of long-lived authority.
6. Test account switching while a protected request or linking callback is pending. Require the final server account identifier and audit/state response, not merely a screen title.
7. For local authentication, identify the protected asset and key policy. Compare normal success, cancel, timeout, fallback, and a diagnostic callback override. If an override changes navigation but the protected cryptographic operation fails, the security boundary may remain intact.
8. Inspect token verification and recovery code for claim/algorithm confusion, stale approval, and inconsistent endpoint enforcement. Use a local verifier fixture or staging endpoint for one invalid token; do not spray algorithm variants or codes.

## Negative controls and disqualifiers

- A public client identifier or embedded public verification key is not a secret.
- A custom scheme, absent CryptoObject, absent visible `state`, or long token lifetime requires context before classification.
- Root/instrumentation can alter client decisions. A callback override demonstrates changed client control flow under instrumentation; a defect requires a separate protected-asset or policy violation under the stated attacker model. It does not establish hardware key extraction or stock-device compromise.
- A UI-only account switch, failed token redemption, audience mismatch, or server-denied operation breaks the claimed account-takeover chain.
- Verify that a test has not reused the wrong account's proxy cookie or bearer token.

## Version and precondition caveats

Record identity-provider configuration, OAuth/OIDC library version, browser and App Link state, target SDK, supported biometric authenticators, key authorization settings, device lock state, and whether test hooks changed the relevant decisions. Check current provider documentation before assuming revocation or rotation guarantees.

## Chain edges and artifacts

Candidate edges: link interception to redeemable credential; weak transaction binding to wrong account association; stale refresh to new access authority; external route to unprotected local secret. Carry the actual artifact type, account owner, expiry, and required verifier across edges.

Save the auth state diagram, sanitized transaction correlation table, expected policy, token fingerprints rather than raw tokens, server-observed identities, negative controls, minimal sequence, and restoration notes.
