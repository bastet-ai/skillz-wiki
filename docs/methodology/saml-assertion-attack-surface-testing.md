---
title: SAML assertion attack-surface testing
---

# SAML assertion attack-surface testing

Sources: [Trail of Bits — SAML: A fractal of bad design](https://blog.trailofbits.com/2026-09-21/saml-a-fractal-of-bad-design/) (2026-09-21); foundational attack research: [On Breaking SAML: Be Whoever You Want to Be (USENIX Sec '12)](https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91.pdf), [Identity Theft Attacks on SSO Systems / XML comment bypass (Black Hat USA '18)](https://i.blackhat.com/us-18/Thu-August-9/us-18-Ludwig-Identity-Theft-Attacks-On-SSO-Systems.pdf), [Go stdlib XML round-trip disclosures (2020)](https://mattermost.com/blog/coordinated-disclosure-go-xml-vulnerabilities/), [Abusing libxml2 quirks to bypass SAML authentication on GitHub Enterprise (2025)](https://repzret.blogspot.com/2025/02/abusing-libxml2-quirks-to-bypass-saml.html), [Sign in as anyone: Bypassing SAML SSO with parser differentials (GitHub, 2025)](https://github.blog/security/sign-in-as-anyone-bypassing-saml-sso-authentication-with-parser-differentials/), [SAML roulette: the hacker always wins (PortSwigger, 2025)](https://portswigger.net/research/saml-roulette-the-hacker-always-wins), [The Fragile Lock: Novel Bypasses for SAML Authentication (PortSwigger, 2025)](https://portswigger.net/research/the-fragile-lock).

!!! warning "Authorized testing only"
    SAML assertions authenticate humans into real tenants. Run mutation batteries only against lab IdP/SP pairs you own or engagements where SSO testing is explicitly scoped. Proofs must stop at "attacker-chosen synthetic principal resolved a session"; never access other users' accounts, never sign in as a real person, never harvest assertions captured from live traffic.

## Why SAML is still a first-class target

The ToB post is a retirement essay, but for an operator it is a target-surface map. The core insight worth stealing: SAML "works if you assume XML signature validation is reliable," and XML signature validation is complex enough that most fielded implementations wrap `libxmlsec` or equivalent libraries nobody audits. Every layer between the raw bytes and the authorization decision — XML parser, canonicalization (C14N), reference/transform pipeline, signature placement, SAML schema handling, identity linking — is an independent parser with its own opinion. Differentials between them are the finding class, and 2025's SAML roulette / Fragile Lock / GitHub Enterprise work proved the class is still landing in flagship products.

Corollary for prioritization: when a target offers SAML SSO, treat the SP's assertion-handling code path as the highest-value auth surface on the app, above the login form itself. A break there yields arbitrary-principal session issuance, not a single account.

## The attack surface layers

Enumerate per layer; each has a distinct mutation family.

| Layer | Bug classes to hunt | Field evidence to collect |
| --- | --- | --- |
| XML parser / DTD | XXE, entity expansion (billion laughs), DTD retrieval (SSRF), CDATA/XInclude/XSLT injection | Stack traces, error verbosity, outbound callbacks from canary DTDs |
| Canonicalization (C14N) | Comment/whitespace insertion inside signed regions, exclusive-vs-inclusive c14n disagreement, round-trip re-serialization drift | Byte diffs between submitted, canonically-signed, and re-parsed trees |
| Enveloped signature | XSW (signature wrapping), signature placement variants, `Reference URI` mutation, `Transforms` manipulation, same-digest-multi-copy | Which copy the verdict reads vs which copy the identity extract reads |
| SAML schema / conditions | `AudienceRestriction`, `SubjectConfirmationData` (Recipient/NotOnOrAfter/InResponseTo), `OneTimeUse`, `Conditions` presence-only checks | Accept/reject decision table per stripped/mutated condition |
| Binding layer | Redirect vs POST vs artifact binding parity, HTTP-Redirect signature coverage gaps, relay-state handling | Per-binding verdict table for the same assertion |
| Identity linking | Email-assertion vs configured-criterion binding, auto-link on unverified email, tenant derived from asserted email domain | Linking decision given attacker-controlled IdP or cross-org provider |

## Mutation battery (lab-proven order)

1. **Fingerprint first.** Fetch SP metadata (usually `/saml/metadata` or a published XML endpoint) — it discloses bindings, ACS URL, NameID format, signing expectations, and library fingerprints without touching auth.
2. **Baseline canary.** Sign a synthetic assertion with your own lab IdP for a synthetic principal; confirm accept, capture raw submitted / stored / served / decision bytes separately.
3. **XSW family.** Insert the signed `Assertion` inside an unsigned wrapper; duplicate the `Assertion` with modified identity; move `<Signature>` to alternate allowed positions. The verdict-vs-identity-copy mismatch is the finding.
4. **Canonicalization family.** Add XML comments inside signed elements, reformat whitespace, reorder attributes, switch namespace prefixes; re-request and watch for one library's "valid" surviving while the identity extractor reads the mutated copy. Comment-bypass variants against `SignatureValue` and `DigestValue` regions specifically.
5. **Condition-stripping matrix.** Remove `AudienceRestriction`, strip `OneTimeUse`, zero/omit `NotOnOrAfter`, swap `Recipient`, reuse the assertion a second time (replay), test assertions without `SubjectConfirmationData` at all.
6. **Binding-parity table.** Deliver the same mutated assertion via every binding the metadata advertises; a control enforced on POST but absent on Redirect/artifact paths is the drift.
7. **Round-trip check.** If the SP re-serializes before verifying (Go `encoding/xml` heritage especially), test the round-trip asymmetries from the 2020 Mattermost disclosures against that copy.
8. **Identity-linking review.** With two disposable tenants, test whether provisioning/linking resolves by asserted email domain, whether unverified provider emails auto-link, and whether the configured matching criterion is actually consulted (the Sept 16 Prowler and WP SAML SSO advisories were both this class).

## Shape-normalization signal

The ToB post quotes the pragmatic defense: reject any SAML message that doesn't have the same shape as what Okta/OneLogin/Google/Shibboleth emit. Operational inversion: **that check is your bypass target**. If an SP shape-normalizes, collect real-shaped traffic from your own legitimate logins on the tenant, then mutate only within the shape grammar the normalizer tolerates — normalization that rewrites before verification reintroduces the canonicalization differential one layer up.

## Cross-references on this wiki

- [Canonicalization differentials at security gates](canonicalization-differentials-at-security-gates.md) — the general gate-vs-sink representation-drift rule; SAML is its densest instance.
- [JWT algorithm confusion testing](jwt-algorithm-confusion-testing.md) — the JSON-era sibling protocol's equivalent mutation family.
- [Keycloak OIDC/SAML/WebAuthn boundary batch](../alerts/2026-06-04-keycloak-mlflow-auth-boundary-batch-ghsa.md) and its SAML `OneTimeUse` replay follow-up.
- [Sentry SAML / identity-linking batch](../alerts/2026-04-30-sentry-patreon-locize-identity-boundary-batch-ghsa.md); [SimpleSAMLphp SP multi-IdP state binding](../alerts/2026-07-02-developer-dashboard-identity-file-boundaries-ghsa.md); [CoreWCF WS-Security XSW](../alerts/2026-06-19-agent-secret-identity-render-boundary-batch-ghsa.md); [Okta Access Gateway SAML-to-LDAP/SQL sinks](../alerts/2026-09-09-okta-oag-hyperdrive-config-injection-and-identity-boundaries-ghsa.md); [Prowler SAML tenant-from-asserted-email ATO](../alerts/2026-09-16-saml-tenant-claim-mcp-metadata-jsonapi-marketplace-and-route-authorization-ghsa.md).

## Proof boundary and reporting

Bounded positive: attacker-constructed or attacker-mutated signed canary → SP resolves an **attacker-chosen synthetic principal** → session marker observed → deleted. Report the exact mutation (kept assertion bytes in the report appendix, principal synthetic), the library/version fingerprint, the binding it works on, and the decision table. Do not report "SAML is bad"; report which copy of the document the signature check and the identity check read.

## Durable lesson

SAML attacks never needed new bug classes — they need fresh implementations that re-derive trust from a multi-layer XML pipeline. The ToB post's thesis is the operator's business model: every layer that "mostly works" is a differential waiting for the next parser version, the next language port, the next SP library. When SAML appears in scope, run the layer table top-to-bottom before touching anything else on the app.
