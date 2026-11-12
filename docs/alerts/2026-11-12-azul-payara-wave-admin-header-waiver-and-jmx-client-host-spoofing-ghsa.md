---
title: Azul Payara wave (2 GHSAs): admin header presence skips checks, JMX trusts client host claims
---

# Azul Payara wave (2 GHSAs): admin header presence skips checks, JMX trusts client host claims

Azul Payara (GlassFish lineage) published two critical admin-plane advisories in one release train on 2026-11-12. Both bypass the "admin access is only allowed from localhost/secure-admin networks" boundary, and both do it by trusting a value the remote client supplies: the mere presence of an authentication header, and a spoofed client host address. Either one escalates to administrative command execution, so the pair is worth a dedicated page despite being only two advisories.

**Wave in one line:** the REST admin interface waives its remote-rejection check when `X-GlassFish-authToken` is merely present and then falls through to a blank-password default, and the JMX/RMI authenticator grants admin when the claimed client host address passes.

Primary sources:

- Admin REST `X-GlassFish-authToken` remote-access waiver: [GHSA-gv3m-v36g-qfr6 / CVE-2026-110003](https://github.com/advisories/GHSA-gv3m-v36g-qfr6) (critical, unauthenticated)
- `GenericAdminAuthenticator` JMX/RMI client-host spoofing: [GHSA-qcx2-v78c-8gq4 / CVE-2026-90908](https://github.com/advisories/GHSA-qcx2-v78c-8gq4) (critical, unauthenticated; Payara Micro affected only when the JMX connector is enabled)
- Fix bands per vendor release notes (GHSA package version fields are empty, so band from the advisories themselves): [Payara 7.6.0](https://docs.azul.com/payara/release-notes/release-notes-7.6.0.html), [Payara Community 7.2026.11](https://docs.azul.com/payara-community/release-notes/release-notes-7.2026.11.html), [Payara 6.44.0](https://docs.azul.com/payara/version/6/release-notes/release-notes-6.44.0.html), [Payara 5.93.0](https://docs.azul.com/payara/version/5/release-notes/release-notes-5.93.0.html), [Payara 4.1.2.191.61](https://docs.azul.com/payara/version/4/release-notes/release-notes-4.1.2.191.61.html)

!!! warning "Lab instances, canary MBeans, no credential abuse"
    Run a disposable Payara/Payara Micro instance, prove the REST leg by reaching an innocuous admin read command (version/list) rather than deploy or config mutation, and bind JMX proofs to a synthetic marker MBean or an attribute read on a lab-only MBean server. Never attach to a production admin port, register persistent MBeans, redeploy applications, or use captured admin access beyond the authorized target.

## Boundary map

| Surface | Trusted decision | Detached state | Bounded positive |
| --- | --- | --- | --- |
| Admin REST (`:4848`) | remote requests rejected unless secure-admin/localhost | presence of `X-GlassFish-authToken` skips the remote-rejection check before the token is validated; invalid token falls through to password auth, which passes with the empty default admin password | remote `GET` of an admin read command returns data from an off-host client on default config |
| JMX/RMI admin connector | client host address inside the admin-allowed set | attacker-controlled claimed host address satisfies `GenericAdminAuthenticator` | remote JMX connection opens and reads a lab marker MBean attribute |

## 1. Header-presence-before-validation is a fail-open switch

The REST flaw is a two-step ordering bug worth memorizing:

1. The remote-rejection check is gated on **whether the auth header exists**, not on what it contains. Supplying any `X-GlassFish-authToken` value makes the request look like a token-authenticated local call, so the "reject non-local admin" gate is never consulted.
2. Token validation then fails on the garbage value, but failure **falls through** to password-based authentication instead of terminating. Default domain installs have an empty admin password, so password auth succeeds with no credentials.

Operator translation: on any admin console, HTTP management API, or actuator-style interface:

- Send the privileged-shape battery **unauthenticated**: attach plausible auth headers with junk values (`X-GlassFish-authToken: x`, plus product-lineage variants and generic ones like `X-Auth-Token`, `Authorization: Bearer x`) and diff responses against the header-absent baseline. A 200 where the bare request got 401/403 is the presence-gate fingerprint.
- Treat "invalid token falls through to another auth method" as its own bug class: the fallback usually has weaker defaults (blank password, anonymous bind, default account). Pair every fall-through path with the product's default-credential posture before dismissing "but the token still has to be valid."

## 2. JMX/RMI admin gates that take the client's word for who you are

`GenericAdminAuthenticator` restricts the JMX/RMI admin connector by client host, and the advisory says a spoofed client host address defeats it. Host-claim channels to enumerate on any JMX/RMI or socket-adjacent management listener:

1. Request-embedded host fields in the handshake (RMI/IIOP codebase-style channels have carried caller-controlled values before, cf. the August 4 WildFly/ORB record on the June 22 control-plane page).
2. Forwarding/proxy headers when the listener sits behind anything that rewrites source IP (`X-Forwarded-For`, PROXY protocol), making the "admin network" decision dependent on a header.
3. DNS reversibility: if the check resolves the peer and compares hostnames, attacker-controlled PTR records for your own IP impersonate an admin host.

Genealogy: OpenDJ's JMX RMI listener deserializing unauthenticated bytes (June 22 page) and the Spinnaker/Glances management-listener lineage. The durable rule stands: **enumerate every management listener separately (REST admin port, JMX/RMI port, admin CLI port), because each has its own auth implementation and its own default exposure.**

## 3. Fingerprinting and engagement notes

- GHSA package version fields are empty across both advisories: this is the vendor-advisory banding fingerprint, treat the Azul release-notes pages as the authoritative fixed versions and confirm the target build before reporting.
- Payara Micro's JMX exposure is opt-in ("only when its JMX connector is enabled"): feature-gated listeners are a scan-time tell, sweep container images and startup flags for `-Djavax.management.builder...`/`--jmx` style enablement rather than probing blind.
- The REST leg works against **default** domain configuration with the empty admin password; on hardened installs the token fall-through still skips the locality gate, so remote-brute-of-admin-password remains reachable, a different severity tier worth stating separately in reports.
- GlassFish-lineage products (Oracle GlassFish, Payara, and derivative app servers) should be re-swept on both channels whenever one lineage member gets an admin-plane advisory; sibling re-sweep rule from the HPE ClearPass and FalkorDB records.

## Evidence and reporting checklist

- [ ] Target build mapped to a fixed/unfixed band from the Azul release notes, not from empty GHSA fields.
- [ ] REST proof uses a read-only admin command; response diff vs header-absent baseline captured.
- [ ] JMX proof bound to a lab marker MBean; no MBean registration or attribute writes on shared hosts.
- [ ] Secure-admin enabled/disabled, JMX connector enabled/disabled (Micro), and admin-password-set/blank recorded as preconditions.
- [ ] No production deploys, config writes, or persistent state changes; rollback notes for any lab config touched.

## Tracked from the same wave without publication

- Zohocorp ManageEngine cross-product RCE pair (CVE-2026-12507 Reports-module query RCE gated on Create Query Reports permission, CVE-2026-12591 M365 Manager Plus delegated-admin scope escalation): authenticated permission-gated RCE, thin descriptions, no new axis beyond the existing permission-drift corpus.
- Microchip TimePictra quad (hardcoded root password CVE-2026-8332, stored XSS CVE-2026-8333, unrestricted upload CVE-2026-8331): known default-credential/upload/XSS classes, NTP appliance, no reusable new pattern.
- Git clone/commit path traversal writing arbitrary files (CVE-2026-113408, low): known malicious-repo class, revisit if a fix diff clarifies the sink.
- MISP Wikidata-lookup SPARQL injection + error-text credential leak (CVE-2026-126991): authenticated enrichment-query tampering, thin.
- Simple JWT Login CSRF <=3.6.8 (CVE-2026-125836), Akaunting invoice-import stored XSS (CVE-2026-118855): WP/PHP single-product classes.
- Qt QDomDocument NULL-deref DoS (CVE-2026-82292), BOSH openstack CPI credential handling (CVE-2026-47832), rejected duplicate CVE-2026-123133: not promotable.
