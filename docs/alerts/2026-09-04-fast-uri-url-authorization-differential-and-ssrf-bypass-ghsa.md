# fast-uri: URL-authorization differential and SSRF bypass boundaries (GHSA)

Source: hourly offensive-security scan, 2026-09-04 late GitHub advisory wave (fast-uri cluster, 4 advisories). Durable because fast-uri is a fast URL parser used as the trust boundary in SSRF filters: the cluster shows the **parser's normalization is not the same as the connector's**, so an attacker-crafted URL passes the allow/block check but dials a different host than the one that was validated.

Primary entries: [GHSA-f65p-4m7j-42xc](https://github.com/advisories/GHSA-f65p-4m7j-42xc) (SSRF via malformed URL), [GHSA-fph4-wmhf-6fwf](https://github.com/advisories/GHSA-fph4-wmhf-6fwf) (SSRF via repeated/malformed host forms), [GHSA-5jgf-p345-68v8](https://github.com/advisories/GHSA-5jgf-p345-68v8) (host confusion via skipped IDN canonicalization), and [GHSA-jqff-g426-hqxp](https://github.com/advisories/GHSA-jqff-g426-hqxp) (host confusion via percent-encoded scheme).

!!! warning "Authorized validation only"
    Keep proofs to a local fast-uri harness and an owned no-content callback peer. Use crafted but harmless URL strings and record the *parsed* host vs. the *dialled* host. Do not reach cloud metadata, internal services, or production internal hosts.

## The reusable defect: parse-then-connect differential

fast-uri is typically the *checker* in an SSRF allow/deny list: code parses the URL, inspects `host`, decides allow/deny, then a *different* layer (or a re-parse) opens the connection. This cluster shows several ways the parsed host and the connected host diverge:

| GHSA | Crafted form | Parsed host | Connected host | Mechanism |
| --- | --- | --- | --- | --- |
| [GHSA-f65p-4m7j-42xc](https://github.com/advisories/GHSA-f65p-4m7j-42xc) | malformed URL | passes block check | internal/attacker host | structural malformedness the validator normalizes differently from the connector |
| [GHSA-fph4-wmhf-6fwf](https://github.com/advisories/GHSA-fph4-wmhf-6fwf) | repeated host segments / ambiguous authority | passes | internal/attacker host | repeated/ambiguous authority parsed to a different peer than validated |
| [GHSA-5jgf-p345-68v8](https://github.com/advisories/GHSA-5jgf-p345-68v8) | non-ASCII (IDN) host | IDN form passes allowlist | canonical (punycode/dotted) form dials | skipped IDN canonicalization in the checker |
| [GHSA-jqff-g426-hqxp](https://github.com/advisories/GHSA-jqff-g426-hqxp) | percent-encoded scheme/authority | decoded form validated | different peer after decode | percent-encoding the checker does not fully normalize |

The operator takeaway is the same as the Puma PROXY, Netty DNS/Redis, and Undertow parser-differential entries in this wiki: **the validation layer and the connect layer must normalize identically, and when they don't, the attacker supplies the divergence.**

## Replayable validation boundaries

### Parse-vs-connect host differential harness

1. Build a local harness that (a) parses a candidate URL with fast-uri and runs the *same* allow/deny predicate a target uses, and (b) opens a connection to an **owned no-content callback** using the *actual* connector path (or a stand-in that records the dialled authority).
2. For each crafted form (malformed, repeated-authority, IDN/non-ASCII, percent-encoded scheme/authority), record: the **parsed host** the validator sees, the **validator decision**, and the **dialled authority** the connector actually connects to.
3. A positive is validator = allow/deny-avoided **and** dialled peer ≠ validated peer. Keep the peer to your owned callback so the proof is the divergence, not a real internal reach.
4. Negative control: the same forms through a connector that re-canonicalizes identically (or the fixed fast-uri version); the dialled peer should match the validated peer.

### IDN canonicalization check

1. Use a non-ASCII host that, under full punycode/dotted canonicalization, maps to a host you control (or to an obviously different authority).
2. Confirm the checker retains the non-ASCII (un-canonicalized) form for the allowlist match while the connector resolves the canonical form.
3. Record the two forms side by side; the reusable fact is "checker skipped IDN canonicalization," proven with your own domains only.

## Durable operator value

1. **URL parsers are SSRF-filter trust boundaries.** Any stack that "check URL, then fetch URL" must be tested for parser/connector normalization drift. fast-uri is just the newest instance; the same class applies to WHATWG URL, Go's `net/url`, Python `urllib`, and hand-rolled parsers.
2. **Normalization gaps are the bypass, not the allowlist.** The allowlist is often correct; the bypass is that the *parsed* representation the allowlist matches on differs from the *connected* representation. Audit the exact transform between "what the filter checked" and "what the socket dials."
3. **Four canonical differential families.** Malformed/structural, repeated/ambiguous authority, IDN/non-ASCII, and percent-encoded scheme/authority. Test all four against any URL-based SSRF filter; most public bypasses are one of these.
4. **Proof is the two-host table.** The decisive, report-safe artifact is validated-host vs. dialled-host, with the dialled peer under your control. No internal reach, no metadata read.

## November 12 follow-up: Addressable five-pack, allowlist-vs-connector path divergence and display-host spoofing

Source: GHSA published 2026-11-12 22:23-22:44Z. The Ruby `addressable` gem shipped five advisories fixed in 2.9.1; two carry reusable operator value and pair directly with this page's parse-vs-connect rule.

**Allowlist path divergence ([GHSA-8gmh-2hhj-2hv9](https://github.com/advisories/GHSA-8gmh-2hhj-2hv9), CVE-2026-126354, `>= 2.2.5, < 2.9.1`).** `URI.normalize_path` removes dot segments by repeatedly finding the *first* `/segment/../` pair and replacing **every textual copy** of that pair in one `gsub` pass. When the first pair found is `/../../` (a `..` climbing above root), every later `/../../` is also deleted instead of removing the preceding segment. So `/../../public/x/../../secret` normalizes to `/public/x/secret` under Addressable but resolves to `/secret` under RFC 3986 (§5.2.4, e.g. Ruby's own `URI.join`, browsers, nginx, most connectors). `URI#normalize`, `#join`, `#==`, and `#===` all use this normalization. The exact bug shape this page exists for: an app that allowlist-checks the **Addressable-normalized** path and hands the **original** URI to something that resolves per RFC 3986 lets `/../../public/x/../../secret` pass a `/public/x/**` check while the connector fetches `/secret`. Precondition fingerprint: any Ruby stack where the checker uses `addressable` and the fetcher uses `URI`, `Net::HTTP`, Faraday, or a proxy re-resolve. Replayable check: run the candidate path through `Addressable::URI.parse(url).normalize.path` and `URI.join(base, path).path` side by side; a positive is any pair where the two differ and the allowlist matches the Addressable form. Include a `/segment/../`-first control (`/a/../../b/c/../../d` resolves correctly in both) to prove you triggered the above-root-clip leg, not generic traversal. Introduced in 2.2.5; 2.0.0-2.2.4 and 2.9.1+ resolve correctly, so the gem version is a live/vulnerable discriminator.

**Display-host spoofing ([GHSA-9crm-g4mf-wc5j](https://github.com/advisories/GHSA-9crm-g4mf-wc5j), CVE-2026-126348 and [GHSA-539f-xcgw-2gjg](https://github.com/advisories/GHSA-539f-xcgw-2gjg), CVE-2026-126349, `>= 2.0.0` pure-Ruby IDNA; native leg `>= 2.5.2`).** `IDNA.to_unicode` (used by `display_uri`) decodes invalid Punycode A-labels instead of returning them unchanged: `https://xn--google-.example.org/` **displays** as `google.example.org` while `#host`, `#normalized_host`, and the actual connection use `xn--google-.example.org`. The bidi leg decodes U+202E RTLO and invisible-isolate characters so `xn--abcmoc-dm0c.com` renders right-to-left as `abc moc.com`. Two operator rules: (1) display-vs-connect is the same differential as parse-vs-connect, just at the presentation layer; when phishing/link-preview/allowlist surfaces render `display_uri` or any `to_unicode` output, the displayed host is attacker-authored; (2) nameprep compliance is an audit surface in every IDNA path, including "native" ones: libidn rejects most prohibited codepoints but not post-Unicode-3.2 additions like U+061C and U+2066-U+2069, so pin your own prohibited-character battery (RTLO, isolates, zero-widths, invalid round-trip labels) against each renderer rather than trusting the library label. Prove with your own domains only: register one `xn--` label that renders as a canary brand string you own, and record displayed-host vs. connected-host side by side.

The three same-wave Addressable advisories (quadratic `normalize_path` [GHSA-qq38-m9mg-xjj5](https://github.com/advisories/GHSA-qq38-m9mg-xjj5), template ReDoS pair [GHSA-j82w-28jv-3pmj](https://github.com/advisories/GHSA-j82w-28jv-3pmj) / [GHSA-9f42-57jx-vpp3](https://github.com/advisories/GHSA-9f42-57jx-vpp3)) are availability-only and tracked without publication; note only that they share the 2.9.1 fix, so an unpatched `addressable < 2.9.1` in a Ruby stack means all five legs are live.

## Safety

- **Owned callbacks only.** The "bad" peer you demonstrate is your own no-content host, never a real internal or metadata address.
- **No internal/metadata access.** Even a single dial to `169.254.169.254` or an internal admin port is out of scope for a parse-differential proof.
- **Record, don't exploit.** Capture the parse/decision/dial table; do not chain into a real SSRF payload.
- **Display spoofing stays on your domains.** Register canary `xn--` labels for brands you own; never render a real third-party brand in report screenshots.

---

*Source: hourly offensive-security scan, 2026-09-04. All 4 fast-uri advisories tracked in the [source index](../notes/source-index.md).*
