# Django REST framework coordinated wave: attacker-named codec amplification, Accept-header negotiation burn, and silent token-revocation failure

**Wave in one line:** three high-severity DRF advisories published 2026-10-22 16:16–16:18Z, all fixed in 3.18.2, each with published code analysis and working PoC — one pre-auth memory-amplification primitive, one pre-auth CPU-exhaustion shape tuned below server kill thresholds, and one credential-revocation failure that returns success.

Source: hourly offensive-security scan of GitHub Security Advisories, 2026-10-22 (16:1xZ window). DRF is one of the most deployed API stacks in bug-bounty scope, and all three legs are reachable with stock configuration — no feature flags, no unusual settings.

!!! warning "Authorized validation only"
    Use your own lab deployment or explicitly authorized targets. The amplification and CPU-burn legs are availability attacks: run them only against disposable instances you own, never against shared or production API endpoints. The revocation leg is a local model-behavior proof, no network needed.

## Legs

### 1. JSONParser applies an attacker-named codec to the request stream — `DATA_UPLOAD_MAX_MEMORY_SIZE` defeated 466,000x

[GHSA-3547-9m27-7rxg](https://github.com/advisories/GHSA-3547-9m27-7rxg) / [CVE-2026-114136](https://nvd.nist.gov/vuln/detail/CVE-2026-114136), high, `djangorestframework < 3.18.2`.

`JSONParser.parse` decodes the request body with the charset from the client's own `Content-Type` header: `codecs.getreader(encoding)(stream)`. Of ~455 codec names CPython resolves, ~18 are **byte transforms, not character sets** (`bz2_codec`, `zlib_codec`, `base64_codec`, `hex_codec`, `quopri_codec`, `uu_codec`…) and `codecs.getreader` is the only `codecs` entry point that never consults `CodecInfo._is_text_encoding`. Sending `Content-Type: application/json; charset=bz2_codec` wraps the stream in a bz2 decompressor before `json.load`.

The exploitability is **ordering**: Django's `DATA_UPLOAD_MAX_MEMORY_SIZE` is charged against wire bytes at `HttpRequest.body`; decompression happens *afterwards, inside the parser, where nothing is counting*. A 108-byte body yields a 50,331,648-character string in the view (466,033x amplification, ~97 MiB peak RSS growth). The sink has existed since 3.6.4 (2017).

Operator rules:

- **Validation-stage budget ≠ consumption-stage budget.** Every size/quota gate must be re-checked at the last transformation before the resource is materialized. On any API stack, fuzz the encoding/compression parameter set (`charset=`, `Content-Encoding:`) with *transform* names, not just compression ids — gzip/br/bz2/zlib each have different amplification and different gate placement.
- Fingerprint: does the framework reject `charset=base64_codec` outright (fails closed, good sign) or accept the request (parser will decode)? One request, no auth, zero side effects on a correct build — this doubles as a hidden-behavior fingerprint for "which HTTP stack is behind this WAF".
- Sibling asymmetry is informative: DRF's own `FormParser`/`MultiPartParser` take the same client-named encoding but fail closed. Same repo, same field, different sink strictness — always prove each parser family separately.

### 2. Accept header with many large quoted params burns ~19 s of CPU per request

[GHSA-33wh-fxxf-88vv](https://github.com/advisories/GHSA-33wh-fxxf-88vv) / [CVE-2026-114138](https://nvd.nist.gov/vuln/detail/CVE-2026-114138), high, `djangorestframework < 3.18.2`.

Content negotiation re-parses each Accept token ~6 times per request (three renderers × passes, plus a *forced second negotiation* just to render the 406 error), and Django's `parse_header_parameters` is quadratic when a quoted parameter value packs semicolons (quote-recounting from string start per candidate separator). Working shape: **96 separate `Accept:` fields of ~8.1 KB each** — each token stays under Django's 10,000-char media-type cap and each field under gunicorn's default `limit_request_field_size 8190` — pins one sync worker for 18.87 s of pure CPU. Two concurrent requests wedge a default two-worker deployment.

Operator rules:

- **Error paths re-run the expensive path.** If rendering the rejection response repeats the very parsing that failed, your mitigation budget doubles before the attacker pays anything. Probe: does a 406/415 cost more CPU than a 200? Time it.
- Header *aggregation* rules are part of the limit surface: Django caps one media-type string, gunicorn caps field size and count — the payload is shaped to slip under *each layer's individual* cap while the sum is unbounded. Multi-value header splitting defeats single-layer header limits on any stack; count `N fields × M bytes` against the *negotiation parser*, not the transport gate.
- Dedup that collapses identical tokens (`order_by_precedence` uses a set) just means you send N *distinct* tokens. Blocklist-shaped defenses (rate-limit on repeated header, dedupe) leak against enumeration.

### 3. `TokenProxy.delete()` reports success and revokes nothing

[GHSA-xw6w-gcfp-cf8m](https://github.com/advisories/GHSA-xw6w-gcfp-cf8m) / [CVE-2026-114137](https://nvd.nist.gov/vuln/detail/CVE-2026-114137), high, `djangorestframework < 3.18.2`.

`TokenProxy` overrides `pk` to return `user_id`, but the concrete `Token` table keys on `key`. `Model.delete()` builds `DELETE ... WHERE key IN ('1')` — matches nothing, raises nothing, returns `(0, {...})`. Every admin panel, script, or API route that revokes DRF tokens through the proxy **believes it revoked a token that is still live**. DRF shipped its own workarounds (`TokenAdmin.delete_model` re-fetches the concrete row; bulk actions disabled with a "mapped IDs" comment) — proof the vendor knew, and proof the silent path was never closed.

Operator rules:

- **Revocation is a claim you must re-test.** Standard post-engagement or post-incident checklist item: after a token delete, *replay the token*. Status code 200 on delete means nothing; the kill is only real when the next authenticated request 401s. Same rule killed the pyLoad auth-cache leg and the OTRS/SmarterMail refresh legs — revocation has its own code path, and its own bugs.
- Proxy/view model overriding `pk` to remap identity + generic ORM delete built from `pk` = **delete-target and identity-claim disagree structurally**. Greppable in any framework: `class .*Proxy`/view-model with a `pk` property over a table keyed differently.
- The vendor's own admin path being safe while every other caller is not is the classic **shipped-workaround fingerprint**: fix exists as a call-site convention, not in the primitive. Grep how *your* target deletes tokens — admin console vs API route vs script take different paths.
- The PoC's control design is the reusable bit: prove the row *was* deletable and the credential *was* live (direct-model delete → 401) before claiming the proxy delete failed. A 200-with-no-revoke is only evidence with both controls.

## Cross-run genealogy

Leg 3 lands in the same revocation-integrity family as pyLoad `check_apikey` auth-cache (June 8 page), OTRS JWT-survives-password-change (Oct 12 page), and SmarterMail stale-role refresh (Oct 9 page): credential-kill paths fail silently across products, and every one is proven by replay-after-delete, never by the delete response. Leg 1 is the validation-vs-consumption ordering family (Sept 15 http4s/parser page, Coraza caps-without-signal page). Leg 2 is a new axis: *negotiation-path* CPU as the exhaustion surface — distinct from body parsing, distinct from transport limits.
