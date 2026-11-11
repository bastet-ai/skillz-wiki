---
title: Template, signing-key, upload, and alternate-route authority boundaries
---

# Template, signing-key, upload, and alternate-route authority boundaries

Nine August 5 records expose a reusable operator pattern: an application treats template text, a deployment-wide signing key, an upload destination, a sibling handler, or rich content as less powerful than the sink that ultimately consumes it. Test the full authority transition with patched sinks and inert canaries rather than executing the effect.

Discovery and validation seeds:

- Eclipse Mojarra remote Facelet inclusion [GHSA-wrxx-w58g-3gqp](https://github.com/advisories/GHSA-wrxx-w58g-3gqp);
- DjangoCRM mass-mail template evaluation [GHSA-qwf5-72hq-pg7x](https://github.com/advisories/GHSA-qwf5-72hq-pg7x) and committed deployment-wide `SECRET_KEY` [GHSA-qc6p-hvpv-4f8h](https://github.com/advisories/GHSA-qc6p-hvpv-4f8h);
- MacCMS10 template blacklist gaps [GHSA-cv48-22qx-mpmx](https://github.com/advisories/GHSA-cv48-22qx-mpmx);
- `wp-downloadmanager` upload-type and destination-path controls [GHSA-cc9f-29gq-5x7c](https://github.com/advisories/GHSA-cc9f-29gq-5x7c);
- toner-management state-changing sibling handlers without authorization [GHSA-c6wq-2527-5fpx](https://github.com/advisories/GHSA-c6wq-2527-5fpx);
- XWiki Blog post-title rendering [GHSA-h2xq-h7f9-vh6c](https://github.com/advisories/GHSA-h2xq-h7f9-vh6c);
- Invoice Ninja invoice/quote terms rendering [GHSA-84j5-x242-f7h8](https://github.com/advisories/GHSA-84j5-x242-f7h8); and
- openHAB CometVisu tokenless proxy and browser-render boundary [GHSA-v7gr-mqpj-wwh3](https://github.com/advisories/GHSA-v7gr-mqpj-wwh3).

Several were unreviewed GitHub/NVD mirrors when this page was written. Treat them as test hypotheses, confirm the exact route and revision in upstream source, and do not infer an affected range, fixed version, or exploit chain that the primary project does not establish.

!!! warning "Disposable applications and denied sinks only"
    Use synthetic content, fake keys, owned HTTP peers, isolated upload roots, no-op mutation handlers, patched template evaluators, and detached script-disabled DOM parsers. Never include remote templates in production, forge real sessions or reset links, upload executable content, mutate application data, probe internal services, or execute template expressions, PHP, or JavaScript.

## 1. Inventory every text-to-template transition

Template vulnerabilities are not one payload class. Build a provenance table before testing:

| Surface | Attacker-controlled value | Compiler/evaluator boundary | Privilege to verify |
| --- | --- | --- | --- |
| Mojarra Facelet | include/resource URL | URL resolution, resource load, Facelet compile | server file/network and template context |
| DjangoCRM mass mail | subject or body | string interpolation followed by Django `Template()` | template context and recipient rendering |
| MacCMS10 editor | template condition/content | blacklist followed by ThinkPHP template compilation | generated PHP/process identity |

Replace the final URL loader, filesystem reader, template compiler, and dangerous callable resolution with recorders. Exercise ordinary literals, delimiter-only canaries, nested expressions, encoded delimiters, alternate include forms, absolute and relative resources, and values that cross multiple formatting passes.

A bounded positive is **a field documented as data -> reaches a template grammar -> parser or patched compiler records an expression/include node with server authority**. Do not execute the node. A literal brace or template error is not enough; preserve the parsed form and exact sink.

For Mojarra, use only an owned HTTP fixture and a disposable local canary path. Record raw resource value, normalized URL, scheme, final peer, resolved resource identity, and denied compile decision. Keep network fetch, local-file selection, and template execution as separate claims.

For blacklist-based editors, test capability classes rather than publishing function names or working payloads. Record which AST node or callable category survives the filter. A missing blacklist entry is reportable only when the same value reaches an executable template context under the tested role.

## 2. Treat a committed signing key as a deployment assumption to prove

Do not paste the published DjangoCRM key into evidence or mint an authenticated cookie. Build two clean disposable installations from the affected revision and one corrected installation. Instrument key loading and token verification, then record only a SHA-256 fingerprint of the loaded synthetic key.

Test this matrix:

| Build pair | Expected invariant |
| --- | --- |
| two clean affected installs | must not share a deployment signing-key fingerprint |
| restart of one install | retains its own generated secret through the documented mechanism |
| corrected install without configured secret | fails closed or generates a unique persistent value as documented |
| explicit synthetic secret | loads only from the approved deployment source |

If two independent installs load the same repository-derived signing key, use an offline serializer/verifier harness with a fake principal and inert claim. Stop when the verifier records acceptance of a canary object created under the other disposable install's key. Do not create an admin session, reset a password, or test a public deployment.

Report the primitive precisely: **shared signing authority across clean installations**. Session takeover, CSRF bypass, or reset-token forgery requires separate proof that the affected framework actually signs and accepts that artifact with this key and that no additional state invalidates it.

## 3. Bind upload type and path to one approved storage root

Create a temporary upload root and a sibling directory containing only random marker names. Replace the final move/write call with a recorder. For `wp-downloadmanager`, capture:

1. caller role and exact capability;
2. original and normalized filename;
3. declared and byte-derived media type;
4. raw destination selector;
5. canonical parent and final path;
6. storage and public-serving origin; and
7. final denied write decision.

Exercise benign text/image bytes with ordinary, unknown, and dangerous-looking extensions; absolute and relative destination values; dot segments; encoded and platform separators; and symlinked parents. Do not upload code or test execution.

Separate two findings:

- **type boundary:** benign bytes with a disallowed executable-looking name would be stored or served in an active context; and
- **path boundary:** the canonical target escapes the approved upload root.

A caller holding an upload-management capability may intentionally add files, but that does not imply authority to choose arbitrary host paths or executable server types.

## 4. Enumerate sibling handlers independently of listing pages

The toner-management record illustrates route-family drift: list pages can enforce access while direct add, edit, and delete handlers do not. Extract routes from source or framework metadata and build a matrix by resource family, operation, method, and authentication state.

Seed one synthetic object per family and replace every INSERT, UPDATE, and DELETE with a no-op recorder. Replay no credential, invalid credential, low-role credential, and intended admin credential against list, form, submit, direct-ID, bulk, and alternate-extension routes. Record middleware, in-handler checks, resolved object, policy decision, and denied mutation.

A strong result is **protected list/form sibling -> direct state-changing handler omits equivalent authentication or authorization -> no-op sink receives only the synthetic object ID**. Never create, alter, or delete real records. Do not infer that all handlers are exposed from one missing check; enumerate each route.

## 5. Trace rich content through its exact render context

XWiki post titles and Invoice Ninja terms demonstrate why sanitization must match the final parser context. Use an inert custom element, a disallowed attribute name, and encoded delimiter markers. Disable scripting and inspect only a detached DOM.

Capture every representation:

- request or API field;
- validation/sanitization output;
- stored value;
- server-rendered HTML;
- browser parser context such as `<title>`, element body, attribute, or rich-text container; and
- detached DOM node/attribute result.

Test the same marker across list, detail, preview, email/PDF generation, client portal, and admin views. Context changes matter: text safe in a normal element may terminate a raw-text element, while approved rich text may still be unsafe in an attribute or document title.

A bounded positive is **synthetic field -> final serialized markup changes parser structure or preserves an event-capable attribute -> detached parser records the inert node**. Do not execute script, access storage, or capture a session. A field accepting HTML is not itself XSS when the product intentionally supports sanitized rich text.

## 6. Separate proxy reachability from response rendering

For the openHAB CometVisu proxy, use two owned listeners: one public control and one isolated denied canary. Inventory authentication, allowed methods, redirect handling, DNS resolution, final socket peer, returned headers/body, and the browser context that consumes the response.

A tokenless proxy request reaching an owned denied peer establishes an outbound-request boundary. Browser impact requires separate evidence that returned canary markup enters an active same-origin render context. Keep these claims independent and never point the proxy at loopback, metadata, or a real internal service.

## Reporting boundaries

- Preserve field provenance, parser/AST output, role, route family, and denied sink,not an executable payload.
- Shared keys prove shared signing authority; stronger account impact requires artifact-specific verification in a disposable lab.
- Upload acceptance, outside-root path selection, public serving, and execution are separate transitions.
- Missing authorization requires the direct handler and no-op mutation sink, not merely an unlinked route.
- Render findings require final parser-context evidence; never call stored text XSS from storage alone.
- SSRF evidence names the final owned peer and response sink; it never uses real internal or metadata targets.
