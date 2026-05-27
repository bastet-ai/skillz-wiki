# Template, container, CMS, ICS, and signature-boundary batch (GHSA, 2026-05-26)

**Signal:** GitHub Advisory Database published a dense batch of advisories after the prior Skillz Wiki pass. The promotable operator value is not the advisory list itself; it is the set of reusable boundary tests across template sanitizers, upload filters, container runtimes, CMS lookup APIs, industrial web consoles, spacecraft/mission-control algorithm engines, and JSON-LD signature verification.

Promoted items:

- `GHSA-2qv6-9wx5-cwv4` / `CVE-2026-44644`: LiquidJS `strip_html` newline tag bypass to XSS.
- `GHSA-7g26-2qgj-chfg` / `CVE-2026-44587`: CarrierWave `content_type_denylist` regex metacharacter bypass for MIME types such as `image/svg+xml`.
- `GHSA-rr59-xxvx-96qr` / `CVE-2026-44210`: Kata Containers virtiofsd extra-argument annotation host-root sharing / VM escape boundary.
- `GHSA-9hx7-c53c-v6x8` / `CVE-2026-44177`: Kirby CMS pre-auth user lookup path traversal and constrained PHP file inclusion.
- `GHSA-86rh-h242-j8xp` / `CVE-2026-44174`: Kirby CMS REST collection query arbitrary model-method calls.
- `GHSA-rg3m-cfq7-g6h6` / `CVE-2026-43947`: FUXA unauthenticated script test-mode confused-deputy RCE when a permissive server-side script exists.
- `GHSA-p69w-mmfv-xrfj` / `CVE-2026-43945`: FUXA path-confusion auth bypass against Node-RED paths in affected deployments.
- `GHSA-524g-x36v-9wm6` / `CVE-2026-44632`: Yamcs Janino-backed algorithm text injection to host command execution for users with mission-database change privileges.
- `GHSA-9rfg-v8g9-9367` / `CVE-2026-42462`: Fedify Linked Data Signature bypass through JSON-LD shape changes such as `@graph`, `@included`, and `@reverse`.

Use these as authorized validation patterns. Keep testing scoped, use benign markers, and avoid destructive host writes or production credential exposure.

## Operator checklist

### 1. Newline-in-tag sanitizer bypasses

Where to look:

- LiquidJS deployments and downstream products that render user-controlled text through `{{ value | strip_html }}`.
- Comment fields, profile text, CMS snippets, email templates, product descriptions, markdown-to-Liquid pipelines, or preview endpoints that treat `strip_html` as a sanitizer.

Safe proof shape:

1. Confirm the app uses vulnerable `liquidjs` `<= 10.25.7` or an embedded copy with the same regex behavior.
2. Submit a harmless multiline HTML tag marker with a newline or carriage return inside the tag boundary.
3. Verify whether the rendered response still contains a browser-parsable tag instead of stripped text.
4. Demonstrate impact with a non-sensitive callback or DOM marker in a lab account, not cookie theft.

Reporting heuristic: frame this as **HTML parser tolerance beating regex sanitizer assumptions**. Strong reports show the exact sink, template expression, rendered response, and absence of a later escaping layer.

### 2. MIME denylist regex bypasses in upload filters

Where to look:

- Ruby/Rails apps using CarrierWave `content_type_denylist` for SVG, XHTML, XML, or other MIME types containing regex metacharacters.
- Public file uploads whose stored object is later rendered inline from the application origin or a trusted CDN origin.

Safe proof shape:

1. Confirm vulnerable CarrierWave versions: `< 2.2.7` or `>= 3.0.0.beta, < 3.1.3`.
2. Identify denylist entries that include regex metacharacters, especially `+` in `image/svg+xml`.
3. Upload an inert SVG or XHTML marker that proves the blocked content type was accepted.
4. If impact depends on rendering, prove same-origin inline delivery with a harmless DOM marker in an isolated account.

Reporting heuristic: report **denylist entry interpreted as regex, not literal MIME**. Include configured denylist, uploaded content type, storage path, and delivery context.

### 3. Default-enabled container annotations crossing into host filesystem

Where to look:

- Kubernetes or containerd environments using Kata Containers with pod creator access.
- Configurations where `enable_annotations` allows `virtio_fs_extra_args` and `kernel_params` or equivalent runtime escape hatches.

Safe proof shape:

1. Confirm the runtime class uses vulnerable Kata Containers before the patched commit/version.
2. Read the runtime config to verify annotation allowlist exposure.
3. In a dedicated lab node, use benign host marker files and read-only validation where possible.
4. Prove whether guest-side virtiofs mounting exposes host-root metadata, hostname, or a pre-created marker file.
5. Do not read secrets such as `/etc/shadow` in customer environments; proving host-root reachability is enough.

Reporting heuristic: frame as **pod annotation value becomes unsanitized virtiofsd command-line control**. Tie exploitability to pod-create permissions, runtime class selection, and host impact.

### 4. CMS lookup and query APIs as filesystem or method-call oracles

Where to look:

- Kirby CMS `5.3.0-5.4.0` user lookup paths reachable through auth or user APIs.
- Kirby Panel/API deployments with authenticated lower-privilege users who can issue collection search, filter, sort, group, pluck, or related query options.

Safe proof shape:

1. For pre-auth lookup traversal, test for directory-existence differences and controlled inclusion of non-sensitive `index.php` fixtures in a lab clone.
2. For arbitrary method calls, use harmless methods first (`root()`-style path disclosure) before attempting sensitive methods.
3. Avoid destructive methods (`delete()` and write actions) unless the customer explicitly provides a disposable target.
4. Capture patched behavior on Kirby `4.9.1` or `5.4.1` when possible.

Reporting heuristic: distinguish **pre-auth path traversal in user identity resolution** from **authenticated method exposure through collection query attributes**. They are adjacent but have different prerequisites and impact.

### 5. Industrial web consoles: project metadata to script execution

Where to look:

- FUXA deployments exposed on internal OT networks, labs, or vendor-managed remote-access surfaces.
- FUXA `1.3.0` with server-side scripts and permissive script permissions.
- FUXA `>= 1.2.11, < 1.3.1` with Node-RED enabled, especially when auth middleware makes path decisions from the full URL rather than the parsed path.

Safe proof shape:

1. Use `GET /api/project` only to inventory script IDs/names and permission posture in authorized scopes.
2. Prove test-mode execution with a benign marker such as a unique string, file in a disposable temp directory, or loopback callback controlled by the tester.
3. For Node-RED path-confusion checks, validate access to a harmless protected endpoint rather than modifying flows.
4. Never manipulate PLC tags, MQTT/OPC-UA data, or live industrial workflows during validation.

Reporting heuristic: report the chain as **guest-accessible project metadata + stored-script permission check + attacker-supplied test code execution**, or as **query-string path confusion bypassing auth middleware for Node-RED routes**.

### 6. Mission-control algorithm expression engines

Where to look:

- Yamcs instances where users can change mission databases or algorithm definitions.
- Algorithm execution backends that compile expression text with Janino or similar Java compilers.

Safe proof shape:

1. Confirm affected `org.yamcs:yamcs-core < 5.12.7`.
2. Verify the tester account has `ChangeMissionDatabase` or equivalent privileges before claiming exploitability.
3. In a test instance, change a disposable algorithm to produce a benign outbound callback or marker value.
4. Trigger the algorithm through normal telemetry simulation and record the callback/marker.
5. Restore the original algorithm text after validation.

Reporting heuristic: frame as **application-level mission-database privilege to host-level code execution via unsandboxed dynamic compiler**. This is privilege escalation inside the platform, not anonymous RCE.

### 7. JSON-LD signatures and tree-shape confusion

Where to look:

- Fedify deployments and ActivityPub implementations that accept Linked Data Signatures.
- Signature-verification paths that normalize the RDF graph but then process the original JSON tree shape.
- Payload parsers that do not reject or compact away JSON-LD keywords and aliases such as `@graph`, `@included`, and `@reverse`.

Safe proof shape:

1. Capture a legitimate signed activity in a controlled federation lab.
2. Transform the JSON-LD tree shape while preserving the signed graph, for example moving an activity/object relationship into a named graph.
3. Confirm the signature still verifies while the application processes a different root object or loses selected properties.
4. Use benign activity types and lab actors; do not impersonate real third-party users.

Reporting heuristic: report **signature verification over one representation, application semantics over another**. Include both the verified canonical form and the parsed application object.

## Non-signal this hour

Reviewed but not promoted as standalone guidance:

- `GHSA-8xx9-69p8-7jp3` LiquidJS render-limit DoS guard bypass: useful for resilience testing, but this pass prioritized exploit-path and boundary-crossing guidance.
- `GHSA-w5r6-mcgq-7pq4`, `GHSA-p2rj-mrmc-9w29`, and `GHSA-cqh3-jg8p-336j` Yamcs auth rate-limit, user-enumeration, and LDAP injection: track as supporting context if a Yamcs assessment is in scope, but they are weaker standalone offensive operator material than the Janino execution boundary.
- `GHSA-fwcm-rqvw-j3p7` FUXA tag-value disclosure: useful as chain support for exposed FUXA instances, but the durable wiki guidance is covered by the FUXA execution and auth-bypass patterns above.
- Kirby draft-access and frontend list-field XSS advisories: valid findings, but lower incremental operator value than the path traversal and method-call boundaries.
- CISA KEV remained catalog `2026.05.26` with `CVE-2026-48172` already reflected in the prior LiteSpeed cPanel guidance. PortSwigger Research, Trail of Bits, ProjectDiscovery, GitHub Security Blog, and Disclosed did not add a new promotable delta.

## Sources

- [LiquidJS `strip_html` newline XSS bypass (`GHSA-2qv6-9wx5-cwv4`)](https://github.com/advisories/GHSA-2qv6-9wx5-cwv4)
- [CarrierWave content type denylist regex bypass (`GHSA-7g26-2qgj-chfg`)](https://github.com/advisories/GHSA-7g26-2qgj-chfg)
- [Kata Containers virtiofsd annotation VM escape (`GHSA-rr59-xxvx-96qr`)](https://github.com/advisories/GHSA-rr59-xxvx-96qr)
- [Kirby user lookup path traversal / PHP inclusion (`GHSA-9hx7-c53c-v6x8`)](https://github.com/advisories/GHSA-9hx7-c53c-v6x8)
- [Kirby arbitrary method call via REST collection queries (`GHSA-86rh-h242-j8xp`)](https://github.com/advisories/GHSA-86rh-h242-j8xp)
- [FUXA script test-mode RCE (`GHSA-rg3m-cfq7-g6h6`)](https://github.com/advisories/GHSA-rg3m-cfq7-g6h6)
- [FUXA Node-RED path-confusion auth bypass (`GHSA-p69w-mmfv-xrfj`)](https://github.com/advisories/GHSA-p69w-mmfv-xrfj)
- [Yamcs Janino algorithm code injection (`GHSA-524g-x36v-9wm6`)](https://github.com/advisories/GHSA-524g-x36v-9wm6)
- [Fedify Linked Data Signature bypass (`GHSA-9rfg-v8g9-9367`)](https://github.com/advisories/GHSA-9rfg-v8g9-9367)
