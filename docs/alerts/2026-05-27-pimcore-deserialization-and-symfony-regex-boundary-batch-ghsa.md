# Pimcore deserialization and Symfony regex boundary batch (GHSA, 2026-05-27)

**Signal:** GitHub Advisory Database published three boundary-crossing advisories with reusable offensive-testing value: Pimcore PHP object injection through raw `unserialize()` sinks, Symfony route-requirement regex anchoring drift that can produce off-site protocol-relative URLs, and Symfony X.509 DN parsing that can authenticate a client certificate as the wrong user.

Promoted items:

- `GHSA-36fc-7wjg-mfvj` / `CVE-2026-45162`: Pimcore calls PHP `unserialize()` directly on several database and filesystem-backed values without `allowed_classes`, creating PHP object-injection sinks when paired with a write primitive.
- `GHSA-72xp-p242-47p9` / `CVE-2026-45065`: Symfony `UrlGenerator` route requirements using ungrouped alternation can validate attacker-controlled values as substring matches and generate `//host` off-site URLs.
- `GHSA-ph86-p8f6-f9r2` / `CVE-2026-45063`: Symfony `X509Authenticator` can match `emailAddress=` inside another DN attribute value, enabling identity spoofing when a trusted client-certificate CA allows free-text subject fields.

Use these only in authorized tests. Prefer local/lab clones, harmless callback hosts, and test certificates issued by an agreed CA. Do not plant production gadget chains or attempt to impersonate real users outside scope.

## Operator checklist

### 1. Pimcore raw `unserialize()` sinks as chain targets

Where to look:

- Pimcore `<= 12.3.6` deployments and applications with `pimcore/pimcore` or `pimcore/admin-ui-classic-bundle` in `composer.lock`.
- Existing or suspected write primitives into Pimcore database-backed values such as `tmp_store`, `sites`, or `custom_layouts`.
- File-write primitives that can target Pimcore-managed filesystem values such as WebDAV delete logs or dashboard configuration files.
- Prior Pimcore SQLi or file-write findings where impact was previously limited to data access or arbitrary write.

Safe proof shape:

1. Confirm the affected Pimcore version and identify the specific deserialization sink reachable in the target flow.
2. Prove control of the serialized data source with a harmless marker value first; keep SQLi/file-write proof separate from deserialization proof where possible.
3. In a local clone or explicitly approved lab, use a benign `phpggc` chain that executes a non-destructive marker command such as writing to a disposable temp path.
4. Trigger the matching read path, for example TmpStore access, site-domain load, custom-layout load, WebDAV operation, or dashboard config read.
5. Stop at proving object instantiation / marker execution in the lab. Do not deploy gadget chains against production systems unless the assessment rules explicitly authorize exploit validation.

Reporting heuristic: frame as **write primitive upgraded by reachable PHP object-injection sink**. Strong reports show the data source, write path, deserialization trigger, available dependency gadget family, affected version, and the exact permission boundary required for the write primitive.

### 2. Symfony route requirements with unanchored alternation

Where to look:

- Symfony apps using vulnerable `symfony/routing` or `symfony/symfony` versions: `< 5.4.52`, `>= 6.0.0 < 6.4.40`, `>= 7.0.0 < 7.4.12`, or `>= 8.0.0 < 8.0.12`.
- Routes that place user-controlled parameters into generated links with Twig `path()` / `url()` or equivalent `UrlGenerator` calls.
- Requirement regexes written as raw alternation, especially locale patterns like `en|fr|de|vi|zh_CN` rather than grouped alternation.
- Redirect, login, invite, email-template, password-reset, locale-switcher, and post-action flows that trust generated URLs.

Safe proof shape:

1. Confirm the vulnerable Symfony routing version from `composer.lock` or a build artifact.
2. Find a route parameter with a raw alternation requirement where at least one middle alternative appears inside an attacker-controlled string.
3. Supply a value that contains the middle alternative while beginning with `//attacker-controlled.example`, for example a protocol-relative host containing `vi` for a locale regex with `vi` as a middle alternative.
4. Observe whether the generated link or redirect target becomes an off-site `//host/...` URL.
5. Use a tester-owned inert host and avoid collecting credentials or tokens.

Reporting heuristic: report **regex requirement validation disagrees with URL-construction trust boundary**. Include the route definition, requirement regex, generated URL, affected helper call, and the downstream impact such as open redirect, OAuth redirect confusion, magic-link leakage, or phishing-quality link generation.

### 3. Symfony X.509 DN parsing identity spoofing

Where to look:

- Symfony applications using `X509Authenticator` with vulnerable `symfony/security-http` or `symfony/symfony` versions: `< 5.4.52`, `>= 6.0.0-BETA1 < 6.4.40`, `>= 7.0.0-BETA1 < 7.4.12`, or `>= 8.0.0-BETA1 < 8.0.12`.
- mTLS deployments where the web server validates client certificates and forwards `SSL_CLIENT_S_DN` to PHP.
- Environments where a trusted client-certificate CA permits user-controlled CN or other free-text subject values.
- Auth mappings that extract `emailAddress` from the subject DN and map it directly to application users.

Safe proof shape:

1. Confirm the application really uses Symfony `X509Authenticator` and maps identity from `SSL_CLIENT_S_DN` / subject DN.
2. In a lab or approved test CA, issue a certificate with a benign controlled CN containing `emailAddress=test-user@example.invalid` while the real email RDN remains different or absent.
3. Present the certificate through the same mTLS ingress path and record which user Symfony resolves.
4. Test only with dedicated lab users or throwaway accounts. Do not attempt to impersonate a production user unless explicitly authorized.
5. Capture whether the ingress normalizes DN format with comma or slash separators, because the parser boundary can differ by web server and TLS proxy.

Reporting heuristic: frame as **certificate trust is correct but DN string parsing shifts identity**. Strong evidence includes the certificate subject, forwarded server variable, Symfony version, user-provider lookup result, and CA subject-field policy that makes the spoof path realistic.

## Non-signal this hour

Reviewed but not promoted as new standalone guidance:

- PortSwigger Research stayed on the Top 10 web hacking techniques of 2025.
- Trail of Bits stayed on the already-covered zizmor GitHub Actions static-analysis hardening article.
- ProjectDiscovery RSS stayed on already-covered Neo / Nuclei / DAST proof-loop material.
- GitHub Security Blog remained GHES signing-key rotation / incident-response oriented.
- Disclosed sitemap remained lander-only.
- CISA KEV remained catalog `2026.05.26` with `CVE-2026-48172` already reflected.

## Sources

- [Pimcore unsafe PHP deserialization in multiple locations (`GHSA-36fc-7wjg-mfvj`)](https://github.com/advisories/GHSA-36fc-7wjg-mfvj)
- [Symfony route-requirement regex bypass to off-site URL injection (`GHSA-72xp-p242-47p9`)](https://github.com/advisories/GHSA-72xp-p242-47p9)
- [Symfony X.509 DN regex identity spoofing (`GHSA-ph86-p8f6-f9r2`)](https://github.com/advisories/GHSA-ph86-p8f6-f9r2)
