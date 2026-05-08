# XML, SCP, and transfer-boundary batch

**Signal:** The **2026-05-08 22:15 UTC** advisory scan added durable guidance for builder-delimiter injection and file-transfer path confinement.

## Advisory cluster

- **fast-xml-parser XMLBuilder delimiter injection** — [GHSA-gh4j-gqv2-49f6](https://github.com/advisories/GHSA-gh4j-gqv2-49f6): `fast-xml-parser <5.7.0` did not escape `-->` in XML comments or `]]>` in CDATA sections, enabling XML injection, SOAP manipulation, or browser XSS when user data flowed into those nodes.
- **Wish SCP path traversal** — [GHSA-xjvp-7243-rg9h](https://github.com/advisories/GHSA-xjvp-7243-rg9h): `charm.land/wish/v2 <2.0.1` and `github.com/charmbracelet/wish <=1.4.7` let malicious SCP clients use `../` path components to read, write, or create files outside the configured server root.

## Why this matters

Serialization APIs and transfer protocols both look like data plumbing, but they carry grammar. XML comment/CDATA delimiters and SCP filenames must be treated as structural control tokens, not harmless strings.

## Triage

1. Patch `fast-xml-parser` to **5.7.0+** and `charm.land/wish/v2` to **2.0.1+**; retire or tightly wrap affected Wish v1 paths.
2. Search code for user-controlled data written into XML comments or CDATA blocks.
3. Audit SSH/SCP services built with Wish for write-capable roots, exposed home directories, deploy-key material, and automation credentials.
4. Hunt for XML outputs containing embedded `-->`, `]]>`, unexpected nested elements after comments/CDATA, and SCP logs with `../`, absolute paths, URL-encoded traversal, or symlink pivots.

## Durable controls

- Prefer text nodes over comments/CDATA for untrusted content; if comments/CDATA are required, reject delimiter sequences before serialization.
- Normalize transfer paths after percent/Unicode decoding and reject any path that escapes the configured root after symlink resolution.
- Run file-transfer services under dedicated OS users with a narrow chroot/container and no ambient secrets.
- Test protocol handlers with malicious clients, not only friendly CLI happy paths.
