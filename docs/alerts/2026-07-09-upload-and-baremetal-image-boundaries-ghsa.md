---
title: Upload validation and bare-metal image boundary checks from July 9 GHSA updates
---

# Upload validation and bare-metal image boundary checks from July 9 GHSA updates

This update promotes three GHSA records into reusable operator checks for authorized assessments. The common pattern is a caller-controlled artifact that crosses a boundary after the platform has already decided it is safe: an upload `Content-Type` compared through an unsafe denylist regex, a tenant-controlled bare-metal console path reaching host-side tooling, or a deployment image influencing commands executed during image preparation.

Sources:

- [GHSA-7g26-2qgj-chfg: CarrierWave `content_type_denylist` bypass via unescaped regex metacharacters](https://github.com/advisories/GHSA-7g26-2qgj-chfg)
- [GHSA-wqpv-c3pp-3m58: OpenStack Ironic functionality from an untrusted control sphere](https://github.com/advisories/GHSA-wqpv-c3pp-3m58)
- [GHSA-rmxr-45gj-889w: OpenStack Ironic Python Agent chroot `grub-install` execution from deployed image content](https://github.com/advisories/GHSA-rmxr-45gj-889w)

!!! warning "Authorized validation only"
    Keep proofs in disposable upload apps, lab OpenStack/Ironic environments, and scratch bare-metal nodes or VMs. Use benign marker files, fake content types, inert wrapper commands, and lab images. Do not upload web shells, alter production bare-metal provisioning flows, run payloads on conductor hosts, or target customer images.

## Operator use

Use these checks when a scope includes:

- Ruby/Rails apps using CarrierWave or equivalent upload libraries with MIME denylist controls;
- upload paths that allow SVG, XML, HTML, archive, office, or polyglot-looking content but claim a denylist blocks dangerous MIME types;
- OpenStack Ironic or bare-metal-as-a-service platforms where tenants can influence image contents, console settings, deployment metadata, or bootloader setup;
- provisioning agents that mount or chroot into tenant-provided images and then run host tooling from inside that environment.

## Recon checklist

| Boundary | What to look for | Safe canary |
| --- | --- | --- |
| MIME denylist regexes | String denylist entries interpolated into regexes without escaping metacharacters such as `+`, `.`, `(`, `)`, `[`, `]`, or anchors | Benign file with a controlled `Content-Type`, such as `image/svg+xml`, and non-executing marker content |
| Upload storage binding | MIME decision separated from extension, final storage path, public serving origin, or downstream processors | Matrix of claimed MIME, detected MIME, extension, storage path, and render/download behavior |
| Bare-metal console helpers | Non-default console interfaces or driver options that cause host-side tools such as `ipmitool` to run using tenant-influenced fields | Lab node with wrapper/logging binary or fake BMC endpoint; no production BMC commands |
| Image preparation chroots | Deployment agents that chroot into an image and run bootloader, package, hook, or helper commands resolved from the image filesystem | Disposable image containing inert marker wrappers and pre/post deployment logs |

## Validation patterns

### CarrierWave MIME denylist bypass

The operator question is whether the application treats a denylist as a reliable block for a dangerous class of uploads while the regex form misses the real MIME value.

1. Identify uploaders using `content_type_denylist` or local wrappers around it. Record the exact configured entries.
2. Build a decision table for MIME values containing regex metacharacters, especially `image/svg+xml`. Compare:
   - the literal denylist value;
   - the real request `Content-Type` header;
   - any server-side detected MIME value;
   - whether the upload is accepted.
3. Use a harmless marker file. If SVG is in scope, use inert SVG/XML with a text marker only; do not include script, external references, or browser-executing payloads.
4. Capture final storage and serving behavior. A strong report shows that the same policy blocks a control MIME but accepts the metacharacter-bearing MIME it intended to deny.

Useful evidence is a compact table: configured denylist entry, regex-equivalent behavior if visible, submitted MIME, expected decision, actual decision, stored filename/path, and fixed-version result.

### OpenStack Ironic console/tool execution boundary

This check is for approved OpenStack/Ironic labs or customer-approved private-cloud tests. It is not a broad internet scan.

1. Confirm the deployment uses OpenStack Ironic and whether non-default console interfaces are enabled for the tested node type.
2. Map tenant-controlled inputs that influence console or BMC helper invocations: node driver info, console settings, management addresses, usernames, and deployment metadata.
3. In a lab, route helper calls to a fake BMC endpoint or replace the helper with a wrapper that logs argv and environment, then exits safely.
4. Evidence should show the boundary crossing: tenant-controlled field -> Ironic/conductor helper invocation -> inert logged argument or callback.

Do not issue real power, boot, SOL, or management commands against production BMCs. The finding is about control-plane trust, not destructive device control.

### Ironic Python Agent chroot image execution

The risky pattern is host/provisioning code entering an image supplied or influenced by the tenant, then executing a helper resolved from that image's filesystem.

1. Build a disposable image in a lab project. Add only an inert marker wrapper for the expected helper path, such as a `grub-install` wrapper that writes a timestamped marker to a lab log and exits with a controlled status.
2. Provision a disposable node/VM through the same Ironic Python Agent path used by the target environment.
3. Capture whether the agent executes the wrapper from inside the image chroot during bootloader setup.
4. Pair the positive proof with a fixed-version or hardened-path negative control where the host uses trusted tooling or refuses the image-controlled helper.

Do not place shell payloads, credential readers, network callbacks to internal services, or persistence hooks in images. Keep the proof to a single inert marker showing image content influenced provisioning-time execution.

## Reporting notes

Lead with the artifact-to-runtime boundary:

- **configured MIME denylist -> regex parser -> accepted upload**;
- **tenant console metadata -> conductor-side helper invocation**;
- **tenant image filesystem -> provisioning agent command resolution**.

Include version, configuration preconditions, role/tenant privileges, exact input class, synthetic canary evidence, and a negative control. Avoid claiming generic RCE unless your approved lab proof shows command execution in the specific service context and you can name that context precisely.
