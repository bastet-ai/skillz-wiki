# Inspektor Gadget buildOptions command injection (GHSA-79qw-g77v-2vfh / CVE-2026-24905)

**Signal:** GitHub Security Advisories updated **2026-04-30**. Inspektor Gadget fixed command injection in custom gadget image building through malicious `buildOptions` values.

## What it is
The `ig` binary can build custom gadget OCI images. Before the fix, build options such as output directory, CFLAGS, source paths, and related Makefile arguments were concatenated into a `make` invocation. Malicious option values could influence Makefile command execution and run attacker-controlled commands during image build.

This matters most where gadget builds are exposed through automation: CI jobs, developer portals, Kubernetes observability platforms, or any service that accepts user-controlled gadget source/build metadata.

Affected Go module: `github.com/inspektor-gadget/inspektor-gadget` `< 0.51.1`.

Reference: <https://github.com/advisories/GHSA-79qw-g77v-2vfh>

## Triage
1. Find hosts and pipelines running `ig image build` or custom gadget image generation.
2. Check whether any build options are derived from pull requests, uploaded archives, API requests, Kubernetes objects, or tenant-controlled metadata.
3. Review build logs for shell metacharacters, unexpected Makefile variables, extra targets, outbound network calls, or filesystem writes outside the build workspace.
4. Rotate credentials if untrusted gadget builds ran on workers with registry, cluster, or cloud secrets.

## Mitigation
- Upgrade Inspektor Gadget to `0.51.1` or later.
- Treat gadget image builds as untrusted code execution: isolate workers, use ephemeral credentials, and restrict network egress.
- Validate build options against strict allowlists and pass arguments without shell or Makefile variable interpretation where possible.
- Keep build output directories outside sensitive workspaces and clear them between builds.

## Detection ideas
- Alert on gadget builds containing `;`, `&&`, `|`, backticks, `$(`, newlines, or unexpected Makefile variable assignments in options.
- Monitor build workers for unexpected child processes, outbound connections, registry pushes, or secret-file reads during gadget builds.
- Compare produced gadget images against expected source digests and build manifests.

## Durable lesson
Observability plugin builders are code-execution surfaces. If users can influence build flags, source paths, or Make variables, run the builder like an untrusted CI job with isolation and disposable credentials.
