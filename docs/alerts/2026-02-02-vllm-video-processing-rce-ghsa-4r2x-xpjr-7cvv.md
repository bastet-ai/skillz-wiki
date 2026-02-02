# 2026-02-02 — vLLM RCE via video processing chain (GHSA-4r2x-xpjr-7cvv)

## Summary

GitHub published an advisory describing a **remote code execution (RCE)** chain in **vLLM** when serving **video-capable models**.

- Advisory: https://github.com/advisories/GHSA-4r2x-xpjr-7cvv
- Affected: vLLM **>= 0.8.3, < 0.14.1** (per advisory)
- Trigger: sending a request that includes a **remote `video_url`** to endpoints like `/v1/chat/completions` or `/v1/invocations` (per advisory)
- Root cause (high level): vLLM downloads attacker-controlled media and passes it into video decoding stacks (OpenCV/FFmpeg/libopenjp2), plus an information leak that helps bypass ASLR (per advisory).

Deployments **not serving a video model** are not affected (per advisory).

## What to do (durable guidance)

### Immediate actions (operators)

1. **If you run vLLM with video models:**
   - **Upgrade vLLM to >= 0.14.1** (or apply upstream patches referenced in the advisory).
2. **Reduce exposure while patching:**
   - **Disable/deny `video_url`** inputs if you can (schema validation / request filtering).
   - **Disable the `/v1/invocations` route** if you don’t need it (especially if it’s reachable pre-auth in your deployment).
3. **Treat media ingestion as hostile:**
   - Block egress to the public internet from the vLLM worker where possible (allowlist artifact buckets only).
   - If you must fetch remote URLs, proxy through a fetch service that enforces:
     - scheme allowlist (https only)
     - DNS/IP allowlisting (no RFC1918, link-local, metadata IPs)
     - size/time limits
     - content-type sniffing
4. **Add OS-level containment:**
   - Run vLLM as **non-root**, in a container with **seccomp/AppArmor**, and without host mounts.
   - Consider gVisor/Kata/Firecracker for workloads that must decode untrusted media.

### Detection / response notes

- Monitor for unusual outbound connections or subprocess behavior from the vLLM process.
- If you suspect exploitation, preserve logs and container images, then rotate any secrets available to that runtime.

## Related Wisdom

- [Agent + CI hardening](../best-practices/agent-ci-hardening.md)
- [Agent tools: command injection (shell=True)](../best-practices/agent-tool-command-injection.md)
