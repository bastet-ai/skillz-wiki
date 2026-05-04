# Pillow, russh, and parser resource-boundary batch (GHSA)

**Signal:** GitHub Security Advisories REST surfaced a **2026-05-04** resource-safety batch where image/font/PDF parsers and SSH authentication handlers trusted attacker-controlled sizes, nested structures, or interaction counts.

## Advisories in this batch

- **Pillow invalid PSD tile extents OOB write** — `pillow >= 10.3.0, < 12.2.0` has an out-of-bounds write via invalid PSD tile extents and integer overflow. References: <https://github.com/advisories/GHSA-pwv6-vv43-88gr>, CVE-2026-42311.
- **Pillow PDF trailer infinite loop** — `pillow >= 4.2.0, < 12.2.0` can hang while parsing crafted PDF trailers. References: <https://github.com/advisories/GHSA-r73j-pqj5-w3x7>, CVE-2026-42310.
- **Pillow font integer overflow** — `pillow < 12.2.0` has an integer overflow while processing fonts. References: <https://github.com/advisories/GHSA-wjx4-4jcj-g98j>, CVE-2026-42308.
- **Pillow nested-list coordinate heap overflow** — `pillow >= 11.2.1, < 12.2.0` has a heap buffer overflow with nested list coordinates. References: <https://github.com/advisories/GHSA-5xmw-vc9v-4wf2>, CVE-2026-42309.
- **russh pre-auth unbounded allocation** — `russh < 0.60.1` can allocate unbounded memory during keyboard-interactive authentication before full auth is complete. References: <https://github.com/advisories/GHSA-f5v4-2wr6-hqmg>, CVE-2026-42189.

## Why this is durable

The shared lesson is that pre-auth and pre-trust parsers are exposed to the cheapest attacker input. Image conversion, PDF thumbnailing, font handling, and SSH authentication should all assume hostile lengths, recursion, iteration counts, and nested structures.

## Immediate triage

1. **Upgrade Pillow to 12.2.0+** wherever user-uploaded images, PDFs, or fonts are parsed.
2. **Upgrade russh to 0.60.1+** or place strict connection and memory controls in front of affected services.
3. **Sandbox conversion workers:** run image/PDF/font processing in low-privilege, no-secret, memory-limited containers or subprocesses.
4. **Enforce input policy:** reject unexpected PSD/PDF/font formats if the application only needs common raster images.
5. **Rate-limit pre-auth SSH:** cap concurrent keyboard-interactive attempts and terminate oversized or slow auth conversations.

## Hunt ideas

- Search upload and conversion logs for PSD, PDF, font, or malformed nested-coordinate payloads around worker crashes, hangs, or OOM events.
- Check process supervisors for repeated Pillow worker restarts, high CPU loops, memory spikes, or stuck PDF parsing jobs.
- Review SSH logs for many keyboard-interactive prompts, long pre-auth sessions, or bursts from the same source before memory pressure.
- Preserve suspicious files for offline reproduction in an isolated harness before deleting them.

## Durable controls

- Put size, recursion, object-count, and runtime budgets around every parser that touches user files.
- Prefer allowlisted file types over parser auto-detection in upload pipelines.
- Decode untrusted media in disposable workers with seccomp/AppArmor, read-only filesystems, and no cloud credentials.
- Treat pre-auth protocol handlers as internet-facing parsers; enforce quotas before allocating attacker-sized buffers.
- Add regression corpus entries for integer-overflow, nested-structure, and infinite-loop parser bugs.

## Operator lesson

Parser bugs are incident-response accelerants. If a service accepts files or pre-auth protocol frames, assume the first useful exploit goal is denial of service or worker escape, and design the blast radius before the bug arrives.
