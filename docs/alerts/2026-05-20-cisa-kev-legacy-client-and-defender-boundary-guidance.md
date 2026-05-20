# CISA KEV legacy client and Defender boundary guidance

**Signal:** CISA KEV catalog version **2026.05.20** added seven exploited vulnerabilities spanning legacy Microsoft/Adobe client-side RCE surfaces and Microsoft Defender endpoint boundary issues: **CVE-2008-4250**, **CVE-2009-1537**, **CVE-2009-3459**, **CVE-2010-0249**, **CVE-2010-0806**, **CVE-2026-41091**, and **CVE-2026-45498**.

## Advisories covered

- **CVE-2008-4250 — Microsoft Windows Server Service buffer overflow:** crafted RPC requests can trigger remote code execution through path canonicalization. CISA lists a **2026-06-03** due date.
- **CVE-2009-1537 — Microsoft DirectX DirectShow QuickTime parser NULL-byte overwrite:** crafted QuickTime media can lead to code execution through the `quartz.dll` parser. CISA lists a **2026-06-03** due date.
- **CVE-2009-3459 — Adobe Acrobat and Reader heap-based buffer overflow:** crafted PDFs can trigger memory corruption and code execution. CISA lists a **2026-06-03** due date.
- **CVE-2010-0249 — Microsoft Internet Explorer use-after-free:** browser exploitation through deleted-object pointer reuse; impacted products may be end-of-life or end-of-service. CISA lists a **2026-06-03** due date.
- **CVE-2010-0806 — Microsoft Internet Explorer use-after-free:** browser exploitation through invalid pointer access after object deletion; impacted products may be end-of-life or end-of-service. CISA lists a **2026-06-03** due date.
- **CVE-2026-41091 — Microsoft Defender link-following vulnerability:** local privilege escalation through Defender path/link handling. CISA lists a **2026-06-03** due date.
- **CVE-2026-45498 — Microsoft Defender denial of service:** unspecified Defender DoS condition. CISA lists a **2026-06-03** due date.

## Why this is durable

This KEV batch is a reminder that exploited risk often persists in two places defenders overlook: **legacy client execution paths** and **security tooling itself**. Old browser, media, PDF, and RPC bugs still matter when unsupported systems, compatibility islands, kiosk devices, lab networks, or embedded Windows images remain reachable. Defender issues matter because endpoint protection runs with deep local privileges and broad file-system visibility; link-following and availability bugs can weaken the same control intended to contain compromise.

## Immediate triage

1. Inventory Windows systems that still expose SMB/RPC broadly, run Internet Explorer components, process legacy QuickTime/DirectShow content, or rely on old Adobe Reader/Acrobat versions.
2. Remove or isolate end-of-life Windows/browser/document-reader stacks. If business constraints prevent removal, place them in tightly segmented networks with no internet browsing or email/document-opening path.
3. Confirm Microsoft Defender platform/engine/security-intelligence update health across endpoints and servers; prioritize machines used by administrators, build systems, security tooling, and high-value users.
4. For Defender link-following risk, audit locations where low-privileged users can create symlinks, junctions, shortcuts, mount points, or archives that Defender scans under higher-privileged contexts.
5. Treat KEV status as evidence of exploitation: patching is required, but also hunt for suspicious documents, browser crashes, RPC exploit attempts, unexpected service crashes, Defender disablement, and local privilege-escalation traces.

## Hunt prompts

- Internet Explorer, DirectShow, Reader/Acrobat, or Office spawning unusual child processes, network connections, dropped executables, or script interpreters.
- SMB/RPC exploit attempts against legacy Windows hosts, especially path-canonicalization anomalies, crashes of Server service components, or lateral movement shortly afterward.
- PDF, QuickTime, or web artifacts delivered by email, browser downloads, shared drives, ticket attachments, or removable media near the suspected window.
- Defender service crashes, unexpected exclusions, disabled real-time protection, failed engine updates, tampered security-center state, or sudden gaps in EDR telemetry.
- Local users creating symlinks/junctions/hardlinks around sensitive directories before Defender scans, quarantine actions, or cleanup operations.

## Durable controls

- Eliminate unsupported client runtimes instead of relying on compensating controls indefinitely; legacy document/browser handling should happen in disposable sandboxes or isolated VDI.
- Segment legacy Windows systems away from normal user, server, and admin networks; block inbound SMB/RPC unless explicitly required.
- Keep endpoint protection engines, platforms, and signatures under compliance monitoring just like OS patches.
- Harden local file-system boundaries: restrict low-privileged link creation where possible, monitor reparse points in writable directories, and avoid running cleanup/scanning workflows that cross attacker-controlled links into privileged paths.
- For KEV additions, pair remediation with evidence preservation, credential review, and post-exploitation hunting rather than treating the catalog as a patch-only queue.

## References

- CISA Known Exploited Vulnerabilities catalog: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
- CISA KEV JSON feed: <https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json>
