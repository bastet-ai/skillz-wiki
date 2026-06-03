---
title: Agent skill supply-chain testing
---

# Agent skill supply-chain testing

Use this workflow during authorized assessments of AI-agent platforms, internal skill registries, curated skill bundles, and marketplace scanner pipelines. It turns the Trail of Bits June 2026 skill-distribution research into a reusable validation path without publishing ready-to-run malicious payloads.

## Operator value

Agent skills are a hybrid supply-chain artifact: natural-language instructions, helper scripts, packaged data, and sometimes compiled or archived content. Scanner pass/fail output is not enough proof that a skill is safe or that a marketplace has meaningful review coverage.

Durable test targets:

- Marketplace or registry upload review.
- Skill ZIP import APIs.
- Git-repository based skill ingestion.
- Agent harnesses that execute helper scripts referenced from `SKILL.md`.
- Scanner integrations that combine static patterns, LLM review, package policy, or third-party verdicts.

## Inputs

Collect these before testing:

- Written authorization for skill upload/import tests.
- A disposable test organization, workspace, and agent identity.
- The skill packaging rules: allowed file extensions, size limits, symlink handling, archive nesting, and executable-bit handling.
- The scanner decision model: block/warn/allow, where verdicts appear, and whether maintainers can override them.
- Network and filesystem egress controls for the agent runtime.

!!! warning "Containment"
    Use inert canary strings and local-only callbacks in lab infrastructure. Do not include credential theft, destructive commands, persistence, or external exfiltration in marketplace submissions.

## Test matrix

| Boundary | What to vary | Evidence to capture |
| --- | --- | --- |
| Prompt review | Long padding before risky instructions; instructions hidden in non-obvious sections; conflicting benign summaries | Scanner transcript, truncation indicators, final verdict |
| File-type policy | Plain text, Markdown, JSON/YAML config, office documents, bytecode, archives, nested archives | Accepted/rejected file list and unpacked artifact tree |
| Helper execution | `SKILL.md` references to scripts, shell snippets, package managers, interpreters, or generated commands | Agent plan, command preview, execution log |
| Indirection | Instructions stored outside `SKILL.md`, referenced by filename, config key, or generated task | Whether scanner follows the reference chain |
| Binary/compiled content | Precompiled bytecode, minified bundles, wasm, native extensions, or generated lockfiles | Whether scanner decompiles, hashes, or ignores content |
| UI review | Very large files, long scroll regions, collapsed sections, misleading filenames | Reviewer-visible screenshot and raw source diff |
| Verdict consistency | Re-submit equivalent artifacts with renamed files, reordered content, or harmless formatting changes | Per-submission verdict deltas |

## Workflow

1. **Mirror the ingestion path.** Test the exact route real users use: direct ZIP upload, Git repository import, marketplace submission, or internal registry publish.
2. **Start with a benign control skill.** Confirm that a minimal skill imports, scans, and runs as expected. Save the raw artifact, scanner output, and agent execution trace.
3. **Map package-policy enforcement.** Submit harmless artifacts that vary extension, size, nesting, and executable bits. The goal is to learn what reaches the scanner and what reaches the agent runtime.
4. **Probe scanner visibility.** Place a unique inert canary in each location (`SKILL.md`, helper script, config file, document XML, compiled artifact metadata) and verify which canaries appear in scanner findings or reviewer UI.
5. **Probe indirection handling.** Reference secondary files from `SKILL.md` and record whether scanners follow the chain or only review top-level Markdown.
6. **Probe truncation and parser gaps.** Use large but harmless padding, deeply nested structures, or verbose generated files to determine whether scanner summaries omit tail content.
7. **Exercise runtime boundaries in a sandbox.** If execution is permitted, make helper scripts print a local canary and current working directory only. Capture whether the agent asks for approval, previews commands, or runs automatically.
8. **Report scanner bypasses as review-coverage failures.** The finding is stronger when it shows a scanner verdict mismatch: the raw artifact contains a clearly labeled inert policy violation, but the platform marks it safe or hides the relevant content from reviewers.

## Safe canary patterns

Prefer canaries that prove reachability without collecting secrets:

```text
SKILLZ_CANARY_DO_NOT_EXECUTE_<case-id>
SKILLZ_POLICY_VIOLATION_MARKER_<case-id>
SKILLZ_LOCAL_RUNTIME_MARKER_<case-id>
```

For runtime tests, use local-only commands such as printing the marker, interpreter version, and working directory. Avoid environment dumps, token paths, outbound HTTP, shell reverse connections, or destructive filesystem writes.

## Reporting checklist

Include:

- Artifact hash and submission timestamp.
- Upload/import path and scanner name/version if visible.
- Allowed file tree after platform unpacking or normalization.
- Exact verdict text and screenshots of reviewer UI.
- Canary placement map and whether each canary appeared in scanner output.
- Runtime evidence limited to benign local markers.
- Clear impact statement: users can install or run a skill containing scanner-invisible instructions or code-like content.

## Sources

- Trail of Bits, "The sorry state of skill distribution" (June 3, 2026): https://blog.trailofbits.com/2026/06/03/the-sorry-state-of-skill-distribution/
- Trail of Bits Blog RSS: https://blog.trailofbits.com/feed/
