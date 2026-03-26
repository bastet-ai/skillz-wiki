# Skills

Skill pages are the reusable operator core of this repo. Each one is written so it can work both as human documentation and as a compact installable skill for an agent.

## Skill contract

Every skill should answer the same questions:

- What problem does this tool solve?
- When should the agent use it?
- What inputs, binaries, credentials, or wordlists are required?
- Which command patterns are safe and worth repeating?
- What output matters, and how should it be captured?
- What scope, authorization, and safety limits apply?

## Current skills

- [HTTP Probing with httpx](httpx.md)
- [DNS Enumeration](dns-enumeration.md)
- [Nmap Scanning](nmap-scanning.md)

## Packaging guidance

When exporting a page into an agent skill, preserve:

- summary and trigger conditions
- prerequisites and environment assumptions
- canonical command snippets
- parsing hints for useful output
- failure modes, validation boundaries, and safety notes
