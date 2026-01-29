# Agent + CI Hardening (Prompt Injection → Secrets Exfil)

Modern “agentic” developer tools can read issues, run workflows, and interact with CI. That creates a new class of attacks:

> **Untrusted input** (issue/PR text) → **agent action** → **CI execution** → **secret exfiltration**

This page is a defensive checklist that also doubles as a test plan.

## Threat model

Attackers will try to:
- inject instructions into agent inputs
- get CI to run attacker-controlled code
- extract secrets (tokens, creds, signing keys)

## CI controls (baseline)

- [ ] Secrets are not exposed to untrusted contexts (fork PRs, external issues).
- [ ] Workflows that can access secrets require maintainer approval.
- [ ] Avoid `pull_request_target` pitfalls unless you fully understand the risk.
- [ ] Pin actions by commit SHA (supply chain hardening).
- [ ] Restrict `GITHUB_TOKEN` permissions (least privilege).

## Agent controls

- [ ] Treat issue/PR text as hostile input.
- [ ] Never allow an agent to:
  - modify workflows
  - run arbitrary commands
  - access secrets
  unless a human approves.
- [ ] Separate “analysis” from “execution” modes.

## TOCTOU gotchas

One common failure mode is time-of-check/time-of-use:
- something is “reviewed” at assignment time
- but the agent later runs on updated/hidden content

**Mitigation:** lock inputs, log the exact content used, require explicit approvals.

## What to test (offensive validation)

- Can an issue author influence a privileged workflow?
- Can you cause secrets to appear in logs/artifacts?
- Can you trigger execution through labels/assignments?

## Source / inspiration

- Inspired by public research describing prompt injection combined with CI workflow gaps to exfiltrate secrets.
