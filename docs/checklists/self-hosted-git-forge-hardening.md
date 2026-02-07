# Self-Hosted Git Forge Hardening (Gogs/Gitea/Forgejo)

Self-hosted Git forges (Gogs/Gitea/Forgejo, etc.) are *high-leverage* targets: if an attacker gets repo admin/maintainer on a single project (or a single forge admin account), they can often pivot to **code execution on the forge host**, steal **signing/CI secrets**, and poison **supply chain outputs**.

This checklist is written to stay useful even as specific CVEs come and go.

## 1) First principles / threat model

Assume a forge compromise can lead to:

- **Source + secret exfiltration** (private repos, deploy keys, webhook secrets)
- **Credential theft** (session cookies, OAuth tokens)
- **Build/CI compromise** (actions runners, webhooks, release pipelines)
- **Host compromise** (RCE via admin functionality, hook editing, unsafe file handling)

Treat the forge as a **Tier-0** service.

## 2) Patch + exposure posture

- [ ] Run **supported, current versions**. Subscribe to upstream security advisories.
- [ ] Prefer **immutable deploys** (container image pinned by digest; regular rebuilds).
- [ ] Put the forge behind:
  - [ ] **SSO** (if possible) and/or a hardened reverse proxy
  - [ ] **Rate limiting** for auth endpoints
  - [ ] **WAF** only as a *bonus* (don’t rely on it)
- [ ] Reduce exposure:
  - [ ] If you don’t need public access, keep it **VPN-only** / **private network**.
  - [ ] If public, enforce **MFA** and strict account policies.

## 3) Dangerous features: disable, restrict, or isolate

Some forge features are effectively “admin RCE surface.”

- [ ] **Git hook editing / custom hooks**
  - [ ] Disable globally if you can.
  - [ ] If enabled, restrict to a tiny allowlist of trusted admins.
  - [ ] Assume this area will periodically produce path traversal / file write / RCE class bugs.
- [ ] **Repository admin permissions**
  - [ ] Review who has repo admin.
  - [ ] Use *least privilege* roles for maintainers.
- [ ] **Webhooks**
  - [ ] Validate destinations (avoid SSRF to internal networks).
  - [ ] Use per-webhook secrets; rotate on incident.

## 4) Credential + session hardening

- [ ] Enforce **MFA** for all accounts; require it for admins.
- [ ] Disable/limit **recovery codes** where possible; otherwise treat them like passwords.
- [ ] Set conservative **session lifetimes** and rotate secrets on upgrades/incidents.
- [ ] Ensure cookies are **Secure**, **HttpOnly**, and **SameSite** appropriately.

## 5) Host isolation (blast-radius control)

Even if the app has an RCE, you want it to die in a small box.

- [ ] Run the forge with a **non-root** user.
- [ ] Use a container/VM with:
  - [ ] **Read-only root filesystem** where possible
  - [ ] Minimal Linux capabilities
  - [ ] Tight seccomp/apparmor profiles
- [ ] Separate components:
  - [ ] Database on its own host/network segment
  - [ ] Object storage separate (if used)
- [ ] Restrict outbound egress from the forge:
  - [ ] Only allow what is necessary (SMTP, updates, object storage, etc.)

## 6) Secrets hygiene

- [ ] Keep secrets out of repos (and out of the forge host filesystem when possible).
- [ ] Store secrets in a dedicated secret manager.
- [ ] Rotate:
  - [ ] app/instance signing keys
  - [ ] OAuth client secrets
  - [ ] webhook secrets
  - [ ] deploy keys / CI tokens

## 7) Detection + response hooks

- [ ] Centralize logs (auth events, admin actions, repo settings changes).
- [ ] Alert on:
  - [ ] New admin users / role escalations
  - [ ] Hook/custom-hook edits
  - [ ] Unusual token creation
  - [ ] Webhook destination changes
- [ ] Practice a “forge compromise” playbook:
  - [ ] rotate secrets
  - [ ] invalidate sessions
  - [ ] audit repositories and CI

## 8) Quick checks after a new advisory drops

When a new high-severity advisory appears for your forge:

- [ ] Identify whether exploitation requires *repo admin*, *site admin*, or *unauthenticated* access.
- [ ] If it requires a special permission (e.g., hook editing), temporarily **disable that feature**.
- [ ] Patch/upgrade, then:
  - [ ] rotate secrets likely exposed
  - [ ] review logs for the vulnerable endpoint(s)

## References (recent examples)

These illustrate the recurring risk themes (path traversal/file write, config tampering, auth bypass):

- Gogs: arbitrary file read/write via path traversal in hook editing (fixed in v0.13.4)
  - https://github.com/advisories/GHSA-mrph-w4hh-gx3g
- Gogs: 2FA bypass via recovery code scoping bug
  - https://github.com/advisories/GHSA-p6x6-9mx6-26wj
- Gogs: authorization bypass allows read-only collaborators to delete repositories via API (fixed in v0.13.4)
  - https://github.com/advisories/GHSA-rjv5-9px2-fqw6
