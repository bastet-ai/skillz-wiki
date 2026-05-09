# AI JWT and YAML deserialization-boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced LightRAG and PraisonAI issues updated on **2026-05-09**.

This batch is durable because AI service control planes commonly deserialize agent definitions and accept bearer tokens at the same boundary where tools, files, and network actions become available. Authentication and configuration formats need boring, explicit allowlists before they touch agent authority.

## Advisories covered

- **LightRAG JWT algorithm confusion** — [GHSA-8ffj-4hx4-9pgf](https://github.com/advisories/GHSA-8ffj-4hx4-9pgf): crafted JWTs using `alg: none` could be accepted by the API token validator, enabling unauthorized access. Affects `lightrag-hku <= 1.4.13`; fixed in `1.4.14`.
- **PraisonAI YAML agent-definition RCE** — [GHSA-32vr-5gcf-3pw2](https://github.com/advisories/GHSA-32vr-5gcf-3pw2): uploaded agent definition files were parsed with `js-yaml` behavior that allowed dangerous JavaScript tags such as `!!js/function`, leading to server-side code execution. Affects `praisonai <= 4.5.114`; fixed in `4.5.115`.

## Operator triage

1. Patch LightRAG to `1.4.14+` and PraisonAI to `4.5.115+`; isolate unfixed AI service frontends from secrets and internal egress.
2. Hunt access logs for unsigned JWTs, `alg=none`, unexpected admin-role claims, and token validation failures that later succeed from the same source.
3. Review uploaded or repository-sourced agent YAML for `!!js/function`, `!!js/undefined`, object-constructor tags, shell/process strings, and unexpected tool definitions.
4. Revoke tokens and rotate service/API keys if forged token acceptance or malicious agent upload paths were reachable.
5. Re-run agent import tests with dangerous YAML tags and unsigned JWT fixtures before restoring internet exposure.

## Durable controls

- JWT validators should pin one expected algorithm server-side, reject `none`, enforce issuer/audience/expiry, and never trust the token header to choose verification behavior.
- Agent-definition formats should use data-only schemas such as JSON schema or safe YAML schemas; executable tags and constructors belong outside upload/import paths.
- Uploaded agent definitions need separate authorization, content validation, review/audit events, and sandboxed dry-run parsing before they can register tools.
- AI control planes should treat model, YAML, notebook, and repository content as untrusted configuration until a non-model policy layer grants execution authority.
