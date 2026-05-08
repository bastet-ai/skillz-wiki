# Open WebUI model, channel, and knowledge-boundary batch

**Signal:** The **2026-05-08 20:15 UTC** advisory scan surfaced a large Open WebUI authorization batch across model routing, Ollama passthrough APIs, knowledge-base access, channel membership, Socket.IO state, Redis cache namespacing, LDAP login, and mass assignment.

## Advisory cluster

All listed advisories affect `open-webui <= 0.8.12` according to GitHub metadata:

- **Knowledge/file and RAG boundaries** — [GHSA-h36f-rqpx-j5wx](https://github.com/advisories/GHSA-h36f-rqpx-j5wx), [GHSA-6c2x-gcp3-gp73](https://github.com/advisories/GHSA-6c2x-gcp3-gp73), [GHSA-7r82-qhg4-6wvj](https://github.com/advisories/GHSA-7r82-qhg4-6wvj): unauthorized file/knowledge content access, global KB enumeration, and collection overwrite leading to destruction or RAG poisoning.
- **Channel and collaborative-document access** — [GHSA-hmgr-67hw-j2cq](https://github.com/advisories/GHSA-hmgr-67hw-j2cq), [GHSA-vrfh-rj4q-rmhr](https://github.com/advisories/GHSA-vrfh-rj4q-rmhr), [GHSA-c7wp-3qh5-55pv](https://github.com/advisories/GHSA-c7wp-3qh5-55pv), [GHSA-7rjh-px4v-5w55](https://github.com/advisories/GHSA-7rjh-px4v-5w55): deactivated channel members, read-only users, missing member checks, and access-grant filter bypasses.
- **Model and tool execution boundaries** — [GHSA-rcvp-6fgw-c7fh](https://github.com/advisories/GHSA-rcvp-6fgw-c7fh), [GHSA-mqq6-cqcx-38vg](https://github.com/advisories/GHSA-mqq6-cqcx-38vg), [GHSA-hp5m-24vp-vq2q](https://github.com/advisories/GHSA-hp5m-24vp-vq2q), [GHSA-9vvh-qmjx-p4q8](https://github.com/advisories/GHSA-9vvh-qmjx-p4q8): Ollama API bypasses, model import overwrite, responses passthrough authorization gaps, and model chaining access-control bypass.
- **Session/cache/account-state boundaries** — [GHSA-3x8w-4f7p-xxc2](https://github.com/advisories/GHSA-3x8w-4f7p-xxc2), [GHSA-45m8-cpm2-3v65](https://github.com/advisories/GHSA-45m8-cpm2-3v65), [GHSA-hr43-rjmr-7wmm](https://github.com/advisories/GHSA-hr43-rjmr-7wmm), [GHSA-2r4p-jpmg-48f4](https://github.com/advisories/GHSA-2r4p-jpmg-48f4): cross-instance Redis cache poisoning, stale admin Socket.IO role state, Pydantic `extra='allow'` mass assignment, and LDAP empty-password authentication bypass.

## Why this matters

AI web consoles collapse many trust zones: user documents, shared channels, model registries, vector collections, tool servers, and external model APIs. If each endpoint reimplements authorization, one passthrough or stale realtime session becomes a broad data/control-plane bypass.

## Triage

1. Patch Open WebUI beyond `0.8.12` as soon as fixed packages are available; otherwise isolate or disable exposed risky features until patched.
2. Rotate LDAP and admin sessions for deployments where empty-password or stale-role risks may have been reachable.
3. Review access logs for direct calls to `/api/generate`, `/api/embed`, `/api/embeddings`, `/api/show`, responses passthrough, model import, KB metadata, and Socket.IO document/channel events.
4. Inspect vector collections and model registry entries for unauthorized overwrites, poisoning, or unexpected ownership.

## Durable controls

- Put one authorization gate in front of every model, vector, document, channel, and passthrough operation; do not rely on UI filtering.
- Revalidate role, membership, deactivation, and ownership on every realtime event and long-lived socket action.
- Namespace cache keys by tenant/deployment/user where appropriate.
- Reject unknown request fields by default; avoid permissive schema modes for authorization-relevant objects.
- Treat model chaining and tool passthrough as delegation: the caller must be allowed to reach every downstream model/tool.
