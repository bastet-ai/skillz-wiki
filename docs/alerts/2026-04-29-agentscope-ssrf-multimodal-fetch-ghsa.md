# AgentScope SSRF in multimodal and URL-fetch helpers (GHSA-659x-hm75-hpv7 / GHSA-8ggf-r3vm-p3jc / GHSA-crx8-wpv6-jrj2)

**Signal:** GitHub Security Advisories updated **2026-04-28** for public SSRF issues in AgentScope up to 1.0.18.

## What it is
Multiple AgentScope helpers accepted attacker-influenced URLs and fetched them server-side, including paths used for multimodal image/audio handling and generic web URL byte loading.

Affected patterns include:

- `image_url` / `audio_file_url` in multimodal tooling
- internal URL byte-fetch helpers
- audio block processing paths

In agent frameworks, SSRF is especially risky because URL fetching may run near cloud metadata services, internal APIs, vector stores, model gateways, or privileged automation credentials.

References:
- GHSA-659x-hm75-hpv7: <https://github.com/advisories/GHSA-659x-hm75-hpv7>
- GHSA-8ggf-r3vm-p3jc: <https://github.com/advisories/GHSA-8ggf-r3vm-p3jc>
- GHSA-crx8-wpv6-jrj2: <https://github.com/advisories/GHSA-crx8-wpv6-jrj2>

## Triage
1. Find AgentScope deployments and notebooks that accept user-supplied image, audio, file, or URL inputs.
2. Identify the network context where the agent runtime executes:
   - cloud VM with metadata service access
   - Kubernetes pod with service-account token
   - internal VPC access
   - model/tool gateway access
3. Check whether SSRF egress controls block link-local, loopback, RFC1918, Kubernetes service, and cloud metadata ranges.
4. Review logs for suspicious fetches to `169.254.169.254`, localhost, cluster DNS names, internal admin panels, or unusual ports.

## Mitigation
- Upgrade when a fixed version is available; otherwise patch or wrap URL fetch helpers.
- Enforce explicit URL allowlists for multimodal inputs.
- Block redirects to private, loopback, link-local, and metadata ranges after every redirect hop.
- Run agent workloads in isolated networks without ambient access to metadata endpoints or internal control planes.
- Prefer object uploads or pre-scanned media blobs over arbitrary remote URL ingestion.

## Detection ideas
Look for:

- agent prompts or API calls containing internal URLs
- outbound requests to cloud metadata endpoints or Kubernetes service IPs
- repeated fetch failures to private network ranges
- new cloud credentials, tokens, or internal documents appearing in agent output

## Durable lesson
Any agent feature that says “give me a URL and I’ll process the content” is an SSRF boundary. Treat multimodal ingestion like a network client with attacker-controlled destinations.
