# GPUStack coordinated wave

Source: hourly offensive-security scan of GitHub Security Advisories, 2026-11-10. Three GHSAs for GPUStack (Kubernetes/LLM inference manager) published in the Nov 9-10 window; **the loopback leg is now in CISA KEV (catalog 2026.11.10, added 2026-11-09) with the advisory itself reporting observed exploitation against a v2.1.1 deployment (attacker-created custom inference backends running reverse shells)**. Related pages: [Oct 2 AI serving/RAG wave](2026-10-02-ai-serving-rag-stack-authz-and-path-wave-ghsa.md) (route-guard parity doctrine), [July 8 browser-to-loopback control-plane page](2026-07-08-integration-deploy-mcp-boundaries-ghsa.md) (Host-is-data-not-identity), [Sept 16 IdP authority page](2026-09-16-zitadel-keycloak-nezha-identity-provider-authority-boundaries-ghsa.md) (SAML validation legs).

Why durable: GPUStack sits between a web UI and GPU worker nodes with cloud/provider credentials, the same "AI infrastructure control plane as initial-access target" pattern the wiki tracks for vLLM, LMCache, and MLflow. This wave shows three *independently sufficient* unauthenticated paths to admin, which means fingerprint-and-pick: you rarely need to chain.

## Advisory table

| GHSA | CVE | CVSS | Leg |
| --- | --- | --- | --- |
| [GHSA-gj9m-f8ph-pmhr](https://github.com/advisories/GHSA-gj9m-f8ph-pmhr) | [CVE-2026-102895](https://nvd.nist.gov/vuln/detail/CVE-2026-102895) | 9.8 **KEV'd 2026-11-09** | Loopback auto-admin: TCP peer *or* `X-GPUStack-Real-IP: 127.0.0.1` → built-in administrator, no credentials |
| [GHSA-62m9-f875-rqw6](https://github.com/advisories/GHSA-62m9-f875-rqw6) | [CVE-2026-102894](https://nvd.nist.gov/vuln/detail/CVE-2026-102894) | 9.1 | SAML callback Base64-decodes and trusts the `SAMLResponse`, **never calls `OneLogin_Saml2_Auth.process_response()`** → auth bypass + ATO as any named identity |
| [GHSA-3hch-x692-6qj3](https://github.com/advisories/GHSA-3hch-x692-6qj3) | [CVE-2026-103002](https://nvd.nist.gov/vuln/detail/CVE-2026-103002) | 8.8 | `cluster_apiserver_proxy` forwards to the chosen Kubernetes cluster with the **worker's ServiceAccount**, no resource-level authz → cross-user cluster read/workload-create/delete |

Fixed bands: 2.2.0 (loopback leg), 2.2.2 (SAML + proxy legs). Empty-version-field GHSA banding again → fingerprint the deployment from the console footer/API banner.

## Leg 1, "localhost is trusted" dies at the reverse proxy, twice

`get_current_user` promotes any request whose source "is loopback" to the built-in admin when `force_auth_localhost` is `False`, **the default**. Two ways the source reports `127.0.0.1` with no credentials:

1. **Same-host reverse proxy (the canonical deployment shape).** `proxy_pass http://127.0.0.1:<port>` makes *every* remote request arrive with TCP peer `127.0.0.1`; the loopback auto-admin branch fires for the whole internet. No header needed. Verified end-to-end by the advisory against HEAD.
2. **`X-GPUStack-Real-IP: 127.0.0.1`**, the product's own forwarded-client-IP header feeds the same trust decision.

Outcome: enumerate/modify users, models, workers, config; mint persistent `["*"]`-scope API keys valid from any source IP; read worker credentials and cloud/provider secrets; and `POST /v2/inference-backends/from-yaml` → code execution on worker hosts (this is exactly the reverse-shell primitive ITW used).

Operator rules:
- **Deployment-shape is the vulnerability predicate.** If the target is nginx/Caddy-in-front-of-app on one host, the socket-peer trust branch is *already* bypassed, test it as the first auth probe on any appliance/self-hosted console that documents a localhost admin mode. Ask: does the app derive identity from anything a proxy homogenizes (TCP peer, source port, UDS absence)?
- **Product-named Real-IP headers are forged by default.** Extend the forwarding-header battery beyond `XFF`/`X-Real-IP`/`X-Forwarded-*` to `<PRODUCT>-Real-IP` style headers, grep the source/config for header names ending in `Real-IP`/`Client-IP` and try the loopback value plus the RFC1918/metadata spellings.
- **API-key persistence changes the reporting tier.** A one-request unauth admin that can mint a `["*"]` token is a full-compromise finding, not a bypass curiosity; capture key mint + one read-only API call as proof, then delete the key.
- **KEV-with-ITW in ~days**: advisory published with observed exploitation, KEV added within days, treat unpatched <2.2.0 as presumptively owned; version evidence (`GET /` banner vs `/healthz` build string) before any claim.

## Leg 2, the SAML callback that verifies nothing

The callback Base64-decodes the posted XML, reads NameID/attributes, resolves-or-provisions the user, and mints a session JWT, with **no signature, issuer, audience, destination, or time-condition validation**. Three durable axes beyond the standing SAML decision matrix:

- **Feature-off is not route-off.** SAML SSO does not need to be *configured*: the callback processes payloads regardless, so every deployment, not just SAML-enabled ones, is affected. Probe every authentication-provider callback family (SAML/OIDC/social) even when the login UI never mentions it; the fix (gating routes to the *active* provider) is the tell for which alternate channels existed.
- **The verification library call that was never made.** `OneLogin_Saml2_Auth.process_response()` exists, is documented, and wasn't called. When auditing any IdP-integrated app from the outside: does the *unsigned* shape get accepted? Post a Base64 of your own XML naming an existing admin. Positive control: a tampered-but-structured response that a real validator would reject.
- **No ID consumption = immortal replay.** Response/Assertion IDs are never stored, so even a *legitimately signed* response captured once (shared link, log, proxy) replays indefinitely. Fold into the three-leg replay matrix (fresh / replay-in-window / expired): GPUStack's third leg never expires.

## Leg 3, the cluster proxy is a confused deputy with someone else's credentials

Any authenticated non-admin user could drive the Kubernetes API of a cluster they were never granted, because the proxy checked *nothing* resource-level before forwarding through a worker's ServiceAccount. Operator read: on AI/ML platforms, the **control plane holds per-tenant cluster credentials and acts with them on user input**; run the full Kubernetes verb battery (get/list pods+secrets, create workload) through every proxy passthrough route as the lowest authenticated role. Creating an attacker-controlled workload = code execution in the target cluster, the pod-spec shapes from the June 22 container page apply (hostPath, privileged, SA token mounts).

## Validation boundaries

Authorized labs only: disposable GPUStack at affected bands behind your own same-host nginx, your own fake IdP XML (no real IdP), synthetic workers/clusters. Proofs: unauth admin = one read-only admin API call + immediate key deletion; SAML = forged NameID pointing at your own second account; proxy = `kubectl get pods` through the proxy from a disposable low-priv user. Never mint keys, create backends, or read worker credentials on production inference infrastructure, reverse-shell primitives are lab-only by definition.
