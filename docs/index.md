---
title: Skillz Wiki
---

# Skillz Wiki

Agent-ready offensive security skills, recon workflows, and replayable exploit-path notes.

## Recent entries

- [**LiteLLM JWT auth takeover: the userinfo cache keys on the first 20 token chars, and every issuer's JWT header starts the same way**](alerts/2026-06-08-litellm-authlib-dash-vitest-boundary-batch.md#november-16-follow-up-litellm-oidc-userinfo-cache-keyed-on-token20-jwt-header-prefix-collision-turns-cache-hit-into-identity-inheritance-ghsa-jjhc-v7c2-5hh6httpsgithubcomadvisoriesghsa-jjhc-v7c2-5hh6-cve-2026-35030-critical-fixed-1830-enrichment-landed-2026-11-16)
- [**SvelteKit server secrets in the public JS bundle: the build-time server-only import guard fails silently through src/params**](alerts/2026-06-09-svelte-ssr-spread-dom-clobbering-boundary-ghsa.md#november-16-follow-up-sveltekit-build-time-server-only-import-guard-failure-bakes-server-secrets-into-the-client-bundle-and-protocol-relative-module-imports-run-cross-origin-code-2-ghsas)
- [**Nuxt auth bypass with one slash: /admin%2Fsecret renders the protected catch-all page while route rules never fire**](alerts/2026-08-05-nuxt-route-payload-cache-boundaries-ghsa.md#november-16-follow-up-2f-route-rule-bypass-incomplete-fix-island-prop-hash-collision-and-ssr-error-payload-leakage-3-ghsas-nuxt-464)
- [**Feed-key login mints a full web session: replay any leaked API or feed token at the browser-session gate, password resets never kill it**](alerts/2026-09-18-mongoid-orm-query-grammar-blazar-authz-fallback-and-cotonti-predictable-tokens-ghsa.md#november-16-follow-up-vulnerability-lookup-a-feed-key-is-a-web-session-in-disguise-and-a-session-id-made-of-just-the-user-id-never-dies-cve-2026-129703--ghsa-p848-gw9g-wq38-high-cve-2026-129706--ghsa-rj73-gwhj-q23q-medium)
- [**SSCMS file read: the upload endpoint copies any server file into your public folder, download it anonymously**](alerts/2026-07-30-tika-leantime-file-reference-boundaries-ghsa.md#november-16-follow-up-sscms-layerimageupload-a-copy-parameter-turns-an-upload-endpoint-into-an-anonymous-download-file-read-cve-2026-129539-ghsa-j86m-5x66-8h64-high-720-through-740)
- [**CloudPaste share proxy leaks the WebDAV password to anyone who knows the slug, backend-wide read and delete**](alerts/2026-07-30-url-policy-tenant-oauth-boundaries-ghsa.md#november-16-follow-up-cloudpaste-apiproxylink-replays-the-stored-webdav-basic-auth-header-to-any-anonymous-caller-who-knows-the-share-slug-cve-2026-129494-ghsa-q4wf-rcwf-h4xf-high-110-through-191)
- [**VoAPI SQLi via search filter keys: read the JWT signing secret from the options table, forge admin tokens**](alerts/2026-07-14-kimai-facturascripts-auth-boundaries-ghsa.md#november-16-follow-up-voapi-search-filter-key-sqli-to-hs256-signing-secret-theft-and-manager-token-forgery-cve-2026-129540-ghsa-6ww7-crwx-359p-high-100-through-120)
- [**Cyrus SASL SRP no-password login: send A = N, the shared secret becomes zero, log in as anyone**](alerts/2026-09-21-auth-method-precedence-http-verb-allowlists-and-acl-tiebreak-drift-ghsa.md#november-15-follow-up-cyrus-sasl-srp-server-accepts-a-n-the-shared-secret-collapses-to-zero-and-any-existing-user-logs-in-with-no-password-cve-2026-129483-ghsa-h9fw-9v74-m2cr-critical-93-through-2128)
- [**OkHttp pinning bypass on trailing-dot hostnames: an allowlist miss that skips the check instead of failing it**](methodology/canonicalization-differentials-at-security-gates.md#november-15-follow-up-okhttp-certificatepinner-skips-the-pin-check-on-trailing-dot-hostnames-cve-2026-129482-ghsa-p22c-cv6w-qc6x-medium-through-551)
- [**Apache Shiro any-password login: auth cache hits skip the LDAP bind and the default matcher checks nothing**](alerts/2026-09-21-auth-method-precedence-http-verb-allowlists-and-acl-tiebreak-drift-ghsa.md#november-15-follow-up-apache-shiro-defaultldaprealm-caches-the-login-but-verifies-nobody-on-cache-hits-any-password-works-while-the-entry-is-warm-cve-2026-129349--ghsa-3j37-vw7v-fxxw-critical-all-versions-through-300-fixed-301)


