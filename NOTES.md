# Publishing notes

## 2026-10-09

- Confirmed Cloudflare Workers Builds is enabled for `bastet-ai/skillz-wiki`, production branch `main`, Worker `skillz-wiki`, root `/`, and included paths `*`.
- The build command is `npm run build`; the deploy command is `npx wrangler deploy`. Checked-in `.node-version` and `.python-version` select the build runtimes.
- Cloudflare fetches and deploys repository commits using its GitHub app. The deployment credential stays in Cloudflare; no Cloudflare secrets were added to GitHub. No build variables or secrets were configured.
- GitHub Actions remains validation-only. Manual recovery must pause automatic builds and wait for running builds to finish before deploying; verify the site before re-enabling builds.
- Existing custom-domain configuration, DNS, and the previous GitHub Pages deployment remain available for recovery.

Local validation before connection: `npm run build`, `npm run deploy:check`, and `npm run test:hosting` passed. The hosting check covers pages, canonical and directory URLs, search, feed, and 404 handling.

### First Git-triggered deployment verified

- Pushing commit [`c4dc6b85dde54e1451161a48d19a89d14e4b6517`](https://github.com/bastet-ai/skillz-wiki/commit/c4dc6b85dde54e1451161a48d19a89d14e4b6517) triggered Cloudflare build `fc33cc31-bd34-4e2f-ade9-539429448f04`, which succeeded and published Worker version `c8b7779b-32e0-46b6-ac34-8e4cd3d5ae0f`. GitHub validation for that commit also succeeded. Exact commit identity comes from Cloudflare build/version evidence, not from the HTTP checks alone.
- All nine HTTPS checks passed through `https://skillz-wiki.bcrt43.workers.dev/` at 20:13 UTC: homepage, `/skills/httpx/`, both canonical URLs using `skillz.wiki`, a 307 trailing-slash redirect, linked CSS, a valid search index with 9,081 entries including the article, a valid RSS feed, and a real 404 for a missing page. Certificate verification remained enabled.
- Direct `https://skillz.wiki/` verification remains blocked on the current network. The same reset appeared in the initial baseline before this Git deployment. Local DNS, two public resolvers, and both authoritative Cloudflare nameservers agree; HTTPS failure follows the `skillz.wiki` hostname even on otherwise working Cloudflare addresses. The workers.dev hostname succeeds with verified TLS on both addresses assigned to `skillz.wiki`.
- HTTP to `skillz.wiki` returned a 302 to `wired.meraki.com:8090/blocked.cgi` with `blocked_url=skillz.wiki` and `blocked_categories=bs_050`; the redirect was not followed. [Cisco Meraki documents HTTP block-page redirects and HTTPS TCP resets for category blocks](https://documentation.meraki.com/MX/Troubleshooting_and_Support/Troubleshooting/A_Guide_to_Troubleshooting_Blocked_Traffic). Current-network Meraki filtering is the likely cause, an inference supported by that response and the TLS comparisons. The category label and applicable policy were not queried.
- Custom-domain HTTPS from an independent unfiltered network remains unverified. No network, security, or DNS settings were changed during diagnosis, and these results do not justify speculative Cloudflare DNS/TLS changes.

### Manual independent HTTPS verification prepared

Added `.github/workflows/verify-public-https.yml`, triggered only by
`workflow_dispatch`, with read-only repository permission and a five-minute job
limit. It invokes the standard-library helper `scripts/check-public-https.py`
from an independent GitHub runner. Curl retains normal CA/hostname verification,
follows no redirects, accepts only the hardcoded `skillz.wiki` and Worker HTTPS
hosts, and has bounded connection/request/body limits. Checks cover the custom
homepage and article, canonical URLs, linked CSS, populated search, RSS, real 404,
and the workers.dev HTTPS comparison. It prints only safe status/check labels.

This job validates serving and HTTPS; it neither publishes nor uses Cloudflare
secrets. Dispatch only after the matching native Cloudflare deployment settles,
to avoid confusing a deployment race with a serving failure. Local Meraki evidence
still limits direct custom-domain checks here; independent public HTTPS remains
unverified until this workflow is actually run and its results are reviewed.
No network-policy, DNS, certificate, or hosting changes were made for this verifier.

The verifier scope input defaults to `skillz`; `all-wikis` adds HTTPS homepage
and HTTP-to-HTTPS redirect checks for the other ten hardcoded canonical hosts.
No arbitrary URL input is accepted and no redirect is followed. Do not dispatch
`all-wikis` before the eight new sites finish their DNS/domain/redirect cutovers.
The Cloudflare dashboard reports active Skillz apex/wildcard certificates through
2026-12-29, and Always Use HTTPS is now enabled; these dashboard observations do
not replace independent public TLS/redirect evidence. That evidence remains
pending the reviewed manual workflow run.
