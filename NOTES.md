# Publishing notes

## 2026-10-09

- Confirmed Cloudflare Workers Builds is enabled for `bastet-ai/skillz-wiki`, production branch `main`, Worker `skillz-wiki`, root `/`, and included paths `*`.
- The build command is `npm run build`; the deploy command is `npx wrangler deploy`. Checked-in `.node-version` and `.python-version` select the build runtimes.
- Cloudflare fetches and deploys repository commits using its GitHub app. The deployment credential stays in Cloudflare; no Cloudflare secrets were added to GitHub. No build variables or secrets were configured.
- GitHub Actions remains validation-only. Manual recovery must pause automatic builds and wait for running builds to finish before deploying; verify the site before re-enabling builds.
- Existing custom-domain configuration, DNS, and the previous GitHub Pages deployment remain available for recovery.

Local validation before connection: `npm run build`, `npm run deploy:check`, and `npm run test:hosting` passed. The hosting check covers pages, canonical and directory URLs, search, feed, and 404 handling.

Verification pending: a push-triggered Cloudflare build for the documentation commit, its deployed commit/build identifier, and public HTTPS checks after that deployment. Connection settings alone do not prove the complete deployment path.
