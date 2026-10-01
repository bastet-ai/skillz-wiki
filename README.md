# Skillz Wiki

Skillz Wiki is a public MkDocs site that doubles as an installable skill library for security-focused agents. It is centered on recon tooling, offensive workflow notes, and replayable exploit paths for authorized pentesting, red-team, and bug-bounty work.

## Local development

```bash
npm ci
npm run build
npm run dev
```

Open `http://127.0.0.1:8787` while serving locally. The build creates an isolated
`.venv` with the pinned Python dependencies. For live Markdown editing, run
`.venv/bin/mkdocs serve` and open `http://127.0.0.1:8000`.

## Validation

```bash
npm run build
npm run deploy:check
npm run test:hosting
```

## Content model

- `docs/skills/`: installable, tool-specific skills for agents
- `docs/methodology/`: recon workflows and exploit-path writeups
- `docs/report-templates/`: reporting skeletons for handoff
- `docs/notes/`: taxonomy, source tracking, and editorial guidance
- `docs/blog/`: launch notes and notable updates
- `overrides/` and `docs/stylesheets/`: shared presentation layer for the site theme

Older `docs/alerts/`, `docs/best-practices/`, and `docs/process/` pages may remain as archive/reference material, but they are not the main navigation model.

## Publishing

Cloudflare Workers Static Assets serves the generated `site/` directory. The
strict MkDocs build, advisory duplicate-ID check, directory URLs, search index,
feed, and custom 404 page are preserved. No database or runtime secrets are needed.

Connect `bastet-ai/skillz-wiki` to the `skillz-wiki` Worker using
[Workers Builds](https://developers.cloudflare.com/workers/ci-cd/builds/):

- Production branch: `main`
- Build command: `npm run build`
- Deploy command: `npm run deploy`
- Root directory: repository root
- Node.js and Python versions: the checked-in `.node-version` and `.python-version`

[`validate.yml`](.github/workflows/validate.yml) checks pushes and pull requests
without publishing to GitHub Pages. Workers Builds is not connected yet. Until
the Cloudflare GitHub app is installed and this repository is connected, publish
the Worker manually from an up-to-date `main` checkout:

```bash
npm ci
npm run build
npm run deploy:check
npm run test:hosting
npm run deploy
```

The Cloudflare preview is [skillz-wiki.bcrt43.workers.dev](https://skillz-wiki.bcrt43.workers.dev/).
The production custom domain [skillz.wiki](https://skillz.wiki/) is attached in
`wrangler.jsonc`. The September 2026 cutover added only this exact hostname;
there were no conflicting Cloudflare DNS records. Keep existing MX/TXT records
when changing the site's DNS. The previous GitHub Pages deployment and `docs/CNAME` remain
as domain metadata and for rollback; it does not configure Cloudflare routing.

The Wrangler configuration enables logs and traces for any Worker execution.
Asset-only requests are served directly by the static asset service and do not
produce Worker invocation logs. Use Cloudflare HTTP analytics for site traffic.

The production site is published at `https://skillz.wiki/`.
