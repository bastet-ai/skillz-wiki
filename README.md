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

[`validate.yml`](.github/workflows/validate.yml) checks pushes and pull requests.
Cloudflare owns automatic production deployment; GitHub Actions only validates.
Attach `skillz.wiki` as a Worker custom domain after verifying the initial
`workers.dev` deployment, then record the custom domain in `wrangler.jsonc`.
Keep existing MX/TXT records when changing the site's DNS. `docs/CNAME` remains
as domain metadata and for rollback; it does not configure Cloudflare routing.

The Wrangler configuration enables logs and traces for any Worker execution.
Asset-only requests are served directly by the static asset service and do not
produce Worker invocation logs. Use Cloudflare HTTP analytics for site traffic.

The production site is published at `https://skillz.wiki/`.
