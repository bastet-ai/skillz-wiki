# Skillz Wiki

Skillz Wiki is a public MkDocs site that doubles as an installable skill library for security-focused agents. It is centered on recon tooling, offensive workflow notes, and replayable exploit paths for authorized pentesting, red-team, and bug-bounty work.

## Local development

```bash
python -m pip install -r requirements.txt
mkdocs serve
```

Open `http://127.0.0.1:8000` while serving locally.

## Validation

```bash
mkdocs build --strict
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

GitHub Pages is driven by [`.github/workflows/deploy.yml`](.github/workflows/deploy.yml). The workflow installs `requirements.txt` and runs a strict MkDocs build on pushes to `main`.

The production site is published at `https://skillz.wiki/`.
