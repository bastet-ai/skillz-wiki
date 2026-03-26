# Skillz Wiki

Skillz Wiki is a public MkDocs site that doubles as an installable skill library for security-focused agents. It combines tool-specific skills, workflow playbooks, checklists, and editorial guidance so the same material can be read on the web or packaged into agent prompts.

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

- `docs/alerts/`: incident notes, advisories, and current threat references
- `docs/skills/`: installable, tool-specific skills for agents
- `docs/methodology/`: cross-tool playbooks and engagement flow
- `docs/checklists/`: compact review lists for common assessment types
- `docs/best-practices/`: reporting and publishing conventions
- `docs/process/`: recurring operational workflows for research and triage
- `docs/notes/`: taxonomy, source tracking, and editorial guidance
- `docs/blog/`: launch notes and notable updates
- `overrides/` and `docs/stylesheets/`: shared presentation layer for the site theme

## Publishing

GitHub Pages is driven by [`.github/workflows/deploy.yml`](/home/pierce/projects/skillz-wiki/.github/workflows/deploy.yml). The workflow installs `requirements.txt` and runs a strict MkDocs build on pushes to `main`.

The production site is published at `https://skillz.wiki/`.
