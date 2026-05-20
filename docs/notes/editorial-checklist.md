# Editorial checklist

Use this before publishing a new skill or major update.

## Basics

- [ ] Title is short and specific
- [ ] Links are clickable Markdown links
- [ ] Commands are reproducible and minimally scoped
- [ ] Page is in the right section
- [ ] Safety, scope, and authorization limits are stated

## Content fit

- [ ] Page is primarily useful to authorized penetration testers, red-teamers, or bug hunters
- [ ] Offensive workflow, recon value, exploit validation, or reporting value is explicit
- [ ] Blue-team/SecOps material is omitted or reframed as operator context only
- [ ] Mitigation or incident-response guidance is not the main purpose unless explicitly requested

## Operator quality

- [ ] Tool trigger conditions or exploit preconditions are clear
- [ ] Required inputs, prerequisites, and environment assumptions are listed
- [ ] Output handling and evidence capture are explained
- [ ] Replay steps are specific enough to run again later
- [ ] Claims match observed behavior and label any inference

## Maintenance

- [ ] `mkdocs.yml` nav is updated when the page is first-class content
- [ ] `docs/index.md` recent entries are updated if the addition is notable
- [ ] `docs/feed.xml` and blog index are updated for major launches or major repositioning posts
- [ ] `docs/notes/source-index.md` is extended if a new tool family is added
- [ ] Alert, mitigation-heavy, incident-response, or defensive-SecOps pages are not promoted in nav unless the user explicitly wants that framing
