# How to use this wiki

- Prefer durable skills, recon workflows, and exploit-path notes over one-off advisories.
- Write so an agent can execute the workflow without guessing at missing prerequisites.
- Keep links explicit and command examples reproducible.
- Keep mitigation or defensive-response advice secondary unless it is required to replay or safely scope the path.

## Section definitions

- **Skills**: tool-specific guides that can be installed into an agent workflow
- **Recon**: how multiple skills combine into discovery, prioritization, and target shaping
- **Exploit Paths**: specific, replayable attack chains for authorized testing
- **Templates**: reusable report and handoff skeletons
- **Notes**: taxonomy, editorial rules, and source tracking
- **Blog**: launch notes and major updates

Legacy alert or mitigation-oriented pages can remain in the repo when they are worth preserving, but they should stay out of the main nav unless the user explicitly asks for that framing.

## Authoring rules

- Put the command that matters, not every possible flag combination.
- State assumptions about scope, credentials, and environment.
- Separate observed behavior from inference.
- Keep pages short enough to be copied into a skill bundle without heavy trimming.
