# Reporting Best Practices

Skillz Wiki reporting guidance is simple: make the finding easy to verify, easy to scope, and hard to misunderstand.

## Minimum structure

1. Title that names the issue and affected surface.
2. Short summary of the broken boundary.
3. Prerequisites and authentication state.
4. Reproduction steps with exact requests or commands.
5. Observed result and impact.
6. Clear remediation direction.

## Evidence rules

- Keep raw requests, responses, and timestamps.
- Screenshot only when it adds context beyond the raw evidence.
- Record the exact account role or privilege level used.
- Distinguish observed behavior from inferred worst case.

## Writing rules

- Prefer plain language over scanner terminology.
- Do not inflate severity with hypothetical chain assumptions.
- State the narrowest true claim first.
- Make remediation actionable enough for an engineer to start fixing.

## Before publishing

- Re-run the proof once from clean state if possible.
- Remove secrets, tokens, and unrelated sensitive data from artifacts.
- Confirm the affected asset names are correct.
- Check that rollback or cleanup steps are documented.
