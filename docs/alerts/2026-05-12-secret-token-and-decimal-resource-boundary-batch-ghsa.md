# Secret-token and decimal resource-boundary batch

Source: GitHub Security Advisories published 2026-05-12.

This batch is durable because it captures two easy-to-miss boundary mistakes: signed tokens are not encrypted containers, and numeric parsers need resource budgets before arithmetic or formatting expands attacker-controlled values.

## Advisories covered

- **sealed-env TOTP secret embedded in unseal token payload** — [GHSA-x3r2-fj3r-g5mv](https://github.com/advisories/GHSA-x3r2-fj3r-g5mv), CVE-2026-45091: enterprise-mode `sealed-env` versions before `0.1.0-alpha.4` embedded the operator's literal TOTP secret in every minted JWS unseal token. JWS payloads are base64-encoded and signed, not encrypted, so tokens visible in CI logs, env dumps, Kubernetes descriptions, or exception telemetry exposed the second-factor seed. Fixed versions replace the embedded secret with a salt-bound HMAC derivative; affected files must be re-sealed and the TOTP secret rotated.
- **Elixir Decimal unbounded exponent DoS** — [GHSA-rhv4-8758-jx7v](https://github.com/advisories/GHSA-rhv4-8758-jx7v), CVE-2026-32686: `decimal >= 0.1.0, < 3.0.0` accepted values such as `1e1000000000`; later arithmetic, rounding, conversion, or normal string formatting could allocate or recurse proportional to the exponent and OOM the BEAM from one request.

## Operator triage

1. Upgrade `sealed-env` npm/Maven packages to `0.1.0-alpha.4` or later; rotate the enterprise TOTP secret and re-seal affected files because old token payloads may have leaked the raw secret.
2. Search CI logs, crash reports, container environment snapshots, deployment manifests, and observability stores for exposed sealed-env unseal tokens; treat any historical token as a possible TOTP-secret disclosure.
3. Upgrade Elixir `decimal` to `3.0.0` or later; identify endpoints that parse user-supplied decimals through JSON, forms, Ecto changesets, CSV imports, or API parameters.
4. Add temporary input limits while patching: reject decimal strings with large exponent components, excessive length, or non-business-required scientific notation.
5. Review crash/OOM telemetry for suspicious very-large-exponent decimal values and restart loops in services that process unauthenticated numeric input.

## Durable controls

- Signed tokens provide integrity, not confidentiality. Never place raw secrets, seed material, private keys, or second-factor values in a JWS/JWT payload unless it is additionally encrypted for every intended observer.
- Document token exposure assumptions: if a token may appear in logs, env vars, URLs, CLI output, or support bundles, its payload must be safe to disclose.
- Numeric parser acceptance must be separate from business acceptance. Put length, exponent, precision, and scale limits at the perimeter before conversion reaches arithmetic or rendering.
- Treat formatting as a resource sink: `to_string`, JSON encoding, database casting, and template rendering can be as dangerous as arithmetic when attacker-controlled magnitudes expand.
- Add regression tests for pathological numbers (`1eN`, deeply nested numeric containers, extreme scale) and for decoded-token payload review during security design.
