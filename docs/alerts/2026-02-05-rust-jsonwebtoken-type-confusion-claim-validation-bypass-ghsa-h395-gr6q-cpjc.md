# 2026-02-05 — Rust jsonwebtoken claim validation bypass via type confusion (GHSA-h395-gr6q-cpjc)

**Product:** Rust crate **`jsonwebtoken`**

## Impact (per advisory)
Malformed standard claims (e.g., `nbf` / `exp`) provided with the **wrong JSON type** (string instead of number) can be treated as **"not present"** rather than invalid.

If an application enables time-claim validation (e.g., `validate_nbf=true`) but does **not** add those claims to `required_spec_claims`, an attacker may bypass time-based validation.

**Fixed:** **jsonwebtoken 10.3.0**

## Recommended actions
- **Upgrade** to **jsonwebtoken 10.3.0+**.
- Defense-in-depth:
  - Treat spec claims as **required** if your authorization logic relies on them.
  - Validate claim types strictly before passing to authZ decisions.

## References
- GitHub advisory: <https://github.com/advisories/GHSA-h395-gr6q-cpjc>
