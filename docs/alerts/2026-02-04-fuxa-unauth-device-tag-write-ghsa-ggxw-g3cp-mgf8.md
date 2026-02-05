# 2026-02-04 — FUXA unauthenticated remote arbitrary device tag write (GHSA-ggxw-g3cp-mgf8)

**Product:** FUXA (SCADA/HMI)

**Issue:** Missing authorization on WebSocket endpoints can allow an **unauthenticated remote attacker** to modify device tags / disable communication drivers.

**Affected:** FUXA `<= 1.2.9`

**Fixed:** `1.2.10`

## Why it matters
In ICS/SCADA contexts, “write a device tag” is not a cosmetic bug. If FUXA is reachable by an attacker, this can enable:

- Unauthorized manipulation of process values / control signals
- Disruption (drivers disabled, data integrity loss)
- Follow-on compromise via operational impact and operator deception

## What to do
1. **Upgrade to FUXA 1.2.10 or later**.
2. **Restrict network exposure**
   - Do not expose FUXA to the public internet.
   - Put it behind VPN / zero-trust access and strict firewall rules.
3. **Assume compromise if exposed**
   - Review access logs, WebSocket activity, and unexpected tag value changes.
   - Validate device state against independent instrumentation when possible.

## References
- Advisory: https://github.com/advisories/GHSA-ggxw-g3cp-mgf8
- Vendor advisory: https://github.com/frangoteam/FUXA/security/advisories/GHSA-ggxw-g3cp-mgf8
