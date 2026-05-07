# Free5GC and mobile-core state boundary batch

**Signal:** GitHub Security Advisories REST fallback surfaced a **2026-05-07** Free5GC batch where mobile-core APIs leaked subscriber state, skipped authentication middleware, or mishandled security-capability transitions.

## Advisories covered

- **Free5GC UDM input validation and sensitive error disclosure** — [GHSA-585v-hcgf-jhfr](https://github.com/advisories/GHSA-585v-hcgf-jhfr): malformed input and verbose errors can expose sensitive subscriber or backend state.
- **Free5GC PCF missing authentication middleware** — [GHSA-6rgm-gr97-x3j5](https://github.com/advisories/GHSA-6rgm-gr97-x3j5): SM policy handlers exposed subscriber SUPI data without the intended auth gate.
- **Free5GC AMF concurrent NAS SMC validation gap during NGAP handover** — [GHSA-vrrx-58h3-prmh](https://github.com/advisories/GHSA-vrrx-58h3-prmh): handover state transitions need concurrency-safe security checks.
- **Free5GC AMF UE security capability bypass on NGAP PathSwitchRequest** — [GHSA-77x9-rf64-92gv](https://github.com/advisories/GHSA-77x9-rf64-92gv): path-switch flows must revalidate negotiated security capabilities rather than trusting stale session state.

## Why this is durable

Telecom core components are state machines. The security boundary is not just the HTTP endpoint or NGAP message parser; it is the authenticated, ordered, replay-resistant transition from one subscriber/session state to the next.

## Immediate triage

1. Patch Free5GC UDM, PCF, and AMF components in lab, private 5G, and research deployments.
2. Block management and SBI/API exposure from untrusted networks; require mTLS or equivalent service identity between core functions.
3. Hunt PCF logs for unauthenticated SM policy access and SUPI enumeration patterns.
4. Review UDM error responses for leaked subscriber identifiers, backend details, or policy internals.
5. Exercise NGAP handover and PathSwitchRequest cases in regression tests with concurrent or downgraded security-capability inputs.

## Durable controls

- Make authentication middleware explicit and fail-closed on every service-based interface route.
- Treat subscriber identifiers as sensitive data in errors, traces, and policy responses.
- Model AMF handover as an atomic state transition with replay, downgrade, and concurrency tests.
- Require invariant checks on security capabilities after every handover, path switch, or context transfer.
