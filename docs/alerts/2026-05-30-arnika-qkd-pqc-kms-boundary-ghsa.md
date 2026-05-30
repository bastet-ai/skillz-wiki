# arnika QKD/PQC/KMS protocol-boundary checks

Sources: [GHSA-rc6v-5rmx-w5mv](https://github.com/advisories/GHSA-rc6v-5rmx-w5mv) and the upstream [arnika security advisory](https://github.com/arnika-project/arnika/security/advisories/GHSA-rc6v-5rmx-w5mv), updated on 2026-05-30.

This is a narrow but durable operator pattern: key-rotation, hybrid key derivation, and KMS client trust can all look cryptographically strong while one unchecked timestamp, empty key file, or hardcoded TLS bypass collapses the boundary. Use this page as a safe validation checklist for authorized assessments of tunnel, QKD/PQC, and KMS-adjacent systems.

## Advisory signals

- **UDP key-rotation ACK replay** — arnika `<= 1.0.0` validates HMAC and packet type in `udpClient()` but does not validate `ackPkt.Timestamp`. A network-positioned attacker can replay an old ACK so the primary advances PSKs while the backup stays behind, breaking the tunnel without knowing the PSK.
- **Empty PQC key file accepted** — `PQC_PSK_FILE` is read through `os.ReadFile`, which follows symlinks, and `base64.DecodeString("")` returns an empty byte slice without error. With write access to the PQC key directory, a tester can prove the hybrid derivation silently falls back to QKD-only material while logging success.
- **KMS TLS verification disabled** — the KMS HTTP client hardcodes `InsecureSkipVerify: true`, so configured CA material is effectively dead code. A MITM-positioned tester can intercept KMS traffic with a self-signed proxy certificate.

## Operator triage

1. Identify whether arnika or similar tunnel/key-rotation components are in scope, especially deployments claiming QKD/PQC hybrid keying or external KMS integration.
2. Map the control-plane trust zones: primary, backup, UDP rotation path, KMS endpoint, key-file directory ownership, and any sidecars or init containers that can write secrets.
3. In a lab or explicitly authorized staging target, replay a previously valid ACK while suppressing current DATA packets. Expected safe result: stale ACKs fail because timestamps, rotation counters, or nonces are bound into validation.
4. Test PQC key-file handling with an empty file and, where scope permits, a symlinked path. Expected safe result: empty, missing, symlinked, world-writable, or wrong-owner key files fail closed before HKDF success is logged.
5. Place a controlled TLS interception proxy between the client and KMS endpoint using an untrusted certificate. Expected safe result: the client rejects the connection unless the certificate chains to the configured trust root and matches the intended hostname.

## Safe validation boundaries

- Do replay/desync tests only in isolated tunnels or maintenance windows; successful reproduction can break connectivity rather than yield an interactive shell.
- Use benign KMS payloads and non-production key material. The useful proof is certificate acceptance/rejection, not secret extraction.
- Prefer packet capture, structured logs, and before/after key-generation state as evidence. Do not publish live PSKs, KMS credentials, or QKD/PQC material.
- Treat “medium severity” crypto/protocol bugs as chain components: they matter most when paired with network position, local write access, weak container isolation, or shared secret volumes.

## Reporting heuristics

- State the exact precondition: network MITM, local directory write, writable secret mount, or compromised sidecar.
- Show the trust-boundary failure independently from impact: stale ACK accepted, empty PQC key accepted, or untrusted KMS certificate accepted.
- Explain the consequence in operator terms: tunnel desync, silent security downgrade from hybrid keying, or KMS endpoint impersonation.
- Recommend regression tests that bind freshness, key-file validity, parent-directory permissions, and TLS trust roots into CI or pre-release integration tests.
