# free5GC NRF NF-registration poisoning via unvalidated NF Profile endpoints, operator validation

**Date reviewed:** 2026-08-28 (updated 2026-08-31: added Boundary 2, the AUSF SUPI-keyed auth-context overwrite)
**Advisory:** [GHSA-x8mj-6p3q-g5pp / CVE-2026-55068](https://github.com/advisories/GHSA-x8mj-6p3q-g5pp), critical; [GHSA-334q-h5g3-fpxv / CVE-2026-55784](https://github.com/advisories/GHSA-334q-h5g3-fpxv), high (CVSS 7.5)
**Affected:** free5GC NRF `nnrf-nfm` `RegisterNFInstance` (`PUT /nnrf-nfm/v1/nf-instances/{nfInstanceID}`); free5GC AUSF `ue-authentications` context pool
**Boundary class:** NF-service-registry trust boundary, unvalidated service-endpoint fields let a registrant poison the discovery cache that other core NFs consult for control-plane routing; and a keyed in-memory state pool, a `sync.Map` keyed by SUPI only lets concurrent requests for the same subscriber overwrite live authentication state.

## Boundary 1, NRF NF-registration poisoning via unvalidated NF Profile endpoints

free5GC NRF's `RegisterNFInstance` handler stores the full NF profile body **without validating any field** against 3GPP TS 29.510. The advisory's fuzzing found all 17 tested constraint violations accepted with HTTP 200/201:

- `nfInstanceId` accepts non-UUID strings (UUID v4 is required by §6.1.6.2.2).
- `nfStatus` accepts values outside the `{REGISTERED, SUSPENDED, UNDISCOVERABLE}` enum.
- `heartBeatTimer` accepts out-of-range values (0, 99999).
- `nfProfile` accepted as `null` (a mandatory field).
- **`nfServices.ipEndPoints` entries are stored with no IP-address validation**, arbitrary attacker-controlled addresses (`10.0.0.99`) register as legitimate NF service endpoints.

Profiles land in MongoDB's `NfProfile` collection, which has **no JSON schema validator**, and are advertised via `NFDiscover`. Legitimate NFs (SMF, UDF, etc.) query NRF for peer instances and route control-plane SBI traffic to whatever `ipEndPoints` the registry returned.

Attack chain (when OAuth/SBI auth is enforced on the *consumers*, but NRF's registration path itself is reachable):

1. A compromised or attacker-controlled NF registers a fake AMF (or any NF type) with `nfServices.ipEndPoints` pointing to the attacker's `10.0.0.99:7777`.
2. NRF stores the profile and advertises it through `NFDiscover`.
3. A SMF querying NRF for AMF instances receives the poisoned profile and initiates NAS/NGAP or SBI signaling toward the attacker endpoint.
4. Consequences: control-plane signaling interception, OAuth2 credential harvest (if tokens are presented to the fake NF), and subscriber DoS (the real AMF is shadowed).

The durable pattern: **a registry/lookup service that other components trust for peer discovery, where the registration input is unvalidated, is a poisoning target even when the consumers are properly authenticated.** The security failure is not the SBI transport, it's the *data-plane integrity* of the registry.

## Boundary 2, AUSF SUPI-keyed auth-context overwrite via concurrent ue-authentications (GHSA-334q-h5g3-fpxv / CVE-2026-55784)

free5GC AUSF stores per-subscriber authentication state in a global `sync.Map` (`UePool` in `internal/context/context.go`) **keyed only by SUPI**. Every incoming `POST /nausf-auth/v1/ue-authentications` calls `NewAusfUeContext(supi)` and `AddAusfUeContextToPool`, which does an **unconditional `Store(supi, ctx)`**, replacing any in-flight authentication context for that SUPI. There is no `LoadOrStore` guard, no in-progress rejection, no per-SUPI rate limit, and the EAP session URL is derived from the SUPI/SUCI path itself, so all concurrent attempts for one subscriber share the same logical session.

An attacker who can reach the AUSF SBI/N12 interface sends concurrent ue-authentication requests for the same target SUPI. Each accepted request overwrites the previous context; a valid EAP-AKA' response for an earlier challenge is then verified against the latest context, whose `K_aut`/`XRES`/`EapID` no longer match the original challenge. Result: **targeted authentication DoS for that SUPI while the flood is maintained**. Confirmed on `ausf` v1.4.4 and main (as of June 2026).

The durable pattern: **a keyed in-memory state pool where the key is an attacker-controllable identifier (SUPI, session ID, tenant ID) and the write is unconditional `Store` is a state-clobber target.** The `sync.Map` makes the *map operations* thread-safe, but says nothing about *which procedure owns the state*. Any service that stores per-entity state keyed by an entity-supplied or entity-identifiable key, without a per-session nonce or an in-progress guard, is vulnerable to the same overwrite: one concurrent write per key destroys all in-flight state for that key.

## Replayable validation (lab only)

Preconditions: a lab free5GC deployment (NRF + at least one consuming NF, e.g. SMF), SBI/OAuth enabled as in production, an authorized lab endpoint to act as the fake NF, and a network recorder on the fake-NF listener. Do not poison a production NRF, do not target real subscribers, and do not harvest real OAuth tokens, capture only that a request *arrived* at your listener with the expected SBI shape.

1. **Enumerate the accepted fields.** Register a test NF instance with a valid UUID, then repeat the registration with each violation class (non-UUID ID, out-of-enum status, `heartBeatTimer=0`, `null` profile) and record HTTP status + stored document. The positive is 200/201 plus the malformed value persisted.
2. **Register the fake service endpoint.** Register a second (fake) NF instance of the same type as a real consumer target (e.g. an AMF if the lab SMF discovers AMFs) with `nfServices.ipEndPoints` pointing at your lab listener's IP:port. Keep every other field valid so the profile is indistinguishable from a legitimate one.
3. **Trigger discovery.** Cause the lab SMF (or equivalent consumer) to perform NF discovery for that type, e.g. via a lab UE attach or a direct `GET /nnrf-nrf/v1/nf-instances?...` as a permitted consumer. Confirm the poisoned instance appears in the response.
4. **Observe routing.** Monitor your listener for an SBI/NGAP/NAS connection attempt from the consumer. The positive is that the consumer contacted the attacker endpoint because the registry returned it. Record the request line, source, and SBI path, redact all tokens and subscriber identifiers.
5. **Negative control.** Re-run with a valid, in-lab endpoint as the fake NF and confirm the consumer reaches the lab endpoint instead; this proves the differential is the registry data, not the consumer's own validation.
6. **AUSF state-clobber (Boundary 2).** In the same lab, as a permitted AUSF consumer, start a real `POST /nausf-auth/v1/ue-authentications` for a synthetic lab SUPI, then immediately send a second (or small flood of) requests for the *same* SUPI and observe: every one is accepted (no in-progress rejection) and the lab subscriber's subsequent EAP-AKA' response fails verification against the overwritten context. The positive evidence is that N concurrent requests all returned 200/201 for one SUPI and the in-flight procedure's state no longer matches its challenge. Use synthetic lab subscribers only.

Stop at "consumer connected to the attacker-registered endpoint" (Boundary 1) and "concurrent same-SUPI ue-authentications all accepted and the in-flight procedure corrupted" (Boundary 2). Do not relay, modify, or respond to signaling as a real NF; do not extract real OAuth tokens or SUPIs; do not hold the poisoned profile longer than the lab window; do not target real subscribers with the flood.

## Recon heuristics

- **Map the discovery trust graph.** In any core/network system, list which services resolve peers from a shared registry (NRF, HSS/UDM, DNS-SD, service mesh, K8s service discovery, mDNS). For each registry, check whether registration input is schema-validated and whether an attacker-reachable write path exists.
- **Endpoint fields are the high-value target.** UUID/enum/range validation gaps are interesting, but the `ipEndPoints`/URL/callback field is what converts a registry entry into traffic redirection. Test endpoint fields with a lab listener even when the rest of the profile looks sane.
- **Schema-less stores amplify it.** If the registry persists to a document store without schema validation (Mongo `NfProfile` here), even fields the API "should" validate may be accepted. Capture the stored document as evidence, not just the API response.
- **Consumer-side hardening is a separate finding.** If consumers also fail to re-validate registry data (e.g. accept any IP, skip mutual auth on the redirected target), that's a second, independent finding, report it separately.
- **Hunt keyed state pools.** In any stateful service, grep for `sync.Map`/`map[Key]*State` where the key is an entity identifier (SUPI, tenant, session) and the write path is `Store`/direct assignment rather than `LoadOrStore`. Two concurrent requests for the same key is the test: does the second one reject, queue, or silently clobber? The EAP-AKA' case shows clobbering turns a race into a targeted DoS without any crash.

## Safe boundaries

- Authorized lab free5GC deployment only; SBI/OAuth enabled to mirror production so the result is meaningful.
- Attacker endpoint is a lab listener; evidence is "request arrived," never a captured token or subscriber identifier.
- PoC profiles are removed from the NRF after the test; no real UE traffic is redirected.
- Report the exact `nfServices.ipEndPoints` value, the discovery response showing the poisoned entry, and the consumer's connection to the lab endpoint.

## Sources

- [GitHub Advisory Database: free5GC GHSA-x8mj-6p3q-g5pp / CVE-2026-55068](https://github.com/advisories/GHSA-x8mj-6p3q-g5pp)
- [GitHub Advisory Database: free5GC GHSA-334q-h5g3-fpxv / CVE-2026-55784](https://github.com/advisories/GHSA-334q-h5g3-fpxv)
