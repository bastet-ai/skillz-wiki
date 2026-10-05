---
title: Quay mirror-fetch and VuFind handler-termination authority boundaries
---

# Quay mirror-fetch and VuFind handler-termination authority boundaries

Two August 6 feed records expose a reusable operator pattern: an early control appears to approve or deny a request, but a later worker or controller retains more authority than that decision represents.

- Red Hat Quay repository-level mirror configuration accepts `external_reference` and can pass it to a Skopeo-backed mirror worker without the URL validation used by the organization-level mirror handlers: [CVE-2026-15927](https://access.redhat.com/security/cve/CVE-2026-15927), [Red Hat Bugzilla 2501256](https://bugzilla.redhat.com/show_bug.cgi?id=2501256), and [GHSA-9rpm-rwwc-xw43](https://github.com/advisories/GHSA-9rpm-rwwc-xw43).
- VuFind's controller-level access check can produce an access-denied response without stopping the requested controller function from executing: [CVE-2026-52466](https://vufind.org/wiki/security:cve-2026-52466) and [GHSA-4m6p-2r8v-vvqp](https://github.com/advisories/GHSA-4m6p-2r8v-vvqp).

The GitHub records were unreviewed mirrors when this page was written. Red Hat's primary record confirms the Quay repository-mirror URL-validation boundary. Treat the VuFind item as a validation seed until the exact route, affected revision, and corrected control flow are confirmed in upstream source; do not invent affected or fixed version ranges.

!!! warning "Owned peers and denied side-effect sinks only"
    Use a disposable Quay deployment, an owned no-content registry recorder, synthetic repositories, a disposable VuFind instance, synthetic users and records, and patched controller side-effect sinks. Never point mirror configuration at metadata, loopback, private production services, or an unowned host. Never create, alter, export, email, or delete real VuFind data.

## 1. Map policy parity across Quay mirror route families

Start from authenticated route metadata or the exact deployed source revision. Inventory repository- and organization-level mirror handlers independently:

| Dimension | Capture |
| --- | --- |
| caller | authenticated principal and repository/organization role |
| route | method, normalized path, handler, object scope |
| input | raw `external_reference`, parsed scheme, authority, path |
| validation | validator name, allow/deny result, resolved addresses |
| handoff | queued task type and normalized registry reference |
| worker | Skopeo argv/config or patched connector arguments |
| network | redirect hop, DNS answer, final socket peer, denied decision |

Do not assume that equivalent UI forms share equivalent server controls. Compare create and update methods, repository and organization scopes, API and UI-backed handlers, and immediate validation versus asynchronous worker execution.

A useful parity matrix is:

| Case | Repository mirror | Organization mirror | Expected invariant |
| --- | --- | --- | --- |
| ordinary owned registry | accepted | accepted | same canonical authority reaches the worker |
| malformed authority | rejected | rejected | no job queued |
| userinfo / alternate port | same policy | same policy | parser cannot hide the final authority |
| redirect to owned denied peer | denied before connect | denied before connect | every hop is revalidated |
| owned DNS name with changed answer | denied at final peer | denied at final peer | validation and connection cannot diverge |

Use only two owned listeners: an ordinary registry-shaped control and an isolated denied canary. Return no credentials, manifests, or image layers. Instrument the connector so it records the final authority tuple and refuses the socket.

A bounded positive is:

```text
repository administrator sets synthetic external_reference
  -> repository handler omits or disagrees with URL validation
  -> mirror job is queued
  -> patched worker selects the owned denied peer
  -> equivalent organization handler rejects before queueing
```

This proves route-family validation drift and worker-side outbound authority without contacting an internal service. An accepted URL alone is insufficient; preserve the queue handoff and final-peer decision.

## 2. Test the asynchronous final-peer boundary

Quay's worker handoff matters because request-time parsing, queue serialization, Skopeo normalization, DNS, redirects, and the final connection may each see a different authority. Record the value at every transition:

```text
raw API field
  -> parsed URL/registry reference
  -> validated authority and DNS set
  -> queued representation
  -> worker/Skopeo input
  -> redirect authority
  -> final DNS answer and socket peer
```

Exercise harmless canonicalization classes: hostname case and trailing dot, userinfo, explicit default ports, IPv4/IPv6 textual forms, redirects between the two owned peers, and controlled DNS answer changes. Do not test real private, link-local, loopback, or metadata addresses.

Report separate claims:

- **validator parity failure:** the repository route accepts a canary rejected by the organization route;
- **queue drift:** the queued reference differs materially from the validated reference;
- **final-peer failure:** the patched connector would select an owned peer outside the approved policy; and
- **response relay:** only if synthetic response metadata is actually returned to the caller.

Do not infer cloud credential access or internal-service reachability from missing request-time validation alone.

## 3. Verify that VuFind denial terminates dispatch

For VuFind, derive affected controllers and actions from the exact source revision or upstream patch. Do not brute-force route names. Build a route matrix with one synthetic object and patched sinks:

| Credential state | Controller policy | Response | Handler entry | Side-effect sink |
| --- | --- | --- | --- | --- |
| none | denied | access denied | must not occur | must not occur |
| authenticated wrong role | denied | access denied | must not occur | must not occur |
| intended role | allowed | normal result | occurs | recorder only |
| fixed build, wrong role | denied | access denied | must not occur | must not occur |

Place recorders at four points: `validateAccessPermission`, the selected action's first line, object resolution, and every read/export/mutation/message sink. A denial response is not proof of safety if handler execution continues after the response object is created.

Use action classes rather than destructive examples:

- read/detail rendering of a synthetic marker;
- export/download selection with a fake record ID;
- create/update/delete routed to a no-op transaction recorder;
- email, webhook, or job scheduling routed to a denied queue; and
- batch or alternate-format siblings, if present in source.

A bounded positive is:

```text
unauthorized synthetic request
  -> access validator records DENY
  -> response is marked access denied
  -> controller action entry recorder still fires
  -> patched sink receives only the synthetic object ID
  -> fixed build returns before action entry
```

This proves non-terminating authorization control flow. It does not prove disclosure or mutation unless the corresponding sink is reached with an object outside the caller's authority.

## 4. Separate response semantics from server-side effects

Preserve both the client-visible response and server-side trace. Frameworks may discard a later handler response, roll back a transaction, or suppress rendering while still performing reads, logging, queueing, or other side effects.

For each action, capture:

1. policy decision and reason;
2. response object/status created by the validator;
3. whether dispatch continues;
4. resolved synthetic object and owner;
5. transaction state;
6. denied sink invocation;
7. final client-visible status/body hash; and
8. affected-versus-fixed control-flow difference.

Use precise outcomes:

| Evidence | Supported claim |
| --- | --- |
| denial response plus action entry | authorization guard fails to terminate dispatch |
| foreign synthetic object reaches read recorder | object disclosure path, with data access denied |
| no-op mutation recorder receives foreign ID | unauthorized mutation path, without mutation |
| queue recorder receives synthetic job | unauthorized asynchronous side-effect path |
| only generic error timing differs | insufficient; investigate before reporting |

## October 5 follow-up: build-trigger config hands read-only admins a repository write token (CVE-2026-105447)

[GHSA-wr22-68gv-32xw](https://github.com/advisories/GHSA-wr22-68gv-32xw) / CVE-2026-105447: Quay's build-trigger API returns trigger configuration details — including the embedded repository **write** delegate token — to global read-only administrative users. A restricted principal reads the token from a GET response, then uses it to push arbitrary images to private repositories: read-only becomes write by way of a config endpoint that leaks the credential its own write path uses.

- **Durable rule: a config/webhook/trigger read endpoint that returns a stored secret is a write-capability disclosure, and least-privilege review usually covers the mutation verb but not the config GET.** Enumerate every endpoint that *stores then replays* credentials (build triggers, webhooks, replication/mirror config, robot accounts, OAuth client secrets) and fetch each one with the lowest-privilege principal.
- Operator check on an authorized Quay (or any registry/CI platform): authenticate as read-only, `GET` trigger/mirror/webhook configs for a synthetic repo, and record whether raw token material appears in any response body — compare against what the same principal is allowed to *do*. Token bytes in the body = escalation proven; redact the token itself from evidence, keep only the field-presence decision.
- Same sibling doctrine as the Airflow `connections/test` cross-team credential-USE oracle (Oct 2 page): separation of duties fails when read surfaces relay write credentials.

## Evidence bundle

```text
Product and exact revision/build:
Caller role and object scope:
Route family / method / handler:
Raw-to-canonical URL or request trace:
Policy decision:
Queue or dispatch continuation:
Final-peer or object identity:
Patched sink result:
Affected-build result:
Fixed-build result:
Supported claim:
Explicitly excluded stronger claims:
```

Keep registry credentials, image metadata, user records, search history, email addresses, and session material out of evidence. Hash synthetic bodies where content is unnecessary.