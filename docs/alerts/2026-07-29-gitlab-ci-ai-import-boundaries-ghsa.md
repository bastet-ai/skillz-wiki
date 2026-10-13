---
title: GitLab CI, import, AI, and project-authorization boundaries
---

# GitLab CI, import, AI, and project-authorization boundaries

GitLab's July 29 patch release describes a reusable cluster of API/UI authorization and automation-boundary tests: user-supplied pipeline attributes selecting another user's configuration, approval rules racing a protected merge, virtual-registry requests forwarding credentials to the wrong host, import routes drifting from project policy, and AI features crossing project or tool-governance boundaries.

Primary source: [GitLab patch release 19.2.1, 19.1.3, and 19.0.5](https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-2-1-released/), with the corresponding GitHub records:

- [GHSA-94p8-87ff-w336 / CVE-2026-12436](https://github.com/advisories/GHSA-94p8-87ff-w336): Pipeline Schedule API mass assignment can modify another user's CI/CD configuration;
- [GHSA-629v-rwjx-m485 / CVE-2026-13113](https://github.com/advisories/GHSA-629v-rwjx-m485): merge-request approval-rule race can permit a protected-branch merge without required approvals;
- [GHSA-5c98-v836-vg79 / CVE-2026-16553](https://github.com/advisories/GHSA-5c98-v836-vg79): virtual-registry upstream handling can disclose credentials to an unintended host;
- [GHSA-g9g2-qc64-jgcj / CVE-2026-6336](https://github.com/advisories/GHSA-g9g2-qc64-jgcj) and [GHSA-35pc-qwv6-4858 / CVE-2026-14341](https://github.com/advisories/GHSA-35pc-qwv6-4858): project-import status/source disclosure and protected-branch configuration modification;
- [GHSA-w973-7qcg-m257 / CVE-2026-15831](https://github.com/advisories/GHSA-w973-7qcg-m257) and [GHSA-349h-ggfr-h55v / CVE-2026-15077](https://github.com/advisories/GHSA-349h-ggfr-h55v): Duo Workflow tool-governance bypass during token generation and Duo Code Review cross-project prompt-context disclosure;
- [GHSA-6fhj-cgmm-xfx6 / CVE-2026-6267](https://github.com/advisories/GHSA-6fhj-cgmm-xfx6): Developer-role access to unauthorized information through internal request handling;
- [GHSA-8jc8-cvqj-p926 / CVE-2026-4672](https://github.com/advisories/GHSA-8jc8-cvqj-p926): Guest-role access to unauthorized Pipeline Test Report API content; and
- [GHSA-45h8-qrqh-xr5v / CVE-2025-14562](https://github.com/advisories/GHSA-45h8-qrqh-xr5v): removed Developer retains a merge-request collaboration path that can commit changes.

!!! warning "Authorized validation only"
    Use a disposable self-managed GitLab instance, two or three synthetic users, canary projects, fake registry credentials, owned upstream listeners, inert pipelines, marker-only test reports, and no-op Duo tools. Never access real repositories, artifacts, CI variables, credentials, prompts, test output, confidential issues, or protected production branches.

## Boundary map

| Surface | Object or authority that must remain bound | Safe positive evidence |
| --- | --- | --- |
| pipeline schedule update | schedule owner, project, and allowed CI/CD attributes | user B changes one inert setting on user A's canary schedule |
| merge approval update/merge | current protected-branch approval snapshot | marker commit merges while the synthetic required approval is absent |
| virtual registry | configured upstream authority and credential scope | owned listener B receives a fake header intended only for listener A |
| project import APIs | project membership and import object's project scope | low/no-role user sees source marker or changes one canary branch setting |
| Duo Code Review | requesting project and authorized retrieval corpus | project A review output contains project B's unique synthetic marker |
| Duo Workflow token | administrator tool-governance policy and requested tool set | denied no-op tool receives an otherwise valid workflow token/dispatch |
| internal/test-report routes | route family, project, job, and caller role | lower-role user receives a marker field from an unauthorized canary object |
| MR collaboration | current project membership, MR authority, and commit permission | removed member's existing collaboration state still accepts an inert commit |

Test every edge as an object/role matrix. A route that returns a generic status is not data access, an AI response that invents a marker is not retrieval, token issuance is not tool execution, and a concurrent merge attempt is not an approval bypass unless the protected branch actually accepts the marker commit without the required approval state.

## Lab topology and controls

Create private projects A and B in separate disposable groups. Use Owner/Maintainer A, Developer B, Guest C, and removed-member D. Seed each project with unique non-secret markers in the specific surface under test: schedule description, import source label, protected-branch rule, test report, repository text, and Duo context document. Configure registry upstream A and owned recorder B with fake credentials that have no value outside the fixture.

For every request, preserve caller, effective role, group/project/object IDs, route family, HTTP method, submitted body keys, server-resolved owner/project, authorization decision, state before/after, and response marker. Include same-project authorized, cross-project unauthorized, nonexistent-object, swapped-parent-ID, removed-member, and fixed-version rows.

## Pipeline Schedule API mass-assignment workflow

GitLab describes an authenticated low-privilege path that, under some conditions, modifies CI/CD configuration belonging to another user through user-supplied pipeline-schedule attributes.

1. Let users A and B each create one inert schedule in project A, with pipelines disabled or reduced to a no-op marker job.
2. Capture the ordinary UI request for B editing B's own schedule. Enumerate body keys and server-returned owner/project identifiers; do not add undocumented destructive fields.
3. Replay against A's schedule while varying route ID, body ID, project ID, owner-like attributes, nested variables, and update masks one at a time. Compare omitted, `null`, duplicate, and conflicting route/body identifiers.
4. Check both response and persisted state as A. Require a harmless field or fake variable to change on A's schedule for positive evidence; status `200` alone is insufficient.
5. Repeat on 19.0.5, 19.1.3, or 19.2.1 as appropriate. The server must derive ownership/project scope from the authorized route object and reject client attempts to select protected attributes.

Report **user B-controlled schedule attributes -> server resolves user A's schedule/configuration -> one inert persisted field changes**. Do not run the schedule or place secrets in its variables.

## Approval-rule race workflow

The race advisory applies to GitLab EE and says an authenticated user can merge into a protected branch without required approvals. Prove the temporal edge without repeatedly racing a shared instance.

1. In a disposable project, protect `main`, require one synthetic approver, and create a merge request containing only a marker text change.
2. Instrument or locally delay one approval-rule operation so the interleaving is deterministic. Record rule version, approval count, target SHA, mergeability decision, and final merge SHA at each phase.
3. Exercise serial controls first: no approval must fail; valid approval must pass; rule change must invalidate or recompute the expected state.
4. Test one controlled interleaving between approval-rule update/recalculation and merge. Stop after one marker merge and reset the repository between rows.
5. On fixed versions, merge authorization must bind atomically to the current target SHA and current approval-rule snapshot.

Strong evidence is **protected branch requires approval at final state -> crafted interleaving uses stale/partial approval state -> marker commit becomes the branch tip**. A stale UI badge or transient API response without a merge is not sufficient.

## Virtual-registry credential forwarding

Treat this as an authority-and-secret-scope differential, not generic SSRF.

1. Configure a virtual registry to use owned upstream A and a unique fake Authorization marker valid nowhere.
2. Place owned recorder B at a different host, scheme, or port. It must log only method, authority, path, redirect source, and whether the fake marker header is present.
3. Exercise direct requests, upstream redirects, package metadata that refers to another authority, absolute artifact URLs, scheme-relative URLs, alternate ports, hostname case/trailing dots, and controlled DNS changes independently.
4. Record both the selected upstream and final socket authority at every hop. A request to B without a credential is destination control, not credential disclosure.
5. Fixed versions must strip scoped credentials whenever scheme, host, or port changes and must re-evaluate redirects and metadata-selected artifact URLs.

Report **registry request/metadata -> final authority changes from A to B -> A-scoped fake credential reaches B**. Never configure real registry tokens or point B at an unowned service.

## Import authorization matrix

GitLab separates two import issues: unauthenticated or unauthorized source-information visibility in import status, and Maintainer-level project import functionality modifying protected-branch configuration.

1. Seed a canary import whose source label is unique but non-sensitive. Create a protected branch with a harmless rule whose before/after state is easy to compare.
2. Test import-status routes as anonymous, Guest, Developer, Maintainer, and Owner across own project, foreign project, invalid import ID, valid import ID under a swapped project, and completed/failed/in-progress states.
3. Test import actions and related project APIs with a Maintainer using only a disposable import archive/repository. Vary project ID, namespace, import object ID, and protected-branch attributes separately.
4. Require the source marker in an unauthorized response for disclosure, or a persisted canary branch-rule change for integrity impact. Do not import production repositories or inspect real remote URLs/credentials.
5. Fixed versions must authorize both parent project and child import object, and must apply normal protected-branch authority regardless of whether configuration arrived through import or a direct API.

Keep the two findings separate: **status object to source metadata** and **import pathway to protected-branch mutation**.

## Duo project-context and tool-governance tests

### Code Review retrieval boundary

1. Put a unique marker in project B that cannot be guessed from project A's content. Ensure user B can request review in A but cannot read B.
2. Submit instruction-shaped comments, diff text, filenames, and repository content in A that ask the reviewer to retrieve or quote B. Use only inert text and do not request secrets.
3. Capture retrieved document IDs/project IDs if observable, prompt-context provenance, and final output. Require the exact B marker plus retrieval evidence; a plausible invented string is not proof.
4. Compare direct user access, review-agent service identity, public/private project combinations, fork/MR direction, and fixed versions.

The bounded result is **A-controlled review content -> Duo retrieval crosses into unauthorized project B -> exact synthetic B marker enters context/output**.

### Workflow token/tool-policy boundary

1. Configure an administrator policy that permits one no-op recorder tool and denies a second recorder tool. Both tools should increment only separate local counters.
2. Request a Duo Workflow token through the ordinary allowed flow, then vary requested tool identifiers, aliases, case, namespace, token refresh, resumed workflow state, and policy change timing.
3. Decode only synthetic lab token claims. Record requested tools, policy decision, minted scopes/capabilities, and which recorder receives dispatch.
4. A token containing an unexpected capability proves generation drift; require the denied recorder to fire before claiming policy bypass at execution.
5. Fixed versions must generate tokens from the current administrator policy and enforce the same policy again at dispatch.

Report token issuance and tool dispatch as separate edges. Never connect the fixture to shell, filesystem-write, network, cloud, deployment, or spending tools.

## Route-family and stale-membership checks

Use the Workhorse internal-request, Pipeline Test Report, and merge-request collaboration advisories as route-family and lifecycle heuristics:

1. Inventory the normal UI route and adjacent API, internal proxy, raw/download, report-summary, and background-fetch variants for one synthetic object.
2. Compare Developer, Guest, anonymous, and removed-member decisions before and after membership revocation. Bind every request to project, job/MR, and object IDs rather than testing role labels alone.
3. For test reports, seed only a fake test name and output marker. For MR collaboration, use a branch containing only a marker file and revoke membership before the final commit attempt.
4. Require marker content or a persisted commit for positive evidence. Redirects, object existence oracles, and generic metadata should be reported only at their observed level.
5. Fixed versions must enforce the current membership and object/project scope at the terminal content or mutation handler, not only in the UI or route precheck.

## Evidence and reporting

Preserve exact GitLab edition/version, feature flags, license-dependent features, deployment topology, synthetic user-role timeline, object-parent mappings, raw request bodies, redirect/final-authority data, fake credential-header presence, approval interleaving, AI retrieval provenance, token claims, tool counters, and affected-versus-fixed matrices. Redact cookies and tokens. Report the narrow crossed boundary rather than summarizing the patch release: **attribute to foreign schedule**, **stale approval to merge**, **upstream credential to new authority**, **import route to foreign/protected state**, **project content to AI retrieval scope**, **policy to workflow capability**, or **stale role to terminal action**.

## October 13 follow-up: 19.2.8 / 19.3.5 / 19.4.2 patch batch (published 2026-10-13 03:30Z)

Detailed operator writeup for the new-axis legs lives on the [Oct 13 msf-ws/regex/log-confusion page](2026-10-13-metasploit-ws-perhandler-auth-regex-validation-escape-and-log-format-confusion-ghsa.md) §3. Summary inventory for this page's audit matrix:

- **[GHSA-9hj5-r43h-h3xg / CVE-2026-97229](https://github.com/advisories/GHSA-9hj5-r43h-h3xg) (critical): unauthenticated RCE via crafted regex in CI/CD config — the regex validator itself is the vulnerability.** New primitive class for the boundary map: regex-evaluation-at-the-gate (timing/ReDoS probes on your own instance, alternate-engine syntax acceptance; never crash-fuzz shared instances).
- **[GHSA-5vgp-j37h-7wfx / CVE-2026-96893](https://github.com/advisories/GHSA-5vgp-j37h-7wfx) (high, EE): AI agent instruction-context injection → command execution attributed to other users.** Extends the Duo section: test instruction-boundary neutralization of every field entering agent conversation construction, and record **whose identity the execution lands under** — attribution confusion is its own impact class.
- **[GHSA-49c6-8ph4-9vr9 / CVE-2026-14814](https://github.com/advisories/GHSA-49c6-8ph4-9vr9) (high): raw-file cache poisoning via repository-reference validation → other users' pipelines execute crafted content, protected env var exposure.** Add a cache-key row to the matrix: does the raw-file cache key include a caller-supplied ref/specifier, and who consumes cached entries?
- **[GHSA-mv9g-3c33-88m6 / CVE-2026-100104](https://github.com/advisories/GHSA-mv9g-3c33-88m6): TOCTOU race in import URL validation → internal SSRF.** The import section's URL checks must pin resolution (validator and fetcher same resolution/authority); test dual-A records and TTL=0 rebinding on owned domains only.
- Scope-drift inventory to add to the fine-grained-PAT sweep: f8h6/CVE-2026-82632 (import beyond token namespace), fqqc/CVE-2026-78335 (project-scoped token → group integrations), hx4m/CVE-2026-14210 (project token → group labels), mqc6/CVE-2026-103549 (maintainer bypasses package protection), 4jhf/CVE-2026-16301 (Developer triggers downstream pipelines on protected branches), 2qxc/CVE-2026-81839 (scheduled-pipeline records survive project transfer into new group privileges), vrcj/CVE-2026-7767 (K8s-agent proxy redirect steals auth tokens), v4pv/CVE-2026-101168 (Pages log data leaks access tokens — sensitive-in-logs class), v9q6/CVE-2026-105458 (Duo agent-platform token bypasses governance), xw26/CVE-2026-100755 (Pages cache-key poisoning), 3wqg/CVE-2026-92528 (contributor self-approves via identity-resolution drift), 7g5q/CVE-2026-104661 (compliance-framework role cross-group pipeline execution), plus disclosure legs 3g57/v4cm/mvmh (unauth GraphQL work items, confidential/internal notes on public projects — GraphQL is its own authz plane), h447 (reporter → CI artifact reports), 7rx8 (Guest → confidential epics), p26w (public-project package downloads), f65j (rollback settings write), and ggg2/CVE-2026-92883 (high, 19.1+): authenticated **stored XSS via a specially crafted repository — improper HTML-attribute sanitization in syntax-highlighted file rendering**, executing in other users' sessions; the rendering layer is the sink, so the probe = commit marker-attribute files in a disposable repo and view the blob/highlight render as a second lab account — highlighter attribute passthrough is a standing sweep item on every code-hosting UI, not just file-content XSS).
