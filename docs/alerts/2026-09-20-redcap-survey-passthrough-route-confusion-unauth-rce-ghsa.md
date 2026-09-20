---
title: REDCap survey-passthrough route confusion to unauthenticated RCE
---

# REDCap survey-passthrough route confusion to unauthenticated RCE

**Scope note.** This page is for authorized assessments of REDCap deployments you own or have explicit written permission to test. REDCap is a research-data platform common at academic and healthcare institutions; treat every finding as sensitive-institution context and stop at route/reachability evidence unless the engagement authorizes deeper validation.

## The advisory

- CVE-2026-90817 / [GHSA-hg88-qg2r-c8mx](https://github.com/advisories/GHSA-hg88-qg2r-c8mx) — unauthenticated RCE in REDCap **13.3.0 and higher** via the **survey passthrough routing** and **Data Import** processing logic. Per the advisory: a public survey context can be manipulated to reach an **unintended controller route**, and a crafted **file-path/stream parameter** during import handling yields arbitrary code execution. No authentication is required, but exploitation **requires knowledge of a valid public survey hash**. Primary source: [Securifera advisories](https://www.securifera.com/advisories) / [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-90817). Technical detail beyond the advisory text was not published at scan time — treat the mechanics below as the validation scaffold, not confirmed exploit steps.

## Why it's durable operator guidance

Two reusable axes, both generalizable beyond REDCap:

1. **A public artifact gating a passthrough router is an access-control layer, not a boundary.** Survey/instrument/access codes (survey hashes, invite tokens, share links, report tokens) authenticate *a context*, then the router dispatches from that context. Test whether the passthrough lets you select *which* internal controller runs behind the gate — route parameters, alternate action paths, and import/export sub-routes reachable from the public leg are the sweep targets. A valid public token never authorizes the internal route family it sits in front of.
2. **Import handlers accept file-path/stream parameters that are file sinks.** Data-import, restore, and bulk-upload features routinely take a path, stream handle, or temp-file reference from the request. Once you reach the handler (even behind a public token), enumerate every parameter the handler consumes and ask which one becomes a filesystem or deserialization sink.

## Passive recon first: the hash precondition

The advisory's precondition is a valid public survey hash. Before any active testing, the hash is a *discovery* problem, and REDCap has a known public surface: instruments deployed as surveys expose hash values in survey URLs, and search engines index them. For an authorized engagement:

```bash
# Scope-limited public-source collection (your target domain only)
# e.g. site:target.edu "surveys/" "PID=" style survey URL patterns via
# your search recon tooling of choice; record only in-scope hosts.
```

Collecting hashes from a client's own deployed survey links (or from the client's supplied test instrument) is the clean path — ask the engagement lead for a deployed public survey rather than crawling.

## Validation scaffold (authorized lab only)

Stand up a disposable REDCap in a container you own; deploy one throwaway survey instrument and note its public hash.

| Step | Input | Record | Stop condition |
| --- | --- | --- | --- |
| Baseline | Ordinary survey response flow | raw request, routed controller, action | control request behaves normally |
| Route-selection probe | Variant route/action parameters from the public survey context while holding the hash constant | dispatch decision: controller class + method reached | non-survey controller reached = route-confusion positive (route evidence only) |
| Import-parameter sweep | Ordinary import + inert path/stream shapes (`/tmp/`, sibling `../`, absolute paths) against the reached handler | parameter name, resolved path, opened sink (patched recorder) | denied sink recorder sees out-of-intended-root canary path |
| Execution claim | — | never run; only handler-reaches-file-sink evidence | RCE claim requires independent reproduction on your own lab instance |

Rules:

- Prove route confusion with **dispatch evidence** (which controller answered — response shape, error text, timing, marker endpoints), not with impact.
- Prove the file sink with a **patched recorder or synthetic marker file** inside a disposable container filesystem; never plant files in web-root or config paths on a live deployment.
- Do not claim unauthenticated RCE against a production host from route reachability alone — the advisory establishes the sink class, not your target's reachability.
- Healthcare/research context: if you reach anything beyond routing evidence on a production system, report immediately through the engagement channel and stop.

## Generalization checklist

For any platform with a public-token → internal-dispatch pattern (survey tools, form builders, public dashboards, share-link apps, payment/checkout passthroughs):

1. Enumerate every route/action the public context can name: path suffixes, `?page=`/`?action=` style selectors, alternate API families, import/export sub-routes.
2. For each reached internal handler, dump its parameter surface and classify which parameters reach file, stream, template, or deserialization sinks.
3. Diff the auth checks: what does the public gate verify (token validity only?) versus what the same handler requires from an authenticated session. Gate-valid-but-route-unauthorized is the finding.
4. Treat hash/token *predictability* as a separate finding class — if hashes are enumerable, the precondition evaporates and the whole route family is effectively unauthenticated.
