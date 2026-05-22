# GitHub Actions static-analysis recon

Source: [Trail of Bits — We hardened zizmor's GitHub Actions static analyzer](https://blog.trailofbits.com/2026/05/22/we-hardened-zizmors-github-actions-static-analyzer/), published 2026-05-22.

GitHub Actions workflows are high-value recon artifacts: they expose trust boundaries, secret paths, deploy identities, and places where untrusted pull-request or issue input can cross into privileged execution. The durable operator lesson from Trail of Bits' zizmor work is the corpus method: collect real workflow files, run a CI-aware static analyzer, triage parser/evaluator gaps, then manually validate only the findings that connect untrusted input to sensitive sinks.

!!! warning "Authorized testing only"
    Use this playbook for owned organizations, public open-source research, or engagements where repository and CI review is in scope. Do not attempt to trigger workflows, access secrets, or modify repositories without explicit authorization.

## When to use this playbook

Use it during recon when a target organization exposes GitHub repositories, Actions workflows, reusable workflows, or third-party Actions that may bridge into deployment credentials.

High-signal conditions:

- Public repositories include `.github/workflows/*.yml` or `.yaml` files.
- Workflows use `pull_request_target`, `workflow_run`, `repository_dispatch`, `issue_comment`, or label/comment-triggered automation.
- Jobs combine untrusted checkout, scripts, or matrix values with `secrets`, cloud login actions, package publishing, or deploy steps.
- Reusable workflows are called across repositories with inherited secrets.
- YAML anchors or aliases hide reused `uses:`, `run:`, `permissions:`, or `env:` blocks from quick manual review.

## Corpus-first workflow

1. **Build the workflow corpus.** Gather every scoped workflow file before judging individual repositories. Preserve repository, path, default branch, and commit SHA so findings can be reproduced.
2. **Run a CI-aware analyzer.** Use `zizmor` or an equivalent GitHub Actions analyzer to catch known dangerous patterns, especially `pull_request_target`, unpinned Actions, broad token permissions, template injection, and secret exposure paths.
3. **Normalize YAML before manual review.** Expand anchors and aliases mentally or with a parser-aware view. Anchors can reuse pinned Actions safely, but they can also move dangerous `run:` or `env:` values away from the sink that consumes them.
4. **Triage analyzer failures as recon signals.** Parser crashes or rejected valid workflows are not automatic vulnerabilities, but they mark complex files worth manual review because unsupported syntax can hide risky paths from tooling.
5. **Trace source to sink.** For each finding, identify the untrusted input source, the privileged context, and the sensitive sink. Do not report generic lint issues unless the chain reaches secrets, deployment identity, package publishing, or privileged repository writes.
6. **Validate with the smallest proof.** Prefer static proof, dry-run reproduction, or a maintainer-approved test branch. Do not exfiltrate secrets; prove that a controlled value could flow to the sink.

## Collection patterns

For a scoped organization or repository list, collect workflows with the GitHub CLI:

```bash
# One repository
repo=OWNER/REPO
gh api "repos/$repo/contents/.github/workflows" \
  --jq '.[] | select(.type=="file") | .download_url' \
| while read -r url; do
    curl -fsS "$url" -o "workflows/${repo//\//__}__$(basename "$url")"
  done
```

For broad public research, use a GitHub code search or BigQuery-derived seed list to select repositories first, then download only workflow files that are in scope. Keep the corpus immutable for the run.

## Analyzer pass

Run `zizmor` against local workflow files and save machine-readable output for triage:

```bash
zizmor --format json workflows/ > zizmor-findings.json
jq -r '.findings[]? | [.severity, .ident, .location.path, .location.line] | @tsv' zizmor-findings.json \
  | sort -u
```

If a workflow fails to parse, capture the file and syntax pattern. Trail of Bits found that real-world constructs such as YAML anchors, aliased `run:` values, duplicate anchors, `if: 0`, `timeout-minutes: 0.5`, and `secrets: inherit` can expose analyzer blind spots. Treat those as prompts for manual review, not as standalone issues.

## Manual review checklist

Focus on exploit-path questions:

- Can attacker-controlled PR code run in a context that has write-token or secrets access?
- Does `pull_request_target` check out the attacker's head ref before running scripts, build tools, package managers, or tests?
- Can issue comments, labels, branch names, workflow inputs, matrix values, or commit metadata reach `run:` without safe quoting?
- Are `secrets: inherit`, environment secrets, cloud OIDC roles, package publish tokens, or deploy keys available to jobs influenced by external contributors?
- Do reusable workflows widen permissions or secrets compared with the caller repository's apparent policy?
- Are Actions pinned by commit SHA, or can an attacker influence a tag, local path Action, or third-party Action boundary?
- Do YAML anchors/aliases hide a risky `run:`, `uses:`, `permissions:`, or `env:` block that appears benign where it is consumed?

## Reporting heuristic

Report only when the path is specific and replayable:

```text
Public repository workflow
  -> untrusted trigger or contributor-controlled input
  -> privileged GitHub Actions context
  -> script/action/template sink
  -> secret, token, deploy role, package publish, or repo-write impact
  -> controlled proof that stops before real secret disclosure
```

Include:

- Repository, workflow path, commit SHA, and trigger.
- Exact source and sink lines, including expanded YAML anchors or reusable workflow calls.
- Token/secret/permission boundary reached.
- Minimal safe reproduction or static evidence.
- What testing did not do, such as no workflow trigger, no secret read, or no package publish.

## Durable lesson

Static CI analysis is strongest when it starts from a corpus rather than a single interesting file. Analyzer warnings identify known risky patterns; analyzer crashes and parser gaps identify places where manual review matters. The highest-value bug-hunting output is not "this workflow is ugly" — it is a narrow chain from untrusted input to privileged CI execution or deploy identity, with evidence that stays inside the authorized boundary.
