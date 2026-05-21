# CI/CD to cloud pivot chain

Source: [ProjectDiscovery — Red-Teaming Cloud Infrastructure with Neo](https://projectdiscovery.io/blog/red-teaming-cloud-infrastructure-with-neo), published 2026-05-21.

A self-hosted CI/CD server is often the shortest path from public recon to cloud impact. The durable operator lesson from ProjectDiscovery's Neo red-team lab is not the AI branding; it is the repeatable chain: internet-facing build service → admin/API access → build-agent code execution → instance metadata credentials → cloud secret stores and backups → private-subnet service validation.

!!! warning "Authorized testing only"
    Run this workflow only in an owned lab or an engagement where CI/CD, cloud resources, and private-network pivots are explicitly in scope. Stop before broad data extraction once impact is proven.

## When to use this playbook

Use it when external recon finds a self-hosted build, deployment, or automation surface such as TeamCity, Jenkins, GitLab runners, Buildkite agents, Drone, GoCD, or bespoke release tooling.

High-signal conditions:

- The service is internet-reachable for webhooks, SSO, or developer convenience.
- Version, plugin, or banner metadata is visible pre-authentication.
- The build agent runs in AWS, GCP, Azure, Kubernetes, or another privileged deployment network.
- Pipeline definitions reference production deploys, secrets, artifacts, cloud buckets, or parameter stores.
- Private services rely on subnet placement as the main access control.

## Operator chain

1. **Fingerprint the CI/CD control plane.** Capture product, version, plugins, exposed REST endpoints, login behavior, and known-CVE fit. For TeamCity, unauthenticated server metadata and version disclosure can be enough to select the right validation template.
2. **Validate initial access with the smallest proof.** A scanner result is not the finding. Prove whether the issue reaches authenticated API context, token minting, project read access, or build configuration access.
3. **Inventory build secrets.** With authorized admin/API access, review project parameters, environment variables, VCS credentials, deploy keys, webhook tokens, artifact references, and masked-secret behavior. Treat plaintext values, reversible encryption, or secret names plus target paths as evidence.
4. **Turn build execution into cloud-context discovery.** If rules permit, run a benign build step that proves agent execution context and checks cloud metadata reachability. Capture role/account identity before enumerating resources.
5. **Enumerate only what proves impact.** Prioritize identity, S3/object storage names, SSM/Secrets Manager paths, container registries, database endpoints, and private service DNS. Avoid bulk downloads unless the engagement explicitly authorizes it.
6. **Pivot through the build agent to private services.** Use the agent as the network vantage point for scoped HTTP checks, not as a general-purpose tunnel unless approved. Validate claim checks, admin endpoints, debug paths, and database error behavior.
7. **Close the loop with business impact.** A strong report connects public exposure to cloud credentials, specific sensitive stores, reachable private systems, and one or two controlled data-access proofs.

## AWS validation checklist

From an authorized build step or controlled shell on the agent, collect narrow evidence:

```bash
aws sts get-caller-identity
aws ec2 describe-instances --filters 'Name=tag:Environment,Values=prod,production' --max-results 20
aws s3 ls
aws ssm describe-parameters --max-results 10
aws secretsmanager list-secrets --max-results 10
aws rds describe-db-instances --max-records 20
```

If instance metadata is in scope, prove the exposure without printing live credentials into long-lived logs:

```bash
curl -sS --max-time 2 http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

For IMDSv2-required hosts, capture the token requirement as a boundary condition instead of trying to bypass it.

## Private-service checks

When the build agent has private-subnet reachability, validate only scoped endpoints first:

- `GET /health`, `/version`, `/metrics`, `/debug`, `/admin`, `/internal`
- Auth behavior with no token, malformed token, and a controlled valid test token
- Whether JWT claims are enforced or merely signature-checked
- Whether SQL/database errors reflect attacker-controlled claim values
- Whether debug database/query endpoints exist on the CI/CD server itself

Evidence should show the pivot path and access-control failure, not a broad dump of private data.

## Reporting heuristic

Structure the report as an exploit path, not isolated findings:

```text
Internet-exposed CI/CD service
  -> version-specific initial access / admin token
  -> build config secrets and deploy keys
  -> build-agent execution
  -> cloud role or metadata credential access
  -> S3/SSM/Secrets/RDS discovery
  -> private API access via agent network position
  -> controlled proof of customer, financial, or production-system impact
```

For each hop, include:

- Entry condition and exact scoped asset.
- Minimum request/command used to prove the hop.
- Credential or identity obtained, redacted to safe evidence.
- What the credential could access.
- Why the next hop was reachable.
- Where testing stopped and why.

## Durable lesson

CI/CD is both an identity concentrator and a network bridge. A finding that looks like "one stale TeamCity/Jenkins/GitLab issue" can become a full cloud compromise when the build agent has production IAM permissions, access to backups, secret-store read privileges, or private-subnet reachability. Red-team reports should validate that chain end to end, while staying inside the authorized data-access boundary.
