# AWS Cognito Identity Pools (ID Leak → Temporary Creds)

Cognito **Identity Pools** can issue AWS temporary credentials (STS) to users. If a pool is misconfigured, an attacker can sometimes exchange a leaked Identity Pool ID for **unauthenticated AWS credentials**.

This checklist covers how to test and what to recommend.

## What you’re hunting

- Leaked **Identity Pool ID** (format like `us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)
- Misconfigured pool allowing **unauthenticated identities**
- Over-permissioned unauth role (S3 write, DynamoDB access, etc.)

## Where Identity Pool IDs leak

- Mobile apps (Android/iOS)
- JS bundles
- Public config files
- Documentation / repos

## Test steps

### 1) Determine if unauth identities are enabled
If you can obtain unauth credentials with the pool ID, the pool is likely allowing unauth identities.

### 2) Exchange for credentials
Typical flow:
- `GetId`
- `GetCredentialsForIdentity`

(Exact calls vary by SDK; use AWS SDK/CLI or reproduce calls manually.)

### 3) Identify permissions
With the temporary credentials:
- enumerate allowed actions
- attempt low-risk reads first
- test for write paths (S3 put, log injection, etc.)

## Impact patterns

- Write access to production buckets
- Reading internal configuration
- Access to other AWS services beyond intended scope

## Recommendations (defense)

- Disable unauth identities unless strictly required.
- Scope unauth role to **least privilege**.
- Use resource-level constraints:
  - prefix scoping
  - per-identity isolation (e.g., claims-based conditions)
- Implement server-side ownership checks (don’t rely on client-side object keys).

## Source / inspiration

- Inspired by public write-ups where a leaked Cognito Identity Pool ID yielded unauth AWS creds and real production impact.
