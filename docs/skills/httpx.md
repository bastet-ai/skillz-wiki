# HTTP Probing with httpx

## Summary

Use this skill to turn large host lists into a prioritized HTTP(S) surface with just enough metadata to decide what deserves deeper testing next.

## Use when

- you already have hostnames from DNS, ASN, certificate, or passive recon
- you need to know which assets actually answer HTTP or HTTPS
- you want to cluster likely auth flows, admin panels, APIs, and staging surfaces before manual review

## Inputs

- newline-delimited host list
- scope limits, rate constraints, and any do-not-touch hosts
- optional ports or schemes that matter for the target
- optional output path for JSONL capture

## Recommended tooling

- `httpx` from ProjectDiscovery for high-volume HTTP(S) probing and lightweight enrichment

## Core workflow

1. Start with a deduplicated host list from DNS or broader recon.
2. Probe conservatively to confirm which assets answer HTTP or HTTPS.
3. Re-run with only the metadata needed to prioritize manual follow-up.
4. Save machine-readable output so the probe can be replayed and filtered later.
5. Hand interesting URLs into client-side analysis, auth testing, and exploit-path validation.

## Command patterns

```bash
# Basic liveness probe
httpx -l hosts.txt -silent

# Enriched recon output for prioritization
httpx -l hosts.txt \
  -status-code -title -tech-detect -content-length \
  -json -o httpx.jsonl

# Probe the ports web apps commonly hide on
httpx -l hosts.txt \
  -ports 80,81,443,3000,4000,5000,8000,8080,8443 \
  -status-code -title -tech-detect

# Extract the most interesting next-step targets from saved output
jq -r 'select(.status_code == 200 or .status_code == 302 or .status_code == 401 or .status_code == 403) | .url' httpx.jsonl \
  | grep -Ei '/(login|admin|oauth|api|graphql)'
```

## What to capture

- final URL and original input host
- status code, title, and content length
- redirect destinations and scheme changes
- tech-detect hints that shape the next tool choice
- any auth, admin, API, or staging routes worth immediate follow-up

## Output hand-off

Feed interesting URLs into [Client-Side Analysis](../methodology/client-side-analysis.md), [CORS Credential Abuse](../methodology/cors-vulnerability-analysis.md), auth testing, or service-specific exploit validation. Keep the raw JSONL so later filtering does not depend on rerunning the probe.

## Safety

- keep concurrency and rate limits conservative on fragile or shared targets
- do not store bodies, screenshots, or extra response artifacts unless scope allows it
- treat tech fingerprints as hints, not proof
- do not spray custom paths or ports without a clear reason tied to scope
