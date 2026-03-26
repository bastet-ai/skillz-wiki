# Nmap Scanning

## Summary

Use this skill to convert reachable hosts into a service map with enough detail to drive targeted validation.

## Use when

- you already have hosts or IP ranges that are in scope
- you need open ports, banners, versions, and likely operating systems
- you want a reproducible baseline before deeper service-specific testing

## Inputs

- hostname, IP, or CIDR
- scope limits and rate constraints
- known ports or service families when available
- optional NSE scripts relevant to the target

## Recommended tooling

- `nmap` for host discovery, TCP and UDP scans, service detection, and NSE execution

## Core workflow

1. Confirm whether host discovery is allowed and useful.
2. Run the narrowest scan that answers the next question.
3. Expand to version detection and scripts only after open ports are confirmed.
4. Record banners, titles, certificates, and protocol details.
5. Hand each exposed service to a more specific skill or checklist.

## Command patterns

```bash
# Host discovery
nmap -sn 192.168.1.0/24
nmap -Pn target.example

# Port discovery
nmap -p- target.example
nmap --top-ports 1000 target.example

# Service identification
nmap -sV -O target.example
nmap -sS -sV -p 22,80,443,8443 target.example

# Focused NSE usage
nmap --script banner,http-title,http-methods -p 80,443 target.example
nmap --script ssl-cert,ssl-enum-ciphers -p 443 target.example
```

## What to capture

- host reachability assumptions such as `-Pn`
- exact ports found open
- service banners and version strings
- certificates, titles, and protocol metadata
- scripts that produced useful enumeration without crossing scope

## Output hand-off

Use the resulting port and service map to drive web testing, auth checks, protocol-specific review, or targeted exploit validation. Record the exact command line that produced each material result.

## Safety

- choose conservative timing on sensitive or rate-limited targets
- do not run brute-force or exploit-style NSE categories without explicit approval
- treat UDP scans as noisy and slow; use them only when the service question justifies it
