# DNS Enumeration

## Summary

Use this skill to expand a target's external surface through DNS records, subdomain discovery, and resolver-based validation.

## Use when

- scope is domain-based
- you need more hosts before port or application testing
- certificate data, MX records, or CNAME chains may reveal hidden assets

## Inputs

- root domain or list of root domains
- scope exclusions
- optional wordlist for active bruteforce
- optional resolver list for high-volume tooling

## Recommended tooling

- `dig` for direct record lookups and validation
- `subfinder` or `amass` for passive collection
- `puredns`, `massdns`, or `gobuster` for active expansion when allowed

## Core workflow

1. Collect passive subdomains from public sources.
2. Validate discovered names and normalize duplicates.
3. Inspect A, AAAA, CNAME, MX, TXT, NS, and SRV records.
4. Check for takeover candidates, external dependencies, and forgotten environments.
5. Escalate interesting hosts into service discovery.

## Command patterns

```bash
# Baseline records
dig example.com A +short
dig example.com AAAA +short
dig example.com MX +short
dig example.com TXT +short
dig example.com NS +short

# Passive discovery
subfinder -d example.com -silent
amass enum -passive -d example.com

# Validate and resolve
cat subdomains.txt | while read sub; do
  printf "%s -> " "$sub"
  dig +short "$sub"
done

# Active expansion when scope allows it
gobuster dns -d example.com -w wordlist.txt -t 50
puredns bruteforce wordlist.txt example.com -r resolvers.txt
```

## What to capture

- interesting names such as `admin`, `vpn`, `stage`, `dev`, `api`, and `sso`
- CNAMEs pointing to third-party platforms with weak ownership signals
- TXT records that expose vendors, SaaS usage, or verification history
- NS and MX records that reveal infrastructure providers
- failed and successful AXFR attempts when explicitly allowed

## Output hand-off

Pass confirmed hosts into [Nmap Scanning](nmap-scanning.md) or application-specific testing. Keep a single normalized inventory with hostname, record type, resolved IP, and notes.

## Safety

- keep active bruteforce inside engagement limits
- do not treat wildcard hits as confirmed assets without validation
- avoid long-running resolver floods on small or fragile targets
