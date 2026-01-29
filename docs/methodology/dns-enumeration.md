# DNS Enumeration

DNS enumeration is a critical first step in reconnaissance that helps identify the full attack surface of a target organization. This page covers systematic approaches to discovering DNS records and infrastructure.

## 🎯 Objectives

- **Subdomain Discovery**: Find all subdomains within scope
- **Infrastructure Mapping**: Identify IP ranges and hosting providers
- **Technology Stack**: Discover technologies and services in use
- **Zone Transfers**: Attempt to extract complete DNS zone data
- **DNS Records Analysis**: Analyze different record types for intelligence

## 🔍 Subdomain Enumeration

### Passive Subdomain Discovery

**Certificate Transparency Logs (CT)**
```bash
# Using crt.sh
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u

# Using Subfinder (includes CT + many other sources)
subfinder -d example.com -silent

# Using Amass (passive mode)
amass enum -passive -d example.com
```

**TLS certificate issuance as a discovery signal**

CT is not just “historical subdomains” — it’s also an *early-warning feed* for newly exposed services.

- Monitor newly issued certs for your org’s domains.
- Treat cert issuance for unusual hostnames (e.g., short-lived test/stage names) as a prompt to probe.
- Correlate cert SANs ↔ resolved IPs ↔ HTTP service discovery.

(Practical note: many orgs now issue certs automatically; seeing a cert may be your first signal that a host exists.)

**Associated domain discovery (beyond your known inventory)**

Organizations often have domains registered via subsidiaries, acquisitions, regional teams, or old projects.
Ways to expand discovery:

- CT SANs that include brand/affiliate domains you didn’t have in scope notes
- WHOIS/registrar signals (where legal/authorized)
- Shared TLS/hosting indicators (cautious — avoid over-attribution)

Always validate association before acting.

_Source inspiration: ProjectDiscovery notes on TLS-based and associated-domain discovery: <https://projectdiscovery.io/blog/surfacing-the-real-attack-surface-advances-in-asset-discovery>_

**Search Engine Reconnaissance**
```bash
# Google dorking for subdomains
site:example.com -www

# Using theHarvester
theHarvester -d example.com -l 500 -b google,bing,yahoo
```

**DNS Aggregators**
```bash
# Using dnsdumpster API
curl -s "https://api.hackertarget.com/hostsearch/?q=example.com"

# Using SecurityTrails
curl -s "https://api.securitytrails.com/v1/domain/example.com/subdomains" \
  -H "APIKEY: YOUR_API_KEY" | jq -r '.subdomains[]'
```

### Active Subdomain Discovery

**Brute Force Enumeration**
```bash
# Using gobuster
gobuster dns -d example.com -w /path/to/wordlist.txt -t 50

# Using puredns with massdns
puredns bruteforce /path/to/wordlist.txt example.com

# Using ffuf
ffuf -w /path/to/wordlist.txt -u http://FUZZ.example.com -mc 200,301,302
```

**DNS Zone Walking**
```bash
# Using dnsrecon
dnsrecon -d example.com -t axfr,brt,srv,std

# Using fierce
fierce -dns example.com --subdomains /path/to/wordlist.txt
```

## 📋 DNS Record Analysis

### Essential Record Types

**A and AAAA Records**
```bash
# Basic A record lookup
dig example.com A +short

# IPv6 AAAA records
dig example.com AAAA +short

# Bulk subdomain resolution
cat subdomains.txt | while read subdomain; do
    echo "$subdomain: $(dig +short $subdomain)"
done
```

**CNAME Records**
```bash
# Find CNAME chains
dig www.example.com CNAME +short

# Identify potential subdomain takeovers
dig abandoned.example.com CNAME +short
# Look for: amazonaws.com, herokuapp.com, github.io, etc.
```

**MX Records**
```bash
# Mail server discovery
dig example.com MX +short

# Check for mail server misconfigurations
dig example.com MX | grep -E "(google|outlook|proofpoint)"
```

**TXT Records**
```bash
# SPF, DKIM, DMARC policies
dig example.com TXT +short

# Look for verification records
dig example.com TXT | grep -E "(google-site-verification|facebook-domain-verification)"
```

**NS Records**
```bash
# Identify name servers
dig example.com NS +short

# Check for DNS hosting providers
dig example.com NS | grep -E "(cloudflare|route53|godaddy)"
```

**SRV Records**
```bash
# Service discovery
dig _http._tcp.example.com SRV +short
dig _ftp._tcp.example.com SRV +short
dig _ldap._tcp.example.com SRV +short

# Microsoft AD services
dig _kerberos._tcp.dc._msdcs.example.com SRV +short
```

## 🏗️ Zone Transfer Testing

### AXFR Attempts

```bash
# Test zone transfer against all name servers
for ns in $(dig example.com NS +short); do
    echo "Testing $ns"
    dig @$ns example.com AXFR
done

# Using dnsrecon
dnsrecon -d example.com -t axfr

# Using fierce
fierce -dns example.com -range 192.168.1.0/24
```

### Zone Walking (NSEC)

```bash
# Using ldns-walk (for DNSSEC enabled domains)
ldns-walk example.com

# Manual NSEC walking
dig example.com NSEC +short
```

## 🔧 Advanced Techniques

### DNS Cache Snooping

```bash
# Check if domain is cached
dig @8.8.8.8 example.com +norecurse

# Cache poisoning detection
dig @target-dns-server random-subdomain.example.com
```

### Reverse DNS Lookups

```bash
# Single IP reverse lookup
dig -x 192.168.1.1 +short

# Bulk reverse DNS
for ip in {1..254}; do
    dig -x 192.168.1.$ip +short | grep -v "NXDOMAIN"
done

# Using prips for IP range generation
prips 192.168.1.0/24 | while read ip; do
    host $ip | grep -v "NXDOMAIN"
done
```

### DNS Wildcards Detection

```bash
# Test for wildcard responses
dig random123.example.com +short
dig nonexistent456.example.com +short

# Using dnswalk
dnswalk example.com
```

## 🛠️ Recommended Tools

### Multi-Purpose Tools

**Amass** - Comprehensive OSINT framework
```bash
# Full passive + active enumeration
amass enum -d example.com -src

# With API keys configured
amass enum -config ~/.config/amass/config.ini -d example.com
```

**Subfinder** - Fast passive subdomain discovery
```bash
# Basic usage
subfinder -d example.com -silent -o subdomains.txt

# With all sources
subfinder -d example.com -all -silent
```

**Assetfinder** - Simple subdomain finder
```bash
assetfinder --subs-only example.com
```

### Specialized Tools

**MassDNS** - High-performance DNS stub resolver
```bash
# Resolve large lists quickly
massdns -r resolvers.txt -t A -o S subdomains.txt
```

**PureDNS** - Fast domain resolver and subdomain bruteforcer
```bash
# Bruteforce with validation
puredns bruteforce wordlist.txt example.com -r resolvers.txt
```

**Shuffle DNS** - Wrapper around massdns
```bash
shuffledns -d example.com -list subdomains.txt -r resolvers.txt
```

## 📊 Analysis and Filtering

### Identifying Interesting Patterns

```bash
# Find development/staging environments
cat subdomains.txt | grep -E "(dev|test|stage|staging|qa|uat|demo)"

# Administrative interfaces
cat subdomains.txt | grep -E "(admin|panel|dashboard|manage|control)"

# API endpoints
cat subdomains.txt | grep -E "(api|rest|graphql|v1|v2|service)"

# Potential vulnerabilities
cat subdomains.txt | grep -E "(old|legacy|backup|temp|bak)"
```

### IP Range Analysis

```bash
# Group subdomains by IP
for subdomain in $(cat subdomains.txt); do
    ip=$(dig +short $subdomain | head -1)
    echo "$ip $subdomain"
done | sort

# Identify cloud providers
dig +short subdomain.example.com | while read ip; do
    whois $ip | grep -E "(OrgName|Organization)"
done
```

## ⚠️ Best Practices

### Rate Limiting and Stealth

- **Respect Rate Limits**: Use delays between requests (`--delay` flags)
- **Rotate Resolvers**: Use multiple DNS servers to distribute load
- **Monitor for Blocks**: Watch for consistent NXDOMAIN responses
- **Use Passive Sources First**: Minimize active enumeration

### Validation and Verification

```bash
# Verify subdomain resolution
cat subdomains.txt | while read sub; do
    if host $sub > /dev/null 2>&1; then
        echo $sub
    fi
done > valid_subdomains.txt

# Check for HTTP services
cat valid_subdomains.txt | while read sub; do
    if curl -s -I "http://$sub" > /dev/null 2>&1; then
        echo "HTTP: $sub"
    fi
    if curl -s -I "https://$sub" > /dev/null 2>&1; then
        echo "HTTPS: $sub"
    fi
done
```

### Scope Management

```bash
# Filter in-scope domains only
cat all_subdomains.txt | grep -E "\.(example\.com|target\.org)$" > inscope_subdomains.txt

# Remove out-of-scope domains
cat subdomains.txt | grep -v -E "\.(outofscope\.com|external\.net)$"
```

## 🔗 Integration with Other Tools

### Feeding Results to Web Scanners

```bash
# Prepare URLs for HTTP probing
cat subdomains.txt | sed 's/^/https:\/\//' > urls.txt

# Use with httpx
httpx -l subdomains.txt -o live_hosts.txt

# Integration with nuclei
nuclei -l live_hosts.txt -t /path/to/templates/
```

### Database Storage

```bash
# Simple CSV format
echo "subdomain,ip,status" > dns_results.csv
cat subdomains.txt | while read sub; do
    ip=$(dig +short $sub | head -1)
    status=$(curl -s -o /dev/null -w "%{http_code}" http://$sub)
    echo "$sub,$ip,$status" >> dns_results.csv
done
```

## 📈 Automation and Scripting

### Complete DNS Enumeration Script

```bash
#!/bin/bash
DOMAIN=$1
OUTPUT_DIR="dns_enum_$(date +%Y%m%d)"

mkdir -p $OUTPUT_DIR

echo "[+] Starting DNS enumeration for $DOMAIN"

# Passive subdomain discovery
echo "[+] Passive subdomain discovery..."
subfinder -d $DOMAIN -silent > $OUTPUT_DIR/passive_subdomains.txt
amass enum -passive -d $DOMAIN >> $OUTPUT_DIR/passive_subdomains.txt

# Active brute forcing
echo "[+] Active subdomain brute forcing..."
gobuster dns -d $DOMAIN -w /usr/share/wordlists/subdomains.txt \
    -o $OUTPUT_DIR/bruteforce_subdomains.txt

# Combine and deduplicate
cat $OUTPUT_DIR/*.txt | sort -u > $OUTPUT_DIR/all_subdomains.txt

# Resolve and validate
echo "[+] Validating subdomains..."
puredns resolve $OUTPUT_DIR/all_subdomains.txt > $OUTPUT_DIR/valid_subdomains.txt

# HTTP probing
echo "[+] HTTP probing..."
httpx -l $OUTPUT_DIR/valid_subdomains.txt -o $OUTPUT_DIR/live_hosts.txt

echo "[+] DNS enumeration complete. Results in $OUTPUT_DIR/"
```

---

*Remember: Always ensure you have proper authorization before conducting DNS enumeration against any target. Respect rate limits and be mindful of the load on DNS servers.*
