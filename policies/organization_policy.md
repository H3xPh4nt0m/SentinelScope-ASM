# Organization Security Policy

## Organization
Name: Example Organization

## Authorized Scope

### Domains
- example.com
- *.example.com

### IP Ranges
- 203.0.113.0/24
- 192.168.245.0/24

## Allowed Tools
- amass
- subfinder
- dnsx
- nmap
- naabu
- httpx
- webanalyze
- whatweb
- nuclei
- zap
- openvas
- katana
- waybackurls
- gau
- dalfox
- subzy
- puredns
- waymore
- ffuf
- playwright

## Allowed Operations
- subdomain_discovery
- dns_enumeration
- port_scan
- service_detection
- web_probe
- vulnerability_scan
- tech_detection
- passive_recon
- web_crawl
- url_discovery
- xss_scan
- subdomain_takeover
- site_screenshot
- directory_scan

## Restricted Operations
- intrusive_scan
- brute_force
- destructive_test
- denial_of_service_test

## Production Rules
- Production assets require non-intrusive scans only.
- Any intrusive scan requires explicit approval.

## Vulnerability Scanning
- Allowed severities: low, medium, high, critical

## LLM Rules
- LLM may recommend actions.
- LLM may execute only approved operations.
- LLM must never operate outside authorized scope.
- LLM must never modify the policy.
- LLM must never bypass ACL.
- LLM must not execute arbitrary shell commands.

## Data Access
- Security Analysts may access security findings of their organization.
- Sensitive credentials must never be exposed through the LLM.
