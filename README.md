# ReconMaster
ReconMaster is an advanced open-source tool for website and domain reconnaissance. It automates WHOIS lookups, DNS gathering, subdomain enumeration, SSL/TLS inspection, technology detection, and vulnerability scanning. Designed for security professionals, it simplifies website audits and OSINT collection.
## Features
## Features

- **Domain Information**: Fetch WHOIS information for the target domain.
- **DNS Records**: Retrieve DNS records for the domain.
- **Subdomain Enumeration**: Discover subdomains using subfinder.
- **HTTP Headers**: Check HTTP headers and server information.
- **SSL/TLS Information**: Perform SSL/TLS checks for the target domain.
- **Technology Stack**: Detect the CMS and web technologies using WhatWeb.
- **Publicly Available Information**: Use `theHarvester` to gather public information about the domain.
- **Web Fingerprinting**: Fingerprint the web server and applications with WhatWeb.
- **Attack Surface**: Identify exposed directories and files using Gobuster.
- **Vulnerability Scanning**: Scan for vulnerabilities (currently removed).
- 
## Installation

### Prerequisites
Make sure you have the following tools installed:
- Python 3.x
- `sublist3r`, `amass`, `theHarvester`, `whatweb`, `nmap`, `testssl.sh`, and other dependencies.

To install dependencies:
```bash
pip install -r requirements.txt

python3 web-audit-tool.py
