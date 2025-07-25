# Zephyr Advanced Vulnerability Scanner

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Security](https://img.shields.io/badge/Security-Ethical%20Hacking-red.svg)

> Advanced Website Vulnerability Scanner for Educational and Authorized Security Testing

## Overview

Zephyr is a comprehensive, modular vulnerability scanner designed for ethical hacking education and authorized penetration testing. Built with modern async Python architecture and browser automation capabilities.

### Key Features

- **Browser-Driven Crawling** - Playwright integration for JavaScript-heavy applications
- **Multi-Vector Detection** - XSS, SQLi, SSRF, XXE, Command Injection, and more
- **Authentication Support** - Automated login handling and session management  
- **Professional Reporting** - HTML, JSON, and Markdown output formats
- **Async Performance** - Concurrent scanning with rate limiting
- **Plugin Architecture** - Extensible with AI-powered patch suggestions
- **Out-of-Band Testing** - DNS callback server for blind vulnerability detection

## Vulnerability Detection

| Vulnerability Type | Detection Method | Severity |
|-------------------|------------------|----------|
| Cross-Site Scripting (XSS) | Payload reflection analysis | High |
| SQL Injection | Error-based detection | Critical |
| Server-Side Request Forgery (SSRF) | Network callback validation | High |
| XML External Entity (XXE) | Entity expansion testing | High |
| Command Injection | System response analysis | Critical |
## Usage

### Basic Usage

1. **Create configuration file:**
2. python advanced_vuln_scanner.py --create-config
3. **Edit the config.yaml file:**
4. target: "https://your-target.com"
scan:
max_concurrency: 10
timeout: 30
templates: ["xss", "sqli", "ssrf", "xxe", "cmd_injection"]

 **Run the scanner:**
 python advanced_vuln_scanner.py

 ### Advanced Usage

#### Authenticated Scanning
Configure login credentials in `config.yaml`:
login:
url: "https://target.com/login"
credentials:
username: "your_username"
password: "your_password"
#### Custom Report Formats
report:
format: ["html", "json", "markdown"]
output_dir: "./custom_reports"

#### Enable Out-of-Band Testing

oob:
dns_server: "127.0.0.1"
port: 9999
enabled: true

### Example Scan Output

🚀 Advanced Website Vulnerability Scanner Starting...
Target: http://testphp.vulnweb.com
✓ Authentication successful
📊 Discovery Results:

Endpoints found: 15

Forms found: 3
Starting vulnerability scanning...
Scanning: 100%|████████████| 15/15 [00:30<00:00]
📋 Scan Summary:

Total vulnerabilities found: 2

Critical: 1

High: 1
Reports generated in ./reports



View help
python advanced_vuln_scanner.py --help

