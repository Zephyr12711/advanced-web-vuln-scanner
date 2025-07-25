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
