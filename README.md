# Cloud Security Scanner

A cloud-aware API and web application security scanner for identifying security
misconfigurations and common vulnerabilities in internet-facing services.

## Overview
This project focuses on analyzing publicly accessible web applications and APIs
to identify security issues such as missing protections, insecure configurations,
and potential vulnerability indicators. The scanner is designed to provide clear,
structured findings with severity ratings and remediation guidance.

## Current Features
- Structured security findings with severity classification
- Modular scanner architecture
- Support for scanning cloud-deployed, internet-exposed services

## Planned Features
- HTTPS enforcement and redirect analysis
- Security header inspection
- API endpoint and input surface discovery
- Reflected input analysis (potential XSS indicators)
- Injection risk pattern detection (SQL injection indicators)
- Request forgery protection checks (CSRF token presence)
- Authentication and authorization surface analysis
- Severity-based finding aggregation
- Professional report generation (JSON / Markdown)
- Automated execution in CI environments


## Tech Stack
- Python
- httpx
- YAML
- GitHub Actions (planned)

## Disclaimer
This tool is intended for educational and defensive security testing on systems you own
or have explicit permission to test.
