# Web Application Security Scanner 

An automated web application security scanner for identifying security
misconfigurations and common vulnerabilities in internet-facing services.

## Overview
This project implements a modular security scanner designed to analyze
internet-facing web applications for common misconfigurations
and vulnerability indicators.

The scanner sends HTTP requests to a target service and evaluates the
responses for security signals such as missing protections, insecure
transport configurations, and exposed application behavior. Findings are
structured with severity classifications and remediation guidance to
mirror how real security tools report risk.

The goal of this project is to better understand how application security
tools operate at the application layer while building a maintainable and
extensible scanning architecture, building to map vulnerability indicators to the OWASP TOP 10.

## Current Features
- Structured security findings with severity classification
- Modular scanner architecture
- HTTPS enforcement and redirect analysis


## Planned Features
- Security header inspection
- Infrastructure fingerprinting (CDN / reverse proxy detection)
- API endpoint and input surface discovery
- Reflected input analysis (potential XSS indicators)
- Injection risk pattern detection (SQL injection indicators)
- Request forgery protection checks (CSRF token presence)
- Authentication and authorization surface analysis
- Severity-based finding aggregation
- Professional report generation (JSON / Markdown)
- Automated execution in CI environments
- Banner grabbing using socket programming

## Tech Stack
- Python
- httpx
- YAML
- GitHub Actions (planned)

## Disclaimer
This tool is intended for educational purposes only.
