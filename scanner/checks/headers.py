import httpx
from scanner.models import Finding, ScanResult

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
]

#marks if any important security headers are missing, adds finding for each missing header
def check_security_headers(response: httpx.Response) -> list[Finding]:
    findings: list[Finding] = []
    headers = response.headers

    for header in SECURITY_HEADERS:
        if header not in headers:
            findings.append(
                Finding(
                    id=f"MISSING_{header.upper().replace('-', '_')}",
                    severity="HIGH",
                    description=f"{header} header is missing.",
                    evidence="Response headers did not include this header.",
                    remediation=f"Add a sensible {header} header to mitigate common web attacks.",
                )
            )

    return findings