import httpx
from scanner.models import Finding, ScanResult

    #requests to target URL w/ timeout follow redirects, return http response
def fetch(url: str) -> httpx.Response:
    resp = httpx.get(url, follow_redirects=True, timeout=10.0)
    return resp

#checks if URL starts w/ https, if not add finding
def check_https(url: str) -> list[Finding]:
    findings: list[Finding] = []

    if not url.startswith("https://"):
        findings.append(
            Finding(
                id="NO_HTTPS",
                severity="CRITICAL",
                description="Target URL is not using HTTPS.",
                evidence=f"URL: {url}",
                remediation=(
                    "Serve the application only over HTTPS and redirect all HTTP "
                    "requests to HTTPS. Configure TLS certificates properly."
                ),
            )
        )

    return findings