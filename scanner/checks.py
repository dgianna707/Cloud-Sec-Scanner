import httpx

from scanner.models import Finding, ScanResult

# Important Headers for basic web security
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
]


def fetch(url: str) -> httpx.Response:
    """
    Sends a GET request to the target URL and returns the HTTP response.
    follow_redirects=True means we'll follow 301/302 redirects automatically.
    """
    resp = httpx.get(url, follow_redirects=True, timeout=10.0)
    return resp


def check_https(url: str) -> list[Finding]:
    """
    Checks whether the URL is using HTTPS.
    If not, we treat that as a critical issue.
    """
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


def check_security_headers(response: httpx.Response) -> list[Finding]:
    """
    Checks if important security headers are present in the HTTP response.
    Missing ones are marked as HIGH severity.
    """
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


def calculate_overall_risk(findings: list[Finding]) -> str:
    """
    Derives a single overall risk label based on the highest severity finding.
    """
    if any(f.severity == "CRITICAL" for f in findings):
        return "CRITICAL"
    if any(f.severity == "HIGH" for f in findings):
        return "HIGH"
    if any(f.severity == "MEDIUM" for f in findings):
        return "MEDIUM"
    if any(f.severity == "LOW" for f in findings):
        return "LOW"
    return "NONE"


def run_all_checks(url: str, env: str) -> ScanResult:
    """
    Main orchestration function:
    - Fetches the URL
    - Runs all individual checks
    - Bundles them into a ScanResult
    """
    # 1) Hit the URL once and reuse the response
    response = fetch(url)

    all_findings: list[Finding] = []

    # 2) HTTPS check (uses just the URL)
    all_findings.extend(check_https(url))

    # 3) Security header checks (uses the response)
    all_findings.extend(check_security_headers(response))

    # Here is where I can add more checks for later use

    overall = calculate_overall_risk(all_findings)

    return ScanResult(target=url, findings=all_findings, overall_risk=overall)
