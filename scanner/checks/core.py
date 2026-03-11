import httpx
from scanner.models import Finding, ScanResult
from scanner.checks.httpscheck import check_https, fetch
from scanner.checks.headers import check_security_headers

def calculate_overall_risk(findings: list[Finding]) -> str:
    if any(f.severity == "CRITICAL" for f in findings):
        return "CRITICAL"
    if any(f.severity == "HIGH" for f in findings):
        return "HIGH"
    if any(f.severity == "MEDIUM" for f in findings):
        return "MEDIUM"
    if any(f.severity == "LOW" for f in findings):
        return "LOW"
    return "NONE"

#URL fetches once, runs all checks, all put into ScanResult, overall risk calculated
def run_all_checks(url: str, env: str) -> ScanResult:
    """
    Main orchestration function:
    - Fetches the URL
    - Runs all individual checks
    - Bundles them into a ScanResult
    """
    # 1) fetch URL once, get response
    response = fetch(url)

    all_findings: list[Finding] = []

    # 2) url to check https/http
    all_findings.extend(check_https(url))

    # 3) checks on response headers
    all_findings.extend(check_security_headers(response))

    # Here is where I can add more checks for later use

    overall = calculate_overall_risk(all_findings)

    return ScanResult(target=url, findings=all_findings, overall_risk=overall)
