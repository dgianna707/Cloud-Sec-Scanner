from dataclasses import dataclass
from typing import List

@dataclass 
class Finding:
    """
    Represents a single security issue the scanner finds.
    """
    id:str # short lines of input code "NO_HTTPS"
    severity:str # "LOW", "MEDIUM", "HIGH, "CRITICAL"
    description:str # readable human desc of the issue
    evidence:str # readable input of what we saw to prove it
    remediation:str # writable how to fix it

@dataclass
class ScanResult:
    """
    Represents the overall result of scanning one target.
    """
    target: str              # URL we scanned
    findings: List[Finding]  # List of all findings
    overall_risk: str        # Summary: "LOW", "HIGH"
    