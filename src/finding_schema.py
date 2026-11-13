from dataclasses import dataclass, asdict
from typing import Optional
import json


@dataclass
class Finding:
    finding_id: str
    scanner: str
    name: str
    severity: str

    target: Optional[str] = None
    method: Optional[str] = None
    url: Optional[str] = None

    confidence: Optional[str] = None

    template_id: Optional[str] = None

    evidence: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None

    # Vulnerability identity
    cwe_id: Optional[str] = None
    wasc_id: Optional[str] = None

    def to_dict(self):
        return asdict(self)

    def to_json(self):
        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            indent=2
        )


def create_finding(
    finding_id,
    scanner,
    name,
    severity,
    target=None,
    method=None,
    url=None,
    confidence=None,
    template_id=None,
    evidence=None,
    description=None,
    category=None,
    cwe_id=None,
    wasc_id=None,
):
    return Finding(
        finding_id=finding_id,
        scanner=scanner,
        name=name,
        severity=severity,
        target=target,
        method=method,
        url=url,
        confidence=confidence,
        template_id=template_id,
        evidence=evidence,
        description=description,
        category=category,
        cwe_id=cwe_id,
        wasc_id=wasc_id,
    )


if __name__ == "__main__":

    test_finding = create_finding(
        finding_id="TEST-0001",
        scanner="test",
        name="Test Finding",
        severity="medium",
        target="http://localhost:3000",
        method="GET",
        url="http://localhost:3000/test",
        confidence="high",
        evidence="Test evidence",
        category="test",
        cwe_id="CWE-693",
        wasc_id="WASC-15",
    )

    print("Finding created successfully:")
    print()
    print(test_finding.to_json())