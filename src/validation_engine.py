"""
Validation + Confidence + Risk Engine
--------------------------------------

Automated Web Vulnerability Assessment Framework

Pipeline:

    ZAP + Nuclei
          ↓
    Common Finding Schema
          ↓
    Correlation Engine
          ↓
    Deduplication / Consolidation
          ↓
    Evidence-Based Validation
          ↓
    Confidence Scoring
          ↓
    Risk Scoring
          ↓
    Unified Validation Results
"""

from typing import Any, Dict, List

from zap_parser import parse_zap_results
from nuclei_parser import parse_nuclei_results
from correlation_engine_v3 import correlate_findings
from deduplication_engine import consolidate_findings


# ============================================================
# SCORE CONFIGURATION
# ============================================================

SEVERITY_SCORE = {
    "critical": 10,
    "high": 8,
    "medium": 5,
    "low": 2,
    "informational": 0,
    "info": 0,
    "unknown": 0,
}


CONFIDENCE_SCORE = {
    "high": 30,
    "medium": 20,
    "low": 10,
    "unknown": 0,
}


# ============================================================
# NORMALIZATION
# ============================================================

def normalize_text(
    value: Any,
) -> str:
    """
    Normalize text for comparison.
    """

    if value is None:
        return ""

    return str(value).strip().lower()


# ============================================================
# SAFE DICTIONARY ACCESS
# ============================================================

def safe_get(
    finding: Dict[str, Any],
    key: str,
    default: Any = None,
) -> Any:
    """
    Safely retrieve a field from a consolidated
    finding dictionary.
    """

    if not isinstance(
        finding,
        dict,
    ):
        return default

    return finding.get(
        key,
        default,
    )


# ============================================================
# EVIDENCE SCORING
# ============================================================

def calculate_evidence_score(
    finding: Dict[str, Any],
) -> int:
    """
    Calculate evidence quality.

    Maximum = 30.

    URL       = 10
    Evidence  = 10
    Method    = 5
    Finding ID / Template evidence = 5
    """

    score = 0

    urls = safe_get(
        finding,
        "urls",
        [],
    )

    evidences = safe_get(
        finding,
        "evidence",
        [],
    )

    methods = safe_get(
        finding,
        "methods",
        [],
    )

    finding_ids = safe_get(
        finding,
        "finding_ids",
        [],
    )

    if urls:
        score += 10

    if evidences:
        score += 10

    if methods:
        score += 5

    if finding_ids:
        score += 5

    return min(
        score,
        30,
    )


# ============================================================
# SCANNER CONFIDENCE
# ============================================================

def calculate_scanner_confidence(
    finding: Dict[str, Any],
) -> int:
    """
    Convert consolidated scanner confidence
    into a numeric score.
    """

    confidence = normalize_text(
        safe_get(
            finding,
            "confidence",
            "unknown",
        )
    )

    return CONFIDENCE_SCORE.get(
        confidence,
        0,
    )


# ============================================================
# CORRELATION BONUS
# ============================================================

def calculate_correlation_bonus(
    finding: Dict[str, Any],
) -> int:
    """
    Add confidence bonus according to
    the correlation/consolidation type.

    DUPLICATE = +25
    RELATED   = +15
    UNIQUE    = +0
    """

    relationship_type = normalize_text(
        safe_get(
            finding,
            "type",
            "unique",
        )
    )

    if relationship_type == "duplicate":
        return 25

    if relationship_type == "related":
        return 15

    return 0


# ============================================================
# VALIDATION STATUS
# ============================================================

def determine_validation_status(
    evidence_score: int,
    confidence_score: int,
) -> str:
    """
    Determine evidence-based validation status.

    IMPORTANT:
    This represents evidence support, not exploit confirmation.
    """

    total_score = (
        evidence_score
        +
        confidence_score
    )

    if total_score >= 50:
        return "VALIDATED"

    if total_score >= 20:
        return "PARTIALLY_VALIDATED"

    return "UNVERIFIED"


# ============================================================
# FINAL CONFIDENCE SCORE
# ============================================================

def calculate_confidence_score(
    evidence_score: int,
    scanner_confidence: int,
    correlation_bonus: int = 0,
) -> int:
    """
    Calculate final confidence score.

    Maximum theoretical raw score:

        Evidence       = 30
        Scanner        = 30
        Correlation    = 25

        Total           = 85

    Normalized to 0-100.
    """

    raw_score = (
        evidence_score
        +
        scanner_confidence
        +
        correlation_bonus
    )

    max_score = 85

    if raw_score <= 0:
        return 0

    normalized_score = (
        raw_score
        /
        max_score
    ) * 100

    return int(
        round(
            min(
                normalized_score,
                100,
            )
        )
    )


# ============================================================
# CONFIDENCE LABEL
# ============================================================

def get_confidence_label(
    confidence_score: int,
) -> str:
    """
    Convert confidence score into label.
    """

    if confidence_score >= 75:
        return "HIGH"

    if confidence_score >= 50:
        return "MEDIUM"

    if confidence_score >= 25:
        return "LOW"

    return "VERY_LOW"


# ============================================================
# RISK SCORE
# ============================================================

def calculate_risk_score(
    severity: str,
    confidence_score: int,
) -> float:
    """
    Calculate risk score.

    Maximum = 10.0.

    Informational findings are explicitly excluded
    from vulnerability risk scoring.
    """

    normalized_severity = normalize_text(
        severity
    )

    # --------------------------------------------------------
    # INFORMATIONAL = ZERO SECURITY RISK
    # --------------------------------------------------------

    if normalized_severity in {
        "informational",
        "info",
    }:
        return 0.0

    severity_value = SEVERITY_SCORE.get(
        normalized_severity,
        0,
    )

    if severity_value == 0:
        return 0.0

    confidence_factor = (
        confidence_score
        /
        100.0
    )

    risk = (
        severity_value
        *
        confidence_factor
    )

    return round(
        min(
            risk,
            10.0,
        ),
        2,
    )


# ============================================================
# RISK LEVEL
# ============================================================

def get_risk_level(
    severity: str,
    risk_score: float,
) -> str:
    """
    Convert risk score to risk category.
    """

    normalized_severity = normalize_text(
        severity
    )

    # --------------------------------------------------------
    # INFORMATIONAL
    # --------------------------------------------------------

    if normalized_severity in {
        "informational",
        "info",
    }:
        return "INFORMATIONAL"

    # --------------------------------------------------------
    # RISK LEVELS
    # --------------------------------------------------------

    if risk_score >= 8:
        return "CRITICAL"

    if risk_score >= 5:
        return "HIGH"

    if risk_score >= 3:
        return "MEDIUM"

    if risk_score > 0:
        return "LOW"

    return "INFORMATIONAL"


# ============================================================
# VALIDATE CONSOLIDATED FINDING
# ============================================================

def validate_finding(
    finding: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Validate one consolidated finding.

    The input is the dictionary returned by
    consolidate_findings().
    """

    # --------------------------------------------------------
    # BASIC INFORMATION
    # --------------------------------------------------------

    group_id = safe_get(
        finding,
        "group_id",
        "UNKNOWN",
    )

    finding_name = safe_get(
        finding,
        "primary_name",
        "Unknown Finding",
    )

    severity = safe_get(
        finding,
        "severity",
        "unknown",
    )

    confidence = safe_get(
        finding,
        "confidence",
        "unknown",
    )

    finding_type = safe_get(
        finding,
        "type",
        "UNIQUE",
    )

    scanners = safe_get(
        finding,
        "scanners",
        [],
    )

    finding_ids = safe_get(
        finding,
        "finding_ids",
        [],
    )

    urls = safe_get(
        finding,
        "urls",
        [],
    )

    evidences = safe_get(
        finding,
        "evidence",
        [],
    )

    methods = safe_get(
        finding,
        "methods",
        [],
    )

    # --------------------------------------------------------
    # SCORES
    # --------------------------------------------------------

    evidence_score = (
        calculate_evidence_score(
            finding
        )
    )

    scanner_confidence = (
        calculate_scanner_confidence(
            finding
        )
    )

    correlation_bonus = (
        calculate_correlation_bonus(
            finding
        )
    )

    confidence_score = (
        calculate_confidence_score(
            evidence_score,
            scanner_confidence,
            correlation_bonus,
        )
    )

    confidence_label = (
        get_confidence_label(
            confidence_score
        )
    )

    validation_status = (
        determine_validation_status(
            evidence_score,
            confidence_score,
        )
    )

    risk_score = calculate_risk_score(
        severity,
        confidence_score,
    )

    risk_level = get_risk_level(
        severity,
        risk_score,
    )

    # --------------------------------------------------------
    # RETURN VALIDATED RECORD
    # --------------------------------------------------------

    return {
        "group_id": group_id,

        "finding": finding_name,

        "scanner": ", ".join(
            scanners
        ) if scanners else "unknown",

        "severity": severity,

        "type": finding_type,

        "finding_count": len(
            finding_ids
        ),

        "validation": validation_status,

        "evidence_score": evidence_score,

        "scanner_confidence": scanner_confidence,

        "correlation_bonus": correlation_bonus,

        "confidence_score": confidence_score,

        "confidence_label": confidence_label,

        "risk_score": risk_score,

        "risk_level": risk_level,

        "urls": urls,

        "methods": methods,

        "evidence": evidences,
    }


# ============================================================
# MAIN VALIDATION PIPELINE
# ============================================================

def run_validation_pipeline() -> List[Dict[str, Any]]:
    """
    Execute the complete validation pipeline.
    """

    print(
        "=" * 70
    )

    print(
        "VALIDATION + CONFIDENCE + RISK ENGINE"
    )

    print(
        "=" * 70
    )

    # ========================================================
    # LOAD ZAP
    # ========================================================

    zap_findings = (
        parse_zap_results()
    )

    # ========================================================
    # LOAD NUCLEI
    # ========================================================

    nuclei_findings = (
        parse_nuclei_results()
    )

    print(
        f"ZAP findings loaded: "
        f"{len(zap_findings)}"
    )

    print(
        f"Nuclei findings loaded: "
        f"{len(nuclei_findings)}"
    )

    # ========================================================
    # COMBINE
    # ========================================================

    all_findings = (
        zap_findings
        +
        nuclei_findings
    )

    print(
        f"Total raw findings: "
        f"{len(all_findings)}"
    )

    # ========================================================
    # CORRELATION
    # ========================================================

    print()

    print(
        "Running correlation..."
    )

    correlations = (
        correlate_findings(
            all_findings
        )
    )

    print(
        f"Correlations found: "
        f"{len(correlations)}"
    )

    # ========================================================
    # DEDUPLICATION
    # ========================================================

    print()

    print(
        "Running deduplication..."
    )

    consolidated_findings = (
        consolidate_findings(
            all_findings,
            correlations,
        )
    )

    print(
        f"Consolidated findings: "
        f"{len(consolidated_findings)}"
    )

    # ========================================================
    # VALIDATION
    # ========================================================

    print()

    print(
        "Running evidence-based validation..."
    )

    results = []

    for finding in consolidated_findings:

        result = validate_finding(
            finding
        )

        results.append(
            result
        )

    return results


# ============================================================
# SUMMARY
# ============================================================

def print_summary(
    results: List[Dict[str, Any]],
) -> None:
    """
    Print validation summary.
    """

    total = len(
        results
    )

    validated = sum(
        1
        for result in results
        if result[
            "validation"
        ] == "VALIDATED"
    )

    partially_validated = sum(
        1
        for result in results
        if result[
            "validation"
        ] == "PARTIALLY_VALIDATED"
    )

    unverified = sum(
        1
        for result in results
        if result[
            "validation"
        ] == "UNVERIFIED"
    )

    high_critical = sum(
        1
        for result in results
        if result[
            "risk_level"
        ] in {
            "HIGH",
            "CRITICAL",
        }
    )

    medium = sum(
        1
        for result in results
        if result[
            "risk_level"
        ] == "MEDIUM"
    )

    low = sum(
        1
        for result in results
        if result[
            "risk_level"
        ] == "LOW"
    )

    informational = sum(
        1
        for result in results
        if result[
            "risk_level"
        ] == "INFORMATIONAL"
    )

    print()

    print(
        "=" * 70
    )

    print(
        "VALIDATION / CONFIDENCE / RISK SUMMARY"
    )

    print(
        "=" * 70
    )

    print(
        f"Total consolidated findings: "
        f"{total}"
    )

    print()

    print(
        f"Validated: "
        f"{validated}"
    )

    print(
        f"Partially validated: "
        f"{partially_validated}"
    )

    print(
        f"Unverified: "
        f"{unverified}"
    )

    print()

    print(
        f"High/Critical risk: "
        f"{high_critical}"
    )

    print(
        f"Medium risk: "
        f"{medium}"
    )

    print(
        f"Low risk: "
        f"{low}"
    )

    print(
        f"Informational: "
        f"{informational}"
    )


# ============================================================
# DETAILED RESULTS
# ============================================================

def print_detailed_results(
    results: List[Dict[str, Any]],
) -> None:
    """
    Print detailed validation results.
    """

    print()

    print(
        "=" * 70
    )

    print(
        "VALIDATED FINDINGS"
    )

    print(
        "=" * 70
    )

    for result in results:

        print(
            "-" * 70
        )

        print(
            f"Group ID: "
            f"{result['group_id']}"
        )

        print(
            f"Finding: "
            f"{result['finding']}"
        )

        print(
            f"Scanner(s): "
            f"{result['scanner']}"
        )

        print(
            f"Severity: "
            f"{result['severity']}"
        )

        print(
            f"Type: "
            f"{result['type']}"
        )

        print(
            f"Validation: "
            f"{result['validation']}"
        )

        print(
            f"Evidence Score: "
            f"{result['evidence_score']}/30"
        )

        print(
            f"Confidence: "
            f"{result['confidence_label']} "
            f"({result['confidence_score']}/100)"
        )

        print(
            f"Risk: "
            f"{result['risk_level']} "
            f"({result['risk_score']}/10)"
        )


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":

    results = (
        run_validation_pipeline()
    )

    print_summary(
        results
    )

    print_detailed_results(
        results
    )