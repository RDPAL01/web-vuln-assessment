import json
import csv
from pathlib import Path
from collections import Counter


BASE_DIR = Path(__file__).resolve().parent.parent
REPORT_DIR = BASE_DIR / "reports"
EVAL_DIR = BASE_DIR / "results" / "evaluation"

REPORT_FILE = REPORT_DIR / "unified_report.json"

OUTPUT_JSON = EVAL_DIR / "evaluation_summary.json"
OUTPUT_CSV = EVAL_DIR / "evaluation_findings.csv"


def load_report():
    if not REPORT_FILE.exists():
        raise FileNotFoundError(
            f"Unified report not found: {REPORT_FILE}"
        )

    with open(REPORT_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def main():

    print("=" * 70)
    print("STEP 12 - EXPERIMENTAL EVALUATION")
    print("=" * 70)

    report = load_report()

    findings = report.get("findings", [])

    if not findings:
        raise ValueError("No findings found in unified report.")

    # ---------------------------------------------------------
    # Basic counts
    # ---------------------------------------------------------

    consolidated_count = len(findings)

    raw_count = report.get(
        "statistics", {}
    ).get(
        "raw_findings",
        33
    )

    correlation_count = report.get(
        "statistics", {}
    ).get(
        "total_correlations",
        1
    )

    reduction_count = raw_count - consolidated_count

    reduction_percentage = (
        reduction_count / raw_count * 100
        if raw_count > 0 else 0
    )

    # ---------------------------------------------------------
    # Scanner distribution
    # ---------------------------------------------------------

    scanner_counter = Counter()

    for finding in findings:

        scanners = finding.get("scanners", [])

        if scanners:
            for scanner in scanners:
                scanner_counter[scanner] += 1

        else:
            scanner = finding.get(
                "primary_scanner",
                finding.get("scanner", "unknown")
            )
            scanner_counter[scanner] += 1

    # ---------------------------------------------------------
    # Severity distribution
    # ---------------------------------------------------------

    severity_counter = Counter(
        finding.get(
            "severity",
            "unknown"
        ).lower()
        for finding in findings
    )

    # ---------------------------------------------------------
    # Risk distribution
    # ---------------------------------------------------------

    risk_counter = Counter(
        finding.get(
            "risk_level",
            "unknown"
        ).upper()
        for finding in findings
    )

    # ---------------------------------------------------------
    # Confidence distribution
    # ---------------------------------------------------------

    confidence_counter = Counter(
        finding.get(
            "confidence_label",
            "unknown"
        ).upper()
        for finding in findings
    )

    # ---------------------------------------------------------
    # Validation distribution
    # ---------------------------------------------------------

    validation_counter = Counter(
        finding.get(
            "validation",
            "unknown"
        ).upper()
        for finding in findings
    )

    # ---------------------------------------------------------
    # Correlation type distribution
    # ---------------------------------------------------------

    correlation_counter = Counter()

    for finding in findings:

        relationship = finding.get(
            "type",
            "UNIQUE"
        ).upper()

        correlation_counter[relationship] += 1

    # ---------------------------------------------------------
    # Evidence statistics
    # ---------------------------------------------------------

    evidence_values = []

    for finding in findings:

        evidence = finding.get(
            "evidence_score",
            0
        )

        try:
            evidence_values.append(
                float(evidence)
            )
        except (ValueError, TypeError):
            evidence_values.append(0)

    average_evidence = (
        sum(evidence_values) / len(evidence_values)
        if evidence_values else 0
    )

    # ---------------------------------------------------------
    # Confidence statistics
    # ---------------------------------------------------------

    confidence_values = []

    for finding in findings:

        confidence = finding.get(
            "confidence_score",
            0
        )

        try:
            confidence_values.append(
                float(confidence)
            )
        except (ValueError, TypeError):
            confidence_values.append(0)

    average_confidence = (
        sum(confidence_values) / len(confidence_values)
        if confidence_values else 0
    )

    # ---------------------------------------------------------
    # Risk statistics
    # ---------------------------------------------------------

    risk_values = []

    for finding in findings:

        risk = finding.get(
            "risk_score",
            0
        )

        try:
            risk_values.append(
                float(risk)
            )
        except (ValueError, TypeError):
            risk_values.append(0)

    average_risk = (
        sum(risk_values) / len(risk_values)
        if risk_values else 0
    )

    # ---------------------------------------------------------
    # Evaluation summary
    # ---------------------------------------------------------

    evaluation = {

        "experiment": {
            "name": "Multi-Scanner Web Vulnerability Assessment",
            "target": "http://localhost:3000",
            "scanners": [
                "OWASP ZAP",
                "Nuclei"
            ]
        },

        "finding_reduction": {
            "raw_findings": raw_count,
            "consolidated_findings": consolidated_count,
            "findings_removed": reduction_count,
            "reduction_percentage": round(
                reduction_percentage,
                2
            )
        },

        "correlation": {
            "total_correlations": correlation_count
        },

        "scanner_distribution": dict(
            scanner_counter
        ),

        "severity_distribution": dict(
            severity_counter
        ),

        "risk_distribution": dict(
            risk_counter
        ),

        "confidence_distribution": dict(
            confidence_counter
        ),

        "validation_distribution": dict(
            validation_counter
        ),

        "relationship_distribution": dict(
            correlation_counter
        ),

        "evidence_statistics": {
            "average_evidence_score": round(
                average_evidence,
                2
            )
        },

        "confidence_statistics": {
            "average_confidence_score": round(
                average_confidence,
                2
            )
        },

        "risk_statistics": {
            "average_risk_score": round(
                average_risk,
                2
            )
        },

        "ground_truth_metrics": {
            "precision": None,
            "recall": None,
            "f1_score": None,
            "note": (
                "Precision, recall and F1 are not calculated "
                "because the current Juice Shop experiment "
                "does not provide an independent ground-truth "
                "set of vulnerabilities."
            )
        }
    }

    # ---------------------------------------------------------
    # Save JSON
    # ---------------------------------------------------------

    EVAL_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        OUTPUT_JSON,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            evaluation,
            f,
            indent=2,
            ensure_ascii=False
        )

    # ---------------------------------------------------------
    # Save detailed CSV
    # ---------------------------------------------------------

    csv_fields = [
        "finding_id",
        "primary_scanner",
        "primary_name",
        "severity",
        "confidence",
        "risk_score",
        "risk_level",
        "validation",
        "type",
        "scanner_count",
        "finding_count"
    ]

    with open(
        OUTPUT_CSV,
        "w",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=csv_fields
        )

        writer.writeheader()

        for finding in findings:

            writer.writerow({

                "finding_id":
                    finding.get(
                        "group_id",
                        finding.get(
                            "finding_id",
                            ""
                        )
                    ),

                "primary_scanner":
                    finding.get(
                        "primary_scanner",
                        ""
                    ),

                "primary_name":
                    finding.get(
                        "primary_name",
                        finding.get(
                            "name",
                            ""
                        )
                    ),

                "severity":
                    finding.get(
                        "severity",
                        ""
                    ),

                "confidence":
                    finding.get(
                        "confidence",
                        ""
                    ),

                "risk_score":
                    finding.get(
                        "risk_score",
                        0
                    ),

                "risk_level":
                    finding.get(
                        "risk_level",
                        ""
                    ),

                "validation":
                    finding.get(
                        "validation",
                        ""
                    ),

                "type":
                    finding.get(
                        "type",
                        "UNIQUE"
                    ),

                "scanner_count":
                    finding.get(
                        "scanner_count",
                        1
                    ),

                "finding_count":
                    finding.get(
                        "finding_count",
                        1
                    )
            })

    # ---------------------------------------------------------
    # Console output
    # ---------------------------------------------------------

    print()
    print("EVALUATION SUMMARY")
    print("-" * 70)

    print(
        f"Raw findings              : {raw_count}"
    )

    print(
        f"Consolidated findings     : {consolidated_count}"
    )

    print(
        f"Findings removed          : {reduction_count}"
    )

    print(
        f"Reduction                 : "
        f"{reduction_percentage:.2f}%"
    )

    print(
        f"Correlations              : "
        f"{correlation_count}"
    )

    print()
    print("SCANNER DISTRIBUTION")
    print("-" * 70)

    for scanner, count in scanner_counter.items():

        print(
            f"{scanner:<25}: {count}"
        )

    print()
    print("SEVERITY DISTRIBUTION")
    print("-" * 70)

    for severity, count in severity_counter.items():

        print(
            f"{severity:<25}: {count}"
        )

    print()
    print("RISK DISTRIBUTION")
    print("-" * 70)

    for risk, count in risk_counter.items():

        print(
            f"{risk:<25}: {count}"
        )

    print()
    print("CONFIDENCE DISTRIBUTION")
    print("-" * 70)

    for confidence, count in confidence_counter.items():

        print(
            f"{confidence:<25}: {count}"
        )

    print()
    print("VALIDATION DISTRIBUTION")
    print("-" * 70)

    for status, count in validation_counter.items():

        print(
            f"{status:<25}: {count}"
        )

    print()
    print("AVERAGES")
    print("-" * 70)

    print(
        f"Average evidence score   : "
        f"{average_evidence:.2f}"
    )

    print(
        f"Average confidence      : "
        f"{average_confidence:.2f}"
    )

    print(
        f"Average risk score      : "
        f"{average_risk:.2f}"
    )

    print()
    print("GROUND-TRUTH METRICS")
    print("-" * 70)

    print("Precision                : N/A")
    print("Recall                   : N/A")
    print("F1-score                 : N/A")

    print()
    print("Files generated:")
    print(
        f"JSON : {OUTPUT_JSON}"
    )
    print(
        f"CSV  : {OUTPUT_CSV}"
    )

    print()
    print("=" * 70)
    print("STEP 12 CURRENT EVALUATION COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()