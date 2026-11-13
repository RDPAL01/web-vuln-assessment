"""
Unified Security Report Generator
----------------------------------

Automated Web Vulnerability Assessment Framework

Generates:

    1. JSON report
    2. CSV report
    3. HTML report

Based on:

    ZAP findings
    Nuclei findings
    Correlation
    Deduplication
    Evidence-based validation
    Confidence scoring
    Risk scoring
"""

from pathlib import Path
import sys
import json
import csv
from datetime import datetime


# ============================================================
# PROJECT PATH
# ============================================================

PROJECT_ROOT = (
    Path(__file__).resolve().parent.parent
)

REPORT_DIR = (
    PROJECT_ROOT / "reports"
)

REPORT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


# ============================================================
# IMPORT VALIDATION PIPELINE
# ============================================================

SRC_DIR = (
    PROJECT_ROOT / "src"
)

if str(SRC_DIR) not in sys.path:
    sys.path.insert(
        0,
        str(SRC_DIR),
    )

from validation_engine import (
    run_validation_pipeline,
)


# ============================================================
# SAFE VALUE
# ============================================================

def safe_value(
    value,
):
    """
    Convert values into JSON/CSV safe values.
    """

    if value is None:
        return ""

    if isinstance(
        value,
        (list, tuple),
    ):
        return "; ".join(
            str(item)
            for item in value
        )

    if isinstance(
        value,
        dict,
    ):
        return json.dumps(
            value,
            ensure_ascii=False,
        )

    return value


# ============================================================
# GENERATE STATISTICS
# ============================================================

def calculate_statistics(
    results,
):
    """
    Calculate report statistics.
    """

    total = len(results)

    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "informational": 0,
        "info": 0,
        "unknown": 0,
    }

    risk_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFORMATIONAL": 0,
    }

    validation_counts = {
        "VALIDATED": 0,
        "PARTIALLY_VALIDATED": 0,
        "UNVERIFIED": 0,
    }

    scanner_counts = {}

    type_counts = {
        "UNIQUE": 0,
        "RELATED": 0,
        "DUPLICATE": 0,
    }

    for result in results:

        severity = str(
            result.get(
                "severity",
                "unknown",
            )
        ).lower()

        if severity not in severity_counts:
            severity = "unknown"

        severity_counts[
            severity
        ] += 1

        risk = result.get(
            "risk_level",
            "INFORMATIONAL",
        )

        if risk not in risk_counts:
            risk = "INFORMATIONAL"

        risk_counts[
            risk
        ] += 1

        validation = result.get(
            "validation",
            "UNVERIFIED",
        )

        if validation not in validation_counts:
            validation = "UNVERIFIED"

        validation_counts[
            validation
        ] += 1

        finding_type = result.get(
            "type",
            "UNIQUE",
        )

        if finding_type not in type_counts:
            finding_type = "UNIQUE"

        type_counts[
            finding_type
        ] += 1

        scanner_string = result.get(
            "scanner",
            "unknown",
        )

        scanners = [
            scanner.strip()
            for scanner in str(
                scanner_string
            ).split(",")
            if scanner.strip()
        ]

        for scanner in scanners:

            scanner_counts[
                scanner
            ] = (
                scanner_counts.get(
                    scanner,
                    0,
                )
                + 1
            )

    return {
        "total_findings": total,
        "severity_distribution": severity_counts,
        "risk_distribution": risk_counts,
        "validation_distribution": validation_counts,
        "scanner_distribution": scanner_counts,
        "relationship_distribution": type_counts,
    }


# ============================================================
# BUILD REPORT OBJECT
# ============================================================

def build_report(
    results,
):
    """
    Build complete unified report object.
    """

    statistics = calculate_statistics(
        results
    )

    generated_at = (
        datetime.now().isoformat(
            timespec="seconds"
        )
    )

    report = {
        "report_metadata": {
            "framework": (
                "Automated Web Vulnerability "
                "Assessment Framework"
            ),
            "generated_at": generated_at,
            "target": (
                "http://localhost:3000"
            ),
            "validation_method": (
                "Evidence-based validation"
            ),
            "note": (
                "Validation indicates evidence "
                "support and does not represent "
                "exploit confirmation."
            ),
        },

        "statistics": statistics,

        "findings": results,
    }

    return report


# ============================================================
# JSON REPORT
# ============================================================

def write_json_report(
    report,
):
    """
    Write unified JSON report.
    """

    output_file = (
        REPORT_DIR
        /
        "unified_report.json"
    )

    with open(
        output_file,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            report,
            file,
            indent=4,
            ensure_ascii=False,
        )

    return output_file


# ============================================================
# CSV REPORT
# ============================================================

def write_csv_report(
    results,
):
    """
    Write flat CSV report.
    """

    output_file = (
        REPORT_DIR
        /
        "unified_report.csv"
    )

    fieldnames = [
        "group_id",
        "finding",
        "scanner",
        "severity",
        "type",
        "finding_count",
        "validation",
        "evidence_score",
        "scanner_confidence",
        "correlation_bonus",
        "confidence_score",
        "confidence_label",
        "risk_score",
        "risk_level",
        "urls",
        "methods",
        "evidence",
    ]

    with open(
        output_file,
        "w",
        newline="",
        encoding="utf-8",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )

        writer.writeheader()

        for result in results:

            row = {}

            for field in fieldnames:

                row[field] = safe_value(
                    result.get(
                        field,
                        "",
                    )
                )

            writer.writerow(
                row
            )

    return output_file


# ============================================================
# HTML ESCAPE
# ============================================================

def html_escape(
    value,
):
    """
    Escape HTML-sensitive characters.
    """

    text = safe_value(
        value
    )

    text = str(
        text
    )

    return (
        text
        .replace(
            "&",
            "&amp;",
        )
        .replace(
            "<",
            "&lt;",
        )
        .replace(
            ">",
            "&gt;",
        )
        .replace(
            '"',
            "&quot;",
        )
        .replace(
            "'",
            "&#39;",
        )
    )


# ============================================================
# HTML REPORT
# ============================================================

def write_html_report(
    report,
):
    """
    Generate interactive HTML report.
    """

    output_file = (
        REPORT_DIR
        /
        "unified_report.html"
    )

    metadata = report[
        "report_metadata"
    ]

    statistics = report[
        "statistics"
    ]

    findings = report[
        "findings"
    ]

    severity = statistics[
        "severity_distribution"
    ]

    risk = statistics[
        "risk_distribution"
    ]

    validation = statistics[
        "validation_distribution"
    ]

    scanner = statistics[
        "scanner_distribution"
    ]

    relationship = statistics[
        "relationship_distribution"
    ]

    rows = []

    for finding in findings:

        rows.append(
            f"""
            <tr>
                <td>{html_escape(finding.get("group_id"))}</td>
                <td>{html_escape(finding.get("finding"))}</td>
                <td>{html_escape(finding.get("scanner"))}</td>
                <td>{html_escape(finding.get("severity"))}</td>
                <td>{html_escape(finding.get("type"))}</td>
                <td>{html_escape(finding.get("validation"))}</td>
                <td>{html_escape(finding.get("confidence_label"))}</td>
                <td>{html_escape(finding.get("confidence_score"))}</td>
                <td>{html_escape(finding.get("risk_level"))}</td>
                <td>{html_escape(finding.get("risk_score"))}</td>
            </tr>
            """
        )

    scanner_rows = []

    for name, count in scanner.items():

        scanner_rows.append(
            f"""
            <tr>
                <td>{html_escape(name)}</td>
                <td>{count}</td>
            </tr>
            """
        )

    html = f"""
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>
Unified Security Assessment Report
</title>

<style>

body {{
    font-family:
        Arial,
        Helvetica,
        sans-serif;

    margin: 0;

    background: #f4f6f8;

    color: #222;
}}

header {{
    background: #111827;

    color: white;

    padding: 30px;
}}

header h1 {{
    margin: 0 0 10px 0;
}}

.container {{
    max-width: 1400px;

    margin: auto;

    padding: 25px;
}}

.grid {{
    display: grid;

    grid-template-columns:
        repeat(
            auto-fit,
            minmax(
                180px,
                1fr
            )
        );

    gap: 15px;

    margin-bottom: 25px;
}}

.card {{
    background: white;

    border-radius: 10px;

    padding: 20px;

    box-shadow:
        0 2px 8px
        rgba(
            0,
            0,
            0,
            0.08
        );
}}

.card h3 {{
    margin-top: 0;

    color: #555;
}}

.card .number {{
    font-size: 30px;

    font-weight: bold;
}}

.section {{
    background: white;

    padding: 25px;

    margin-bottom: 25px;

    border-radius: 10px;

    box-shadow:
        0 2px 8px
        rgba(
            0,
            0,
            0,
            0.08
        );
}}

table {{
    width: 100%;

    border-collapse: collapse;
}}

th,
td {{
    padding: 10px;

    border-bottom:
        1px solid #ddd;

    text-align: left;
}}

th {{
    background: #111827;

    color: white;
}}

tr:hover {{
    background: #f5f5f5;
}}

.badge {{
    padding:
        4px
        8px;

    border-radius: 5px;

    font-weight: bold;
}}

.note {{
    background: #fff8e1;

    border-left:
        5px solid #f59e0b;

    padding: 15px;

    margin-top: 15px;
}}

</style>

</head>

<body>

<header>

<div class="container">

<h1>
Unified Web Security Assessment Report
</h1>

<p>
Automated Web Vulnerability Assessment Framework
</p>

<p>
Target:
{html_escape(metadata.get("target"))}
</p>

<p>
Generated:
{html_escape(metadata.get("generated_at"))}
</p>

</div>

</header>


<div class="container">


<!-- ====================================================== -->
<!-- EXECUTIVE SUMMARY -->
<!-- ====================================================== -->

<div class="section">

<h2>
Executive Summary
</h2>

<p>
The framework collected vulnerability findings from
multiple security scanners, correlated related findings,
consolidated the results, and applied evidence-based
validation, confidence scoring, and risk scoring.
</p>

<div class="note">

<strong>Methodology Note:</strong>

{html_escape(metadata.get("note"))}

</div>

</div>


<!-- ====================================================== -->
<!-- OVERVIEW -->
<!-- ====================================================== -->

<div class="grid">

<div class="card">

<h3>
Total Findings
</h3>

<div class="number">
{statistics.get("total_findings", 0)}
</div>

</div>


<div class="card">

<h3>
Critical
</h3>

<div class="number">
{severity.get("critical", 0)}
</div>

</div>


<div class="card">

<h3>
High
</h3>

<div class="number">
{severity.get("high", 0)}
</div>

</div>


<div class="card">

<h3>
Medium
</h3>

<div class="number">
{severity.get("medium", 0)}
</div>

</div>


<div class="card">

<h3>
Low
</h3>

<div class="number">
{severity.get("low", 0)}
</div>

</div>


<div class="card">

<h3>
Informational
</h3>

<div class="number">
{
    severity.get("informational", 0)
    +
    severity.get("info", 0)
}
</div>

</div>

</div>


<!-- ====================================================== -->
<!-- RISK -->
<!-- ====================================================== -->

<div class="section">

<h2>
Risk Distribution
</h2>

<table>

<tr>
<th>Risk Level</th>
<th>Count</th>
</tr>

<tr>
<td>Critical</td>
<td>{risk.get("CRITICAL", 0)}</td>
</tr>

<tr>
<td>High</td>
<td>{risk.get("HIGH", 0)}</td>
</tr>

<tr>
<td>Medium</td>
<td>{risk.get("MEDIUM", 0)}</td>
</tr>

<tr>
<td>Low</td>
<td>{risk.get("LOW", 0)}</td>
</tr>

<tr>
<td>Informational</td>
<td>{risk.get("INFORMATIONAL", 0)}</td>
</tr>

</table>

</div>


<!-- ====================================================== -->
<!-- VALIDATION -->
<!-- ====================================================== -->

<div class="section">

<h2>
Validation Distribution
</h2>

<table>

<tr>
<th>Status</th>
<th>Count</th>
</tr>

<tr>
<td>Validated</td>
<td>{validation.get("VALIDATED", 0)}</td>
</tr>

<tr>
<td>Partially Validated</td>
<td>{validation.get("PARTIALLY_VALIDATED", 0)}</td>
</tr>

<tr>
<td>Unverified</td>
<td>{validation.get("UNVERIFIED", 0)}</td>
</tr>

</table>

</div>


<!-- ====================================================== -->
<!-- SCANNERS -->
<!-- ====================================================== -->

<div class="section">

<h2>
Scanner Distribution
</h2>

<table>

<tr>
<th>Scanner</th>
<th>Findings</th>
</tr>

{"".join(scanner_rows)}

</table>

</div>


<!-- ====================================================== -->
<!-- CORRELATION -->
<!-- ====================================================== -->

<div class="section">

<h2>
Correlation / Consolidation
</h2>

<table>

<tr>
<th>Relationship Type</th>
<th>Count</th>
</tr>

<tr>
<td>Unique</td>
<td>{relationship.get("UNIQUE", 0)}</td>
</tr>

<tr>
<td>Related</td>
<td>{relationship.get("RELATED", 0)}</td>
</tr>

<tr>
<td>Duplicate</td>
<td>{relationship.get("DUPLICATE", 0)}</td>
</tr>

</table>

</div>


<!-- ====================================================== -->
<!-- DETAILED FINDINGS -->
<!-- ====================================================== -->

<div class="section">

<h2>
Detailed Findings
</h2>

<table>

<tr>

<th>
Group ID
</th>

<th>
Finding
</th>

<th>
Scanner
</th>

<th>
Severity
</th>

<th>
Type
</th>

<th>
Validation
</th>

<th>
Confidence
</th>

<th>
Confidence Score
</th>

<th>
Risk
</th>

<th>
Risk Score
</th>

</tr>

{"".join(rows)}

</table>

</div>


</div>

</body>

</html>
"""

    with open(
        output_file,
        "w",
        encoding="utf-8",
    ) as file:

        file.write(
            html
        )

    return output_file


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "=" * 70
    )

    print(
        "UNIFIED SECURITY REPORT GENERATOR"
    )

    print(
        "=" * 70
    )

    # --------------------------------------------------------
    # RUN COMPLETE PIPELINE
    # --------------------------------------------------------

    print()

    print(
        "Running assessment pipeline..."
    )

    results = (
        run_validation_pipeline()
    )

    print()

    print(
        f"Validated result records: "
        f"{len(results)}"
    )

    # --------------------------------------------------------
    # BUILD REPORT
    # --------------------------------------------------------

    report = build_report(
        results
    )

    # --------------------------------------------------------
    # WRITE JSON
    # --------------------------------------------------------

    json_file = (
        write_json_report(
            report
        )
    )

    # --------------------------------------------------------
    # WRITE CSV
    # --------------------------------------------------------

    csv_file = (
        write_csv_report(
            results
        )
    )

    # --------------------------------------------------------
    # WRITE HTML
    # --------------------------------------------------------

    html_file = (
        write_html_report(
            report
        )
    )

    # --------------------------------------------------------
    # FINAL OUTPUT
    # --------------------------------------------------------

    print()

    print(
        "=" * 70
    )

    print(
        "REPORT GENERATION COMPLETE"
    )

    print(
        "=" * 70
    )

    print()

    print(
        f"JSON : {json_file}"
    )

    print(
        f"CSV  : {csv_file}"
    )

    print(
        f"HTML : {html_file}"
    )

    print()

    print(
        "All unified reports generated successfully."
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()