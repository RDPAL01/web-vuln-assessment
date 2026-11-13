"""
Deduplication and Consolidation Engine
---------------------------------------

Automated Web Vulnerability Assessment Framework

Pipeline:

    ZAP + Nuclei
          ↓
    Common Findings
          ↓
    Correlation Engine V3
          ↓
    Deduplication
          ↓
    Consolidated Findings
          ↓
    Unified Security Report

This module:
    1. Loads ZAP findings.
    2. Loads Nuclei findings.
    3. Runs the V3 correlation engine.
    4. Groups DUPLICATE / RELATED findings.
    5. Selects a primary finding for each group.
    6. Preserves scanner/evidence information.
    7. Reports the reduction in findings.
"""

from pathlib import Path
import sys
from typing import List, Dict, Any


# =====================================================================
# PROJECT PATH
# =====================================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# =====================================================================
# IMPORT EXISTING PROJECT COMPONENTS
# =====================================================================

from src.zap_parser import parse_zap_results
from src.nuclei_parser import parse_nuclei_results
from src.correlation_engine_v3 import correlate_findings


# =====================================================================
# SEVERITY PRIORITY
# =====================================================================

SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
    "info": 1,
    "unknown": 0,
}


def severity_value(severity: Any) -> int:
    """
    Convert severity into a numeric priority.
    """

    if severity is None:
        return 0

    severity = str(severity).lower().strip()

    return SEVERITY_ORDER.get(
        severity,
        0,
    )


# =====================================================================
# CONFIDENCE PRIORITY
# =====================================================================

CONFIDENCE_ORDER = {
    "high": 3,
    "medium": 2,
    "low": 1,
    "unknown": 0,
}


def confidence_value(confidence: Any) -> int:
    """
    Convert confidence into a numeric priority.
    """

    if confidence is None:
        return 0

    confidence = str(confidence).lower().strip()

    return CONFIDENCE_ORDER.get(
        confidence,
        0,
    )


# =====================================================================
# SAFE ATTRIBUTE ACCESS
# =====================================================================

def get_attr(
    finding: Any,
    attribute: str,
    default=None,
):
    """
    Safely retrieve an attribute from a Finding object.

    This keeps the engine compatible with optional fields.
    """

    return getattr(
        finding,
        attribute,
        default,
    )


# =====================================================================
# UNION-FIND DATA STRUCTURE
# =====================================================================

class UnionFind:
    """
    Disjoint-set / Union-Find structure.

    Used to combine findings that are identified as
    DUPLICATE or RELATED by the correlation engine.
    """

    def __init__(self, size: int):

        self.parent = list(
            range(size)
        )

        self.rank = [0] * size

    def find(self, value: int) -> int:
        """
        Find the root of a set.
        """

        if self.parent[value] != value:

            self.parent[value] = self.find(
                self.parent[value]
            )

        return self.parent[value]

    def union(
        self,
        first: int,
        second: int,
    ) -> None:
        """
        Merge two sets.
        """

        root_first = self.find(first)
        root_second = self.find(second)

        if root_first == root_second:
            return

        if self.rank[root_first] < self.rank[root_second]:

            self.parent[root_first] = root_second

        elif self.rank[root_first] > self.rank[root_second]:

            self.parent[root_second] = root_first

        else:

            self.parent[root_second] = root_first

            self.rank[root_first] += 1


# =====================================================================
# FINDING INDEX
# =====================================================================

def build_finding_index(
    findings: List[Any],
) -> Dict[int, int]:
    """
    Map Python object identity to finding index.
    """

    return {
        id(finding): index
        for index, finding in enumerate(findings)
    }


# =====================================================================
# SELECT PRIMARY FINDING
# =====================================================================

def select_primary_finding(
    findings: List[Any],
) -> Any:
    """
    Select the primary finding from a consolidated group.

    Priority:
        1. Severity
        2. Confidence
        3. ZAP as deterministic tie-breaker
    """

    if not findings:
        return None

    def ranking(finding):

        severity = severity_value(
            get_attr(
                finding,
                "severity",
                "unknown",
            )
        )

        confidence = confidence_value(
            get_attr(
                finding,
                "confidence",
                "unknown",
            )
        )

        scanner = str(
            get_attr(
                finding,
                "scanner",
                "",
            )
        ).lower()

        scanner_priority = (
            1
            if scanner == "zap"
            else 0
        )

        return (
            severity,
            confidence,
            scanner_priority,
        )

    return max(
        findings,
        key=ranking,
    )


# =====================================================================
# UNIQUE VALUES
# =====================================================================

def unique_values(
    findings: List[Any],
    attribute: str,
) -> List[Any]:
    """
    Return unique non-empty values for a Finding attribute.
    """

    values = []

    for finding in findings:

        value = get_attr(
            finding,
            attribute,
            None,
        )

        if value is None:
            continue

        value = str(value).strip()

        if not value:
            continue

        if value not in values:
            values.append(value)

    return values


# =====================================================================
# BUILD CORRELATION GROUPS
# =====================================================================

def build_groups(
    findings: List[Any],
    correlations: List[Dict[str, Any]],
) -> List[List[Any]]:
    """
    Build finding groups using correlation relationships.

    DUPLICATE and RELATED relationships both cause findings
    to belong to the same consolidated group.
    """

    if not findings:
        return []

    union_find = UnionFind(
        len(findings)
    )

    finding_index = build_finding_index(
        findings
    )

    for correlation in correlations:

        relation = correlation.get(
            "type"
        )

        if relation not in {
            "DUPLICATE",
            "RELATED",
        }:
            continue

        finding_a = correlation.get(
            "finding_a"
        )

        finding_b = correlation.get(
            "finding_b"
        )

        if finding_a is None or finding_b is None:
            continue

        index_a = finding_index.get(
            id(finding_a)
        )

        index_b = finding_index.get(
            id(finding_b)
        )

        if index_a is None or index_b is None:
            continue

        union_find.union(
            index_a,
            index_b,
        )

    groups = {}

    for index, finding in enumerate(findings):

        root = union_find.find(
            index
        )

        if root not in groups:
            groups[root] = []

        groups[root].append(
            finding
        )

    return list(
        groups.values()
    )


# =====================================================================
# FIND CORRELATIONS INSIDE GROUP
# =====================================================================

def get_group_relationships(
    group: List[Any],
    correlations: List[Dict[str, Any]],
) -> List[str]:
    """
    Return relationship types present inside a group.
    """

    relationships = []

    group_ids = {
        id(finding)
        for finding in group
    }

    for correlation in correlations:

        finding_a = correlation.get(
            "finding_a"
        )

        finding_b = correlation.get(
            "finding_b"
        )

        if finding_a is None or finding_b is None:
            continue

        if (
            id(finding_a) in group_ids
            and
            id(finding_b) in group_ids
        ):

            relation = correlation.get(
                "type"
            )

            if (
                relation
                and relation not in relationships
            ):
                relationships.append(
                    relation
                )

    return relationships


# =====================================================================
# DETERMINE GROUP TYPE
# =====================================================================

def determine_group_type(
    relationships: List[str],
) -> str:
    """
    Determine whether a group is:

        UNIQUE
        RELATED
        DUPLICATE
    """

    if not relationships:
        return "UNIQUE"

    if "DUPLICATE" in relationships:
        return "DUPLICATE"

    if "RELATED" in relationships:
        return "RELATED"

    return "UNIQUE"


# =====================================================================
# CONSOLIDATE SINGLE GROUP
# =====================================================================

def consolidate_group(
    group_id: str,
    group: List[Any],
    correlations: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Convert one group of Finding objects into a unified record.
    """

    primary = select_primary_finding(
        group
    )

    relationships = get_group_relationships(
        group,
        correlations,
    )

    group_type = determine_group_type(
        relationships
    )

    scanners = unique_values(
        group,
        "scanner",
    )

    names = unique_values(
        group,
        "name",
    )

    urls = unique_values(
        group,
        "url",
    )

    targets = unique_values(
        group,
        "target",
    )

    methods = unique_values(
        group,
        "method",
    )

    evidences = unique_values(
        group,
        "evidence",
    )

    cwe_ids = unique_values(
        group,
        "cwe_id",
    )

    wasc_ids = unique_values(
        group,
        "wasc_id",
    )

    finding_ids = unique_values(
        group,
        "finding_id",
    )

    severities = unique_values(
        group,
        "severity",
    )

    confidences = unique_values(
        group,
        "confidence",
    )

    highest_severity = "unknown"

    if severities:

        highest_severity = max(
            severities,
            key=severity_value,
        )

    highest_confidence = "unknown"

    if confidences:

        highest_confidence = max(
            confidences,
            key=confidence_value,
        )

    return {
        "group_id": group_id,

        "type": group_type,

        "primary_finding_id": get_attr(
            primary,
            "finding_id",
            None,
        ),

        "primary_scanner": get_attr(
            primary,
            "scanner",
            "unknown",
        ),

        "primary_name": get_attr(
            primary,
            "name",
            "Unknown Finding",
        ),

        "severity": highest_severity,

        "confidence": highest_confidence,

        "scanner_count": len(
            scanners
        ),

        "scanners": scanners,

        "finding_count": len(
            group
        ),

        "finding_ids": finding_ids,

        "names": names,

        "urls": urls,

        "targets": targets,

        "methods": methods,

        "evidence": evidences,

        "cwe_ids": cwe_ids,

        "wasc_ids": wasc_ids,

        "relationships": relationships,

        "findings": group,
    }


# =====================================================================
# CONSOLIDATE ALL FINDINGS
# =====================================================================

def consolidate_findings(
    findings: List[Any],
    correlations: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Consolidate all raw findings into unified groups.
    """

    groups = build_groups(
        findings,
        correlations,
    )

    consolidated = []

    for index, group in enumerate(
        groups,
        start=1,
    ):

        group_id = (
            f"VULN-{index:04d}"
        )

        record = consolidate_group(
            group_id,
            group,
            correlations,
        )

        consolidated.append(
            record
        )

    return consolidated


# =====================================================================
# REDUCTION METRICS
# =====================================================================

def calculate_reduction(
    raw_count: int,
    consolidated_count: int,
) -> Dict[str, float]:
    """
    Calculate deduplication reduction metrics.
    """

    reduced = (
        raw_count
        -
        consolidated_count
    )

    if raw_count == 0:

        percentage = 0.0

    else:

        percentage = (
            reduced
            /
            raw_count
        ) * 100.0

    return {
        "raw_findings": raw_count,

        "consolidated_findings": (
            consolidated_count
        ),

        "findings_reduced": reduced,

        "reduction_percentage": round(
            percentage,
            2,
        ),
    }


# =====================================================================
# PRINT SUMMARY
# =====================================================================

def print_summary(
    findings: List[Any],
    correlations: List[Dict[str, Any]],
    consolidated: List[Dict[str, Any]],
) -> None:
    """
    Print deduplication summary.
    """

    duplicate_count = sum(
        1
        for correlation in correlations
        if correlation.get("type")
        == "DUPLICATE"
    )

    related_count = sum(
        1
        for correlation in correlations
        if correlation.get("type")
        == "RELATED"
    )

    metrics = calculate_reduction(
        len(findings),
        len(consolidated),
    )

    print()
    print("=" * 70)
    print("DEDUPLICATION SUMMARY")
    print("=" * 70)

    print(
        f"Raw findings: "
        f"{metrics['raw_findings']}"
    )

    print(
        f"Duplicate relationships: "
        f"{duplicate_count}"
    )

    print(
        f"Related relationships: "
        f"{related_count}"
    )

    print(
        f"Consolidated findings: "
        f"{metrics['consolidated_findings']}"
    )

    print(
        f"Findings reduced: "
        f"{metrics['findings_reduced']}"
    )

    print(
        f"Reduction percentage: "
        f"{metrics['reduction_percentage']:.2f}%"
    )


# =====================================================================
# PRINT CONSOLIDATED RESULTS
# =====================================================================

def print_consolidated_findings(
    consolidated: List[Dict[str, Any]],
) -> None:
    """
    Print consolidated vulnerability groups.
    """

    print()
    print("=" * 70)
    print("CONSOLIDATED FINDINGS")
    print("=" * 70)

    for item in consolidated:

        print("-" * 70)

        print(
            f"Group ID: "
            f"{item['group_id']}"
        )

        print(
            f"Type: "
            f"{item['type']}"
        )

        print(
            f"Primary Finding ID: "
            f"{item['primary_finding_id']}"
        )

        print(
            f"Primary Scanner: "
            f"{item['primary_scanner']}"
        )

        print(
            f"Primary Name: "
            f"{item['primary_name']}"
        )

        print(
            f"Severity: "
            f"{item['severity']}"
        )

        print(
            f"Confidence: "
            f"{item['confidence']}"
        )

        print(
            f"Finding Count: "
            f"{item['finding_count']}"
        )

        print(
            f"Scanners: "
            f"{', '.join(item['scanners'])}"
        )

        if item["relationships"]:

            print(
                f"Relationships: "
                f"{', '.join(item['relationships'])}"
            )

        print(
            "URLs:"
        )

        for url in item["urls"]:

            print(
                f"  - {url}"
            )

        print(
            "Finding Names:"
        )

        for name in item["names"]:

            print(
                f"  - {name}"
            )


# =====================================================================
# MAIN
# =====================================================================

def main():

    print("=" * 70)
    print("DEDUPLICATION / CONSOLIDATION ENGINE")
    print("=" * 70)

    # ---------------------------------------------------------------
    # ZAP
    # ---------------------------------------------------------------

    try:

        zap_findings = (
            parse_zap_results()
        )

    except Exception as exc:

        print(
            f"ERROR loading ZAP findings: "
            f"{exc}"
        )

        zap_findings = []

    print(
        f"ZAP findings loaded: "
        f"{len(zap_findings)}"
    )

    # ---------------------------------------------------------------
    # NUCLEI
    # ---------------------------------------------------------------

    try:

        nuclei_findings = (
            parse_nuclei_results()
        )

    except Exception as exc:

        print(
            f"ERROR loading Nuclei findings: "
            f"{exc}"
        )

        nuclei_findings = []

    print(
        f"Nuclei findings loaded: "
        f"{len(nuclei_findings)}"
    )

    # ---------------------------------------------------------------
    # COMBINE
    # ---------------------------------------------------------------

    findings = (
        zap_findings
        +
        nuclei_findings
    )

    print(
        f"Total raw findings: "
        f"{len(findings)}"
    )

    # ---------------------------------------------------------------
    # CORRELATION
    # ---------------------------------------------------------------

    print()
    print(
        "Running correlation engine..."
    )

    try:

        correlations = correlate_findings(
            findings
        )

    except Exception as exc:

        print(
            f"ERROR during correlation: "
            f"{exc}"
        )

        correlations = []

    print(
        f"Correlations found: "
        f"{len(correlations)}"
    )

    # ---------------------------------------------------------------
    # DEDUPLICATION
    # ---------------------------------------------------------------

    print()
    print(
        "Running deduplication..."
    )

    consolidated = consolidate_findings(
        findings,
        correlations,
    )

    # ---------------------------------------------------------------
    # SUMMARY
    # ---------------------------------------------------------------

    print_summary(
        findings,
        correlations,
        consolidated,
    )

    # ---------------------------------------------------------------
    # DETAILS
    # ---------------------------------------------------------------

    print_consolidated_findings(
        consolidated
    )


# =====================================================================
# ENTRY POINT
# =====================================================================

if __name__ == "__main__":
    main()