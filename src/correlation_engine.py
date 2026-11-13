from typing import List, Dict

from finding_schema import Finding
from zap_parser import parse_zap_results
from nuclei_parser import parse_nuclei_results


def normalize_text(text: str) -> str:
    if not text:
        return ""

    return " ".join(
        text.lower().strip().split()
    )


def normalize_url(url: str) -> str:
    if not url:
        return ""

    return url.strip().lower().rstrip("/")


SECURITY_CONCEPTS = {

    "security_headers": {
        "content security policy",
        "csp",
        "security headers",
        "missing security headers",
        "x-content-type-options",
        "strict-transport-security",
        "hsts",
        "anti-clickjacking",
        "clickjacking",
        "x-frame-options",
    },

    "information_disclosure": {
        "information disclosure",
        "private ip disclosure",
        "timestamp disclosure",
        "suspicious comments",
        "technology detection",
        "fingerprint",
    },

    "api_exposure": {
        "swagger",
        "api",
        "api-docs",
        "prometheus",
        "metrics",
    },

    "robots": {
        "robots.txt",
        "robots",
    },

    "cache": {
        "cache",
        "retrieved from cache",
        "cache-control",
    },

    "session": {
        "session",
        "session id",
        "session management",
    },

    "injection": {
        "sql injection",
        "xss",
        "cross site scripting",
        "command injection",
        "injection",
    },

    "cors": {
        "cross-domain",
        "cors",
        "cross origin",
    },
}


def get_security_concepts(finding: Finding) -> set:

    text = normalize_text(
        " ".join(
            [
                finding.name or "",
                finding.description or "",
                finding.category or "",
            ]
        )
    )

    concepts = set()

    for concept, keywords in SECURITY_CONCEPTS.items():

        for keyword in keywords:

            if keyword in text:
                concepts.add(concept)
                break

    return concepts


def same_url(
    finding_a: Finding,
    finding_b: Finding
) -> bool:

    url_a = normalize_url(finding_a.url)
    url_b = normalize_url(finding_b.url)

    return bool(url_a) and url_a == url_b


def same_name(
    finding_a: Finding,
    finding_b: Finding
) -> bool:

    name_a = normalize_text(finding_a.name)
    name_b = normalize_text(finding_b.name)

    return bool(name_a) and name_a == name_b


def same_concept(
    finding_a: Finding,
    finding_b: Finding
) -> bool:

    concepts_a = get_security_concepts(finding_a)
    concepts_b = get_security_concepts(finding_b)

    return bool(concepts_a & concepts_b)


def classify_relationship(
    finding_a: Finding,
    finding_b: Finding
) -> str:

    if finding_a.scanner == finding_b.scanner:
        return "INDEPENDENT"

    if (
        same_url(finding_a, finding_b)
        and same_name(finding_a, finding_b)
    ):
        return "DUPLICATE"

    if (
        same_url(finding_a, finding_b)
        and same_concept(finding_a, finding_b)
    ):
        return "RELATED"

    return "INDEPENDENT"


def correlate_findings(
    findings: List[Finding]
) -> List[Dict]:

    relationships = []

    for i in range(len(findings)):

        for j in range(i + 1, len(findings)):

            finding_a = findings[i]
            finding_b = findings[j]

            relationship = classify_relationship(
                finding_a,
                finding_b
            )

            if relationship in {
                "DUPLICATE",
                "RELATED"
            }:

                relationships.append(
                    {
                        "relationship": relationship,
                        "finding_a": finding_a,
                        "finding_b": finding_b,
                    }
                )

    return relationships


def print_relationships(
    relationships: List[Dict]
):

    print()
    print("=" * 70)
    print("CORRELATION RESULTS")
    print("=" * 70)
    print()

    duplicate_count = 0
    related_count = 0

    for index, relation in enumerate(
        relationships,
        start=1
    ):

        finding_a = relation["finding_a"]
        finding_b = relation["finding_b"]

        relationship = relation["relationship"]

        if relationship == "DUPLICATE":
            duplicate_count += 1

        elif relationship == "RELATED":
            related_count += 1

        print(
            f"[{relationship}] Group {index}"
        )

        print(
            f"  {finding_a.scanner.upper()} | "
            f"{finding_a.finding_id} | "
            f"{finding_a.name}"
        )

        print(
            f"  URL: {finding_a.url}"
        )

        print(
            f"  {finding_b.scanner.upper()} | "
            f"{finding_b.finding_id} | "
            f"{finding_b.name}"
        )

        print(
            f"  URL: {finding_b.url}"
        )

        print("-" * 70)

    print()
    print(
        f"Duplicate relationships: "
        f"{duplicate_count}"
    )

    print(
        f"Related relationships: "
        f"{related_count}"
    )

    print(
        f"Total relationships: "
        f"{len(relationships)}"
    )


def main():

    print("Loading ZAP findings...")

    zap_findings = parse_zap_results()

    print(
        f"ZAP findings loaded: "
        f"{len(zap_findings)}"
    )

    print()

    print("Loading Nuclei findings...")

    nuclei_findings = parse_nuclei_results()

    print(
        f"Nuclei findings loaded: "
        f"{len(nuclei_findings)}"
    )

    print()

    all_findings = (
        zap_findings +
        nuclei_findings
    )

    print(
        f"Total raw findings: "
        f"{len(all_findings)}"
    )

    relationships = correlate_findings(
        all_findings
    )

    print_relationships(
        relationships
    )


if __name__ == "__main__":
    main()
