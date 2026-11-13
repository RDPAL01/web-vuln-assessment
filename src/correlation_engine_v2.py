from typing import Dict, List
from urllib.parse import urlparse

from finding_schema import Finding
from zap_parser import parse_zap_results
from nuclei_parser import parse_nuclei_results


# ============================================================
# TEXT NORMALIZATION
# ============================================================

def normalize_text(text: str) -> str:
    if not text:
        return ""

    return " ".join(
        text.lower().strip().split()
    )


# ============================================================
# URL / ENDPOINT FEATURES
# ============================================================

def normalize_url(url: str) -> str:
    if not url:
        return ""

    return url.lower().strip().rstrip("/")


def extract_endpoint(url: str) -> str:
    """
    Extract only the URL path.
    Query parameters are intentionally ignored
    for endpoint-level comparison.
    """

    if not url:
        return ""

    try:
        parsed = urlparse(url)

        path = parsed.path or "/"

        return path.lower().rstrip("/")

    except Exception:
        return normalize_url(url)


def endpoint_similarity(
    finding_a: Finding,
    finding_b: Finding
) -> float:

    endpoint_a = extract_endpoint(
        finding_a.url
    )

    endpoint_b = extract_endpoint(
        finding_b.url
    )

    if not endpoint_a or not endpoint_b:
        return 0.0

    if endpoint_a == endpoint_b:
        return 1.0

    parts_a = set(
        endpoint_a.strip("/").split("/")
    )

    parts_b = set(
        endpoint_b.strip("/").split("/")
    )

    if not parts_a or not parts_b:
        return 0.0

    intersection = parts_a & parts_b
    union = parts_a | parts_b

    if not union:
        return 0.0

    return len(intersection) / len(union)


# ============================================================
# FINDING NAME SIMILARITY
# ============================================================

def name_similarity(
    finding_a: Finding,
    finding_b: Finding
) -> float:

    name_a = normalize_text(
        finding_a.name
    )

    name_b = normalize_text(
        finding_b.name
    )

    if not name_a or not name_b:
        return 0.0

    if name_a == name_b:
        return 1.0

    words_a = set(name_a.split())
    words_b = set(name_b.split())

    if not words_a or not words_b:
        return 0.0

    intersection = words_a & words_b
    union = words_a | words_b

    if not union:
        return 0.0

    return len(intersection) / len(union)


# ============================================================
# SECURITY CONCEPTS
# ============================================================

SECURITY_CONCEPTS = {

    "injection": {
        "sql injection",
        "xss",
        "cross site scripting",
        "command injection",
        "injection",
    },

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

    "session": {
        "session",
        "session id",
        "session management",
    },

    "cors": {
        "cross-domain",
        "cors",
        "cross origin",
    },

    "information_disclosure": {
        "information disclosure",
        "private ip disclosure",
        "timestamp disclosure",
        "suspicious comments",
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
        "cache-control",
        "retrieved from cache",
    },

    "technology_detection": {
        "technology detection",
        "fingerprint",
        "wappalyzer",
        "fingerprinthub",
    },
}


def get_security_concepts(
    finding: Finding
) -> set:

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


def concept_similarity(
    finding_a: Finding,
    finding_b: Finding
) -> float:

    concepts_a = get_security_concepts(
        finding_a
    )

    concepts_b = get_security_concepts(
        finding_b
    )

    if not concepts_a or not concepts_b:
        return 0.0

    intersection = concepts_a & concepts_b
    union = concepts_a | concepts_b

    if not union:
        return 0.0

    return len(intersection) / len(union)


# ============================================================
# HTTP METHOD SIMILARITY
# ============================================================

def method_similarity(
    finding_a: Finding,
    finding_b: Finding
) -> float:

    method_a = normalize_text(
        finding_a.method
    )

    method_b = normalize_text(
        finding_b.method
    )

    if not method_a or not method_b:
        return 0.0

    if method_a == method_b:
        return 1.0

    return 0.0


# ============================================================
# SCANNER AGREEMENT
# ============================================================

def scanner_agreement(
    finding_a: Finding,
    finding_b: Finding
) -> float:

    if (
        finding_a.scanner
        == finding_b.scanner
    ):
        return 0.0

    return 1.0


# ============================================================
# FEATURE EXTRACTION
# ============================================================

def extract_features(
    finding_a: Finding,
    finding_b: Finding
) -> Dict:

    return {

        "endpoint_similarity":
            round(
                endpoint_similarity(
                    finding_a,
                    finding_b
                ),
                3
            ),

        "name_similarity":
            round(
                name_similarity(
                    finding_a,
                    finding_b
                ),
                3
            ),

        "concept_similarity":
            round(
                concept_similarity(
                    finding_a,
                    finding_b
                ),
                3
            ),

        "method_similarity":
            round(
                method_similarity(
                    finding_a,
                    finding_b
                ),
                3
            ),

        "scanner_agreement":
            round(
                scanner_agreement(
                    finding_a,
                    finding_b
                ),
                3
            ),
    }


# ============================================================
# CORRELATION SCORE
# ============================================================

def calculate_correlation_score(
    features: Dict
) -> float:

    score = (

        0.35
        * features["endpoint_similarity"]

        +

        0.30
        * features["name_similarity"]

        +

        0.25
        * features["concept_similarity"]

        +

        0.05
        * features["method_similarity"]

        +

        0.05
        * features["scanner_agreement"]

    )

    return round(score, 3)


# ============================================================
# RELATIONSHIP CLASSIFICATION
# ============================================================

def classify_relationship(
    score: float,
    features: Dict
) -> str:

    endpoint = features[
        "endpoint_similarity"
    ]

    name = features[
        "name_similarity"
    ]

    concept = features[
        "concept_similarity"
    ]

    # Strong duplicate evidence.
    if (
        score >= 0.80
        and name >= 0.80
        and endpoint >= 0.80
    ):
        return "DUPLICATE"

    # Related requires semantic evidence.
    # Endpoint similarity alone is not enough.
    if score >= 0.45:

        if (
            name >= 0.25
            or concept >= 0.50
        ):
            return "RELATED"

    return "INDEPENDENT"


# ============================================================
# CORRELATION ENGINE
# ============================================================

def correlate_findings(
    findings: List[Finding]
) -> List[Dict]:

    relationships = []

    for i in range(
        len(findings)
    ):

        for j in range(
            i + 1,
            len(findings)
        ):

            finding_a = findings[i]
            finding_b = findings[j]

            # Only cross-scanner comparison.
            if (
                finding_a.scanner
                == finding_b.scanner
            ):
                continue

            features = extract_features(
                finding_a,
                finding_b
            )

            score = calculate_correlation_score(
                features
            )

            relationship = classify_relationship(
                score,
                features
            )

            if relationship in {
                "DUPLICATE",
                "RELATED",
            }:

                relationships.append(
                    {
                        "relationship":
                            relationship,

                        "score":
                            score,

                        "features":
                            features,

                        "finding_a":
                            finding_a,

                        "finding_b":
                            finding_b,
                    }
                )

    return relationships


# ============================================================
# RESULT DISPLAY
# ============================================================

def print_results(
    relationships: List[Dict]
):

    duplicate_count = 0
    related_count = 0

    print()
    print("=" * 70)
    print("CORRELATION ENGINE V2")
    print("=" * 70)
    print()

    for relation in relationships:

        finding_a = relation[
            "finding_a"
        ]

        finding_b = relation[
            "finding_b"
        ]

        relationship = relation[
            "relationship"
        ]

        score = relation[
            "score"
        ]

        features = relation[
            "features"
        ]

        if relationship == "DUPLICATE":

            duplicate_count += 1

        elif relationship == "RELATED":

            related_count += 1

        print(
            f"[{relationship}] "
            f"{finding_a.finding_id} "
            f"<-> "
            f"{finding_b.finding_id}"
        )

        print(
            f"A: {finding_a.name}"
        )

        print(
            f"B: {finding_b.name}"
        )

        print(
            f"A URL: {finding_a.url}"
        )

        print(
            f"B URL: {finding_b.url}"
        )

        print(
            f"Correlation Score: "
            f"{score}"
        )

        print("Features:")

        for key, value in features.items():

            print(
                f"  {key}: {value}"
            )

        print("-" * 70)

    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)

    print(
        f"Duplicate relationships: "
        f"{duplicate_count}"
    )

    print(
        f"Related relationships: "
        f"{related_count}"
    )

    print(
        f"Total correlations: "
        f"{len(relationships)}"
    )

    print("=" * 70)


# ============================================================
# DIAGNOSTIC: TOP CORRELATION CANDIDATES
# ============================================================

def print_top_candidates(
    findings: List[Finding],
    limit: int = 10
):

    candidates = []

    for i in range(
        len(findings)
    ):

        for j in range(
            i + 1,
            len(findings)
        ):

            finding_a = findings[i]
            finding_b = findings[j]

            # Only cross-scanner comparison.
            if (
                finding_a.scanner
                == finding_b.scanner
            ):
                continue

            features = extract_features(
                finding_a,
                finding_b
            )

            score = calculate_correlation_score(
                features
            )

            candidates.append(
                (
                    score,
                    finding_a,
                    finding_b,
                    features
                )
            )

    # Highest scores first.
    candidates.sort(
        key=lambda item: item[0],
        reverse=True
    )

    print()
    print("=" * 70)
    print("TOP CORRELATION CANDIDATES")
    print("=" * 70)

    for rank, item in enumerate(
        candidates[:limit],
        start=1
    ):

        score, finding_a, finding_b, features = item

        print()
        print(
            f"#{rank} | Score: {score}"
        )

        print(
            f"A: "
            f"{finding_a.finding_id} | "
            f"{finding_a.scanner} | "
            f"{finding_a.name}"
        )

        print(
            f"B: "
            f"{finding_b.finding_id} | "
            f"{finding_b.scanner} | "
            f"{finding_b.name}"
        )

        print(
            f"A URL: "
            f"{finding_a.url}"
        )

        print(
            f"B URL: "
            f"{finding_b.url}"
        )

        print(
            f"Endpoint: "
            f"{features['endpoint_similarity']}"
        )

        print(
            f"Name: "
            f"{features['name_similarity']}"
        )

        print(
            f"Concept: "
            f"{features['concept_similarity']}"
        )

        print(
            f"Method: "
            f"{features['method_similarity']}"
        )

        print(
            f"Scanner: "
            f"{features['scanner_agreement']}"
        )

        print("-" * 70)


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "Loading ZAP findings..."
    )

    zap_findings = parse_zap_results()

    print(
        f"ZAP findings loaded: "
        f"{len(zap_findings)}"
    )

    print()

    print(
        "Loading Nuclei findings..."
    )

    nuclei_findings = (
        parse_nuclei_results()
    )

    print(
        f"Nuclei findings loaded: "
        f"{len(nuclei_findings)}"
    )

    print()

    all_findings = (
        zap_findings
        + nuclei_findings
    )

    print(
        f"Total findings: "
        f"{len(all_findings)}"
    )

    relationships = correlate_findings(
        all_findings
    )

    print_results(
        relationships
    )

    # Diagnostic analysis.
    print_top_candidates(
        all_findings,
        limit=10
    )


if __name__ == "__main__":

    main()