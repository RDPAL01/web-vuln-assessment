from typing import Dict

from finding_schema import Finding


def normalize_text(text: str) -> str:
    if not text:
        return ""

    return " ".join(
        text.lower().strip().split()
    )


def normalize_url(url: str) -> str:
    if not url:
        return ""

    return url.lower().strip().rstrip("/")


def url_similarity(
    finding_a: Finding,
    finding_b: Finding
) -> float:

    url_a = normalize_url(finding_a.url)
    url_b = normalize_url(finding_b.url)

    if not url_a or not url_b:
        return 0.0

    if url_a == url_b:
        return 1.0

    return 0.0


def name_similarity(
    finding_a: Finding,
    finding_b: Finding
) -> float:

    name_a = normalize_text(finding_a.name)
    name_b = normalize_text(finding_b.name)

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

    return len(intersection) / len(union)


def concept_similarity(
    finding_a: Finding,
    finding_b: Finding
) -> float:

    text_a = normalize_text(
        " ".join(
            [
                finding_a.name or "",
                finding_a.description or "",
                finding_a.category or "",
            ]
        )
    )

    text_b = normalize_text(
        " ".join(
            [
                finding_b.name or "",
                finding_b.description or "",
                finding_b.category or "",
            ]
        )
    )

    if not text_a or not text_b:
        return 0.0

    words_a = set(text_a.split())
    words_b = set(text_b.split())

    intersection = words_a & words_b
    union = words_a | words_b

    if not union:
        return 0.0

    return len(intersection) / len(union)


def calculate_similarity(
    finding_a: Finding,
    finding_b: Finding
) -> Dict:

    url_score = url_similarity(
        finding_a,
        finding_b
    )

    name_score = name_similarity(
        finding_a,
        finding_b
    )

    concept_score = concept_similarity(
        finding_a,
        finding_b
    )

    # Same URL alone must not create
    # a RELATED relationship.
    if (
        url_score == 1.0
        and name_score == 0.0
        and concept_score == 0.0
    ):
        final_score = 0.0

    else:
        final_score = (
            0.40 * url_score
            + 0.35 * name_score
            + 0.25 * concept_score
        )

    return {
        "url_score": round(url_score, 3),
        "name_score": round(name_score, 3),
        "concept_score": round(concept_score, 3),
        "final_score": round(final_score, 3),
    }


def classify_similarity(
    score: float,
    url_score: float,
    name_score: float,
    concept_score: float
) -> str:

    # Duplicate requires strong name similarity.
    if (
        score >= 0.80
        and name_score >= 0.80
    ):
        return "DUPLICATE"

    # Same URL alone is NOT enough.
    if url_score == 1.0:

        # At least one meaningful semantic
        # similarity signal is required.
        if (
            name_score >= 0.25
            or concept_score >= 0.20
        ):
            if score >= 0.45:
                return "RELATED"

    return "INDEPENDENT"


if __name__ == "__main__":

    from zap_parser import parse_zap_results
    from nuclei_parser import parse_nuclei_results

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
        zap_findings
        + nuclei_findings
    )

    print(
        f"Total findings: "
        f"{len(all_findings)}"
    )

    print()

    duplicate_count = 0
    related_count = 0

    # ---------------------------------------------------------
    # MAIN CROSS-SCANNER COMPARISON
    # ---------------------------------------------------------

    for i in range(len(all_findings)):

        for j in range(i + 1, len(all_findings)):

            finding_a = all_findings[i]
            finding_b = all_findings[j]

            # Only compare findings from different scanners.
            if (
                finding_a.scanner
                == finding_b.scanner
            ):
                continue

            result = calculate_similarity(
                finding_a,
                finding_b
            )

            relationship = classify_similarity(
                result["final_score"],
                result["url_score"],
                result["name_score"],
                result["concept_score"]
            )

            if relationship == "DUPLICATE":

                duplicate_count += 1

            elif relationship == "RELATED":

                related_count += 1

            else:

                continue

            print(
                f"[{relationship}] "
                f"{finding_a.finding_id} ↔ "
                f"{finding_b.finding_id}"
            )

            print(
                f"  Score: "
                f"{result['final_score']}"
            )

            print(
                f"  URL: "
                f"{result['url_score']} | "
                f"Name: "
                f"{result['name_score']} | "
                f"Concept: "
                f"{result['concept_score']}"
            )

            print(
                f"  A: {finding_a.name}"
            )

            print(
                f"  B: {finding_b.name}"
            )

            print(
                f"  A URL: {finding_a.url}"
            )

            print(
                f"  B URL: {finding_b.url}"
            )

            print("-" * 70)

    # ---------------------------------------------------------
    # SUMMARY
    # ---------------------------------------------------------

    print()

    print("=" * 70)
    print("SIMILARITY RESULTS")
    print("=" * 70)

    print(
        f"Duplicate relationships: "
        f"{duplicate_count}"
    )

    print(
        f"Related relationships: "
        f"{related_count}"
    )

    print("=" * 70)

    # ---------------------------------------------------------
    # DETAILED RELATED RELATIONSHIPS
    # ---------------------------------------------------------

    print()
    print("ALL RELATED RELATIONSHIPS")
    print("=" * 70)

    for i in range(len(all_findings)):

        for j in range(i + 1, len(all_findings)):

            finding_a = all_findings[i]
            finding_b = all_findings[j]

            if (
                finding_a.scanner
                == finding_b.scanner
            ):
                continue

            result = calculate_similarity(
                finding_a,
                finding_b
            )

            relationship = classify_similarity(
                result["final_score"],
                result["url_score"],
                result["name_score"],
                result["concept_score"]
            )

            if relationship != "RELATED":
                continue

            print()

            print(
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
                f"URL Score: "
                f"{result['url_score']}"
            )

            print(
                f"Name Score: "
                f"{result['name_score']}"
            )

            print(
                f"Concept Score: "
                f"{result['concept_score']}"
            )

            print(
                f"Final Score: "
                f"{result['final_score']}"
            )

            print("-" * 70)