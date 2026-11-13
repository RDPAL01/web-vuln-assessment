"""
Correlation Engine V3
---------------------

Conservative cross-scanner correlation engine for the
Automated Web Vulnerability Assessment Framework.

Scanners:
    - OWASP ZAP
    - Nuclei

Goals:
    1. Compare findings from different scanners.
    2. Avoid generic concept-based false correlations.
    3. Use concrete vulnerability names/evidence.
    4. Identify DUPLICATE and RELATED findings.
"""

from pathlib import Path
import sys
import re
from typing import Optional, Dict, List

# ---------------------------------------------------------------------
# Project path
# ---------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# ---------------------------------------------------------------------
# Import common finding schema
# ---------------------------------------------------------------------

from src.finding_schema import Finding


# =====================================================================
# TEXT NORMALIZATION
# =====================================================================

def normalize_text(text: Optional[str]) -> str:
    """
    Normalize text for comparison.
    """

    if not text:
        return ""

    text = str(text).lower()

    # Replace punctuation with spaces
    text = re.sub(r"[^a-z0-9]+", " ", text)

    # Normalize whitespace
    text = re.sub(r"\s+", " ", text).strip()

    return text


# =====================================================================
# URL NORMALIZATION
# =====================================================================

def normalize_url(url: Optional[str]) -> str:
    """
    Normalize URLs so scanner-specific formatting does not
    prevent endpoint comparison.
    """

    if not url:
        return ""

    url = str(url).strip()

    # Remove fragment
    url = url.split("#")[0]

    # Remove trailing slash
    if len(url) > 1:
        url = url.rstrip("/")

    return url.lower()


# =====================================================================
# ENDPOINT EXTRACTION
# =====================================================================

def extract_endpoint(url: Optional[str]) -> str:
    """
    Extract endpoint/path from a URL.

    Example:
        http://localhost:3000/rest/products/search?q=test

    becomes:
        /rest/products/search
    """

    if not url:
        return ""

    url = normalize_url(url)

    # Remove scheme
    url = re.sub(r"^https?://", "", url)

    # Remove host
    parts = url.split("/", 1)

    if len(parts) == 1:
        return "/"

    path = "/" + parts[1]

    # Remove query parameters
    path = path.split("?", 1)[0]

    # Remove fragment
    path = path.split("#", 1)[0]

    # Normalize trailing slash
    if path != "/":
        path = path.rstrip("/")

    return path.lower()


# =====================================================================
# ENDPOINT SIMILARITY
# =====================================================================

def endpoint_similarity(
    url_a: Optional[str],
    url_b: Optional[str]
) -> float:
    """
    Compare two finding endpoints.

    Returns:
        1.0 -> exact endpoint match
        0.0 -> different endpoints
    """

    endpoint_a = extract_endpoint(url_a)
    endpoint_b = extract_endpoint(url_b)

    if not endpoint_a or not endpoint_b:
        return 0.0

    if endpoint_a == endpoint_b:
        return 1.0

    return 0.0


# =====================================================================
# TOKEN / NAME SIMILARITY
# =====================================================================

def tokenize(text: Optional[str]) -> set:
    """
    Convert text into normalized tokens.
    """

    normalized = normalize_text(text)

    if not normalized:
        return set()

    return set(normalized.split())


def jaccard_similarity(
    text_a: Optional[str],
    text_b: Optional[str]
) -> float:
    """
    Calculate Jaccard similarity between two strings.
    """

    tokens_a = tokenize(text_a)
    tokens_b = tokenize(text_b)

    if not tokens_a or not tokens_b:
        return 0.0

    intersection = tokens_a.intersection(tokens_b)
    union = tokens_a.union(tokens_b)

    if not union:
        return 0.0

    return len(intersection) / len(union)


# =====================================================================
# SECURITY CONCEPTS
# =====================================================================

SECURITY_CONCEPTS = {
    "csp": [
        "content security policy",
        "csp",
    ],

    "hsts": [
        "strict transport security",
        "hsts",
    ],

    "x_content_type_options": [
        "x content type options",
        "content type options",
    ],

    "anti_clickjacking": [
        "anti clickjacking",
        "x frame options",
        "clickjacking",
    ],

    "session_url": [
        "session id in url",
        "session id in url rewrite",
    ],

    "cross_domain": [
        "cross domain",
        "cross domain misconfiguration",
    ],

    "private_ip": [
        "private ip",
        "private ip disclosure",
    ],

    "timestamp": [
        "timestamp disclosure",
        "unix timestamp",
    ],

    "sql_injection": [
        "sql injection",
        "sqli",
    ],

    "prometheus": [
        "prometheus",
        "prometheus metrics",
    ],

    "robots": [
        "robots txt",
        "robots",
    ],

    "security_txt": [
        "security txt",
        "security.txt",
    ],
}


def detect_security_concepts(text: Optional[str]) -> set:
    """
    Detect concrete security concepts in a finding name/evidence.
    """

    normalized = normalize_text(text)

    if not normalized:
        return set()

    detected = set()

    for concept, keywords in SECURITY_CONCEPTS.items():

        for keyword in keywords:

            keyword_normalized = normalize_text(keyword)

            if keyword_normalized in normalized:
                detected.add(concept)
                break

    return detected


def concept_similarity(
    finding_a: Finding,
    finding_b: Finding
) -> float:
    """
    Compare concrete security concepts.

    Important:
        Generic 'security header' is NOT treated as a concrete
        vulnerability concept.
    """

    text_a = " ".join([
        finding_a.name or "",
        finding_a.description or "",
        finding_a.evidence or "",
    ])

    text_b = " ".join([
        finding_b.name or "",
        finding_b.description or "",
        finding_b.evidence or "",
    ])

    concepts_a = detect_security_concepts(text_a)
    concepts_b = detect_security_concepts(text_b)

    if not concepts_a or not concepts_b:
        return 0.0

    intersection = concepts_a.intersection(concepts_b)
    union = concepts_a.union(concepts_b)

    if not union:
        return 0.0

    return len(intersection) / len(union)


# =====================================================================
# EVIDENCE SIMILARITY
# =====================================================================

def evidence_similarity(
    evidence_a: Optional[str],
    evidence_b: Optional[str]
) -> float:
    """
    Compare scanner evidence.

    Exact concrete evidence gets strong similarity.
    """

    if not evidence_a or not evidence_b:
        return 0.0

    a = normalize_text(evidence_a)
    b = normalize_text(evidence_b)

    if not a or not b:
        return 0.0

    if a == b:
        return 1.0

    return jaccard_similarity(a, b)


# =====================================================================
# METHOD SIMILARITY
# =====================================================================

def method_similarity(
    method_a: Optional[str],
    method_b: Optional[str]
) -> float:
    """
    Compare HTTP methods.
    """

    if not method_a or not method_b:
        return 0.0

    a = method_a.upper().strip()
    b = method_b.upper().strip()

    if a == b:
        return 1.0

    return 0.0


# =====================================================================
# SCANNER SIMILARITY
# =====================================================================

def scanner_similarity(
    scanner_a: Optional[str],
    scanner_b: Optional[str]
) -> float:
    """
    Scanner similarity.

    Cross-scanner correlation is the main goal, therefore:
        different scanners -> 1.0
        same scanner       -> 0.0
    """

    if not scanner_a or not scanner_b:
        return 0.0

    a = normalize_text(scanner_a)
    b = normalize_text(scanner_b)

    if a == b:
        return 0.0

    return 1.0


# =====================================================================
# CONCRETE EVIDENCE EXTRACTION
# =====================================================================

def extract_concrete_evidence(
    finding: Finding
) -> str:
    """
    Extract useful concrete evidence.

    Priority:
        1. Explicit evidence
        2. Finding name
    """

    if finding.evidence:
        return normalize_text(finding.evidence)

    return normalize_text(finding.name)


# =====================================================================
# METRIC CALCULATION
# =====================================================================

def calculate_metrics(
    finding_a: Finding,
    finding_b: Finding
) -> Dict[str, float]:

    endpoint = endpoint_similarity(
        finding_a.url,
        finding_b.url
    )

    name = jaccard_similarity(
        finding_a.name,
        finding_b.name
    )

    concept = concept_similarity(
        finding_a,
        finding_b
    )

    evidence = evidence_similarity(
        finding_a.evidence,
        finding_b.evidence
    )

    method = method_similarity(
        finding_a.method,
        finding_b.method
    )

    scanner = scanner_similarity(
        finding_a.scanner,
        finding_b.scanner
    )

    # Weighted score
    score = (
        endpoint * 0.25 +
        name * 0.25 +
        concept * 0.15 +
        evidence * 0.25 +
        method * 0.05 +
        scanner * 0.05
    )

    return {
        "endpoint": round(endpoint, 4),
        "name": round(name, 4),
        "concept": round(concept, 4),
        "evidence": round(evidence, 4),
        "method": round(method, 4),
        "scanner": round(scanner, 4),
        "score": round(score, 4),
    }


# =====================================================================
# CONCRETE VULNERABILITY MATCHING
# =====================================================================

CONCRETE_MATCH_GROUPS = [

    # Content Security Policy
    (
        [
            "content security policy",
            "csp",
        ],
        [
            "content security policy",
            "csp",
        ],
    ),

    # HSTS
    (
        [
            "strict transport security",
            "hsts",
        ],
        [
            "strict transport security",
            "hsts",
        ],
    ),

    # X-Content-Type-Options
    (
        [
            "x content type options",
            "content type options",
        ],
        [
            "x content type options",
            "content type options",
        ],
    ),

    # Clickjacking
    (
        [
            "anti clickjacking",
            "clickjacking",
        ],
        [
            "x frame options",
            "clickjacking",
        ],
    ),

    # Session ID in URL
    (
        [
            "session id in url",
            "session id in url rewrite",
        ],
        [
            "session id in url",
            "session id in url rewrite",
        ],
    ),

    # Cross-domain
    (
        [
            "cross domain misconfiguration",
            "cross domain",
        ],
        [
            "cross domain misconfiguration",
            "cross domain",
        ],
    ),

    # Private IP
    (
        [
            "private ip disclosure",
            "private ip",
        ],
        [
            "private ip disclosure",
            "private ip",
        ],
    ),

    # Timestamp
    (
        [
            "timestamp disclosure",
            "unix timestamp",
        ],
        [
            "timestamp disclosure",
            "unix timestamp",
        ],
    ),

    # SQL Injection
    (
        [
            "sql injection",
            "sqli",
        ],
        [
            "sql injection",
            "sqli",
        ],
    ),

    # Prometheus
    (
        [
            "prometheus",
            "prometheus metrics",
        ],
        [
            "prometheus",
            "prometheus metrics",
        ],
    ),
]


def contains_any(
    text: str,
    keywords: List[str]
) -> bool:

    normalized = normalize_text(text)

    for keyword in keywords:

        keyword_normalized = normalize_text(keyword)

        if keyword_normalized in normalized:
            return True

    return False


def concrete_vulnerability_match(
    finding_a: Finding,
    finding_b: Finding
) -> bool:

    text_a = " ".join([
        finding_a.name or "",
        finding_a.evidence or "",
    ])

    text_b = " ".join([
        finding_b.name or "",
        finding_b.evidence or "",
    ])

    for keywords_a, keywords_b in CONCRETE_MATCH_GROUPS:

        if (
            contains_any(text_a, keywords_a)
            and
            contains_any(text_b, keywords_b)
        ):
            return True

        if (
            contains_any(text_a, keywords_b)
            and
            contains_any(text_b, keywords_a)
        ):
            return True

    return False


# =====================================================================
# CORRELATION CLASSIFICATION
# =====================================================================

def classify_correlation(
    metrics: Dict[str, float],
    finding_a: Finding,
    finding_b: Finding
) -> Optional[str]:

    endpoint = metrics["endpoint"]
    name = metrics["name"]
    concept = metrics["concept"]
    evidence = metrics["evidence"]
    score = metrics["score"]

    name_a = normalize_text(
        finding_a.name
    )

    name_b = normalize_text(
        finding_b.name
    )

    evidence_a = normalize_text(
        finding_a.evidence or ""
    )

    evidence_b = normalize_text(
        finding_b.evidence or ""
    )

    # ---------------------------------------------------------
    # RULE 1
    # Exact concrete evidence match
    # ---------------------------------------------------------

    if (
        evidence_a
        and evidence_b
        and evidence_a == evidence_b
        and endpoint >= 0.80
    ):

        if score >= 0.60:
            return "DUPLICATE"

    # ---------------------------------------------------------
    # RULE 2
    # Different evidence alone does NOT mean different finding.
    #
    # Different scanners may report the same vulnerability
    # using completely different evidence formats.
    #
    # Example:
    #
    # ZAP:
    #     Risk level: 2
    #
    # Nuclei:
    #     content-security-policy
    #     HTTP request/response
    #
    # These can still represent the same vulnerability.
    #
    # Therefore, only block correlation when evidence differs
    # AND there is no concrete vulnerability match.
    # ---------------------------------------------------------

    evidence_conflict = (
        evidence_a
        and evidence_b
        and evidence_a != evidence_b
    )

    concrete_match = concrete_vulnerability_match(
        finding_a,
        finding_b
    )

    if evidence_conflict and not concrete_match:
        return None

    # ---------------------------------------------------------
    # RULE 3
    # Strong name + endpoint match
    # ---------------------------------------------------------

    if (
        endpoint >= 0.80
        and name >= 0.80
        and score >= 0.65
    ):
        return "DUPLICATE"

    # ---------------------------------------------------------
    # RULE 4
    # Concrete vulnerability match
    # ---------------------------------------------------------

    if (
        endpoint >= 0.80
        and concrete_match
    ):

        # If names are sufficiently similar -> duplicate
        if name >= 0.50:
            return "DUPLICATE"

        # Same concrete vulnerability identified
        # differently by different scanners.
        return "RELATED"

    # ---------------------------------------------------------
    # RULE 5
    # Same concrete concept with no conflicting evidence
    # ---------------------------------------------------------

    if (
        endpoint >= 0.80
        and concept >= 0.80
        and name >= 0.40
        and score >= 0.50
    ):
        return "RELATED"

    # ---------------------------------------------------------
    # RULE 6
    # No generic concept-only correlation
    #
    # IMPORTANT:
    #
    # CSP ↔ Permissions-Policy
    # CSP ↔ Referrer-Policy
    # CSP ↔ X-Recruiting
    #
    # must NOT correlate merely because they are all
    # security-related findings.
    # ---------------------------------------------------------

    return None


# =====================================================================
# FINDING CORRELATION
# =====================================================================

def correlate_findings(
    findings: List[Finding]
) -> List[Dict]:

    correlations = []

    total = len(findings)

    for i in range(total):

        finding_a = findings[i]

        for j in range(i + 1, total):

            finding_b = findings[j]

            # -----------------------------------------------------
            # Only correlate different scanners
            # -----------------------------------------------------

            if normalize_text(
                finding_a.scanner
            ) == normalize_text(
                finding_b.scanner
            ):
                continue

            metrics = calculate_metrics(
                finding_a,
                finding_b
            )

            relation = classify_correlation(
                metrics,
                finding_a,
                finding_b
            )

            if relation is None:
                continue

            correlations.append({
                "type": relation,

                "finding_a": finding_a,

                "finding_b": finding_b,

                "metrics": metrics,
            })

    return correlations


# =====================================================================
# LOAD ZAP FINDINGS
# =====================================================================

def load_zap_findings() -> List[Finding]:

    from src.zap_parser import parse_zap_results

    try:

        findings = parse_zap_results()

        return findings

    except Exception as exc:

        print(
            f"ERROR loading ZAP findings: {exc}"
        )

        return []


# =====================================================================
# LOAD NUCLEI FINDINGS
# =====================================================================

def load_nuclei_findings() -> List[Finding]:

    from src.nuclei_parser import parse_nuclei_results

    try:

        findings = parse_nuclei_results()

        return findings

    except Exception as exc:

        print(
            f"ERROR loading Nuclei findings: {exc}"
        )

        return []


# =====================================================================
# DISPLAY CORRELATION
# =====================================================================

def print_correlation(
    correlation: Dict
) -> None:

    relation = correlation["type"]

    finding_a = correlation["finding_a"]
    finding_b = correlation["finding_b"]

    metrics = correlation["metrics"]

    print("-" * 70)

    print(relation)

    print(
        f"  A: {finding_a.scanner} | "
        f"{finding_a.name}"
    )

    print(
        f"  B: {finding_b.scanner} | "
        f"{finding_b.name}"
    )

    print(
        f"  A Evidence: "
        f"{finding_a.evidence}"
    )

    print(
        f"  B Evidence: "
        f"{finding_b.evidence}"
    )

    print()

    print(
        f"  Score: {metrics['score']}"
    )

    print(
        f"  Endpoint: {metrics['endpoint']}"
    )

    print(
        f"  Name: {metrics['name']}"
    )

    print(
        f"  Concept: {metrics['concept']}"
    )

    print(
        f"  Evidence: {metrics['evidence']}"
    )

    print(
        f"  Method: {metrics['method']}"
    )

    print(
        f"  Scanner: {metrics['scanner']}"
    )


# =====================================================================
# SUMMARY
# =====================================================================

def print_summary(
    correlations: List[Dict]
) -> None:

    duplicate_count = sum(
        1
        for c in correlations
        if c["type"] == "DUPLICATE"
    )

    related_count = sum(
        1
        for c in correlations
        if c["type"] == "RELATED"
    )

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
        f"{len(correlations)}"
    )


# =====================================================================
# MAIN
# =====================================================================

def main():

    print("=" * 70)

    print(
        "MULTI-SCANNER CORRELATION ENGINE V3"
    )

    print("=" * 70)

    # ---------------------------------------------------------
    # Load ZAP
    # ---------------------------------------------------------

    zap_findings = load_zap_findings()

    print(
        f"ZAP findings loaded: "
        f"{len(zap_findings)}"
    )

    # ---------------------------------------------------------
    # Load Nuclei
    # ---------------------------------------------------------

    nuclei_findings = load_nuclei_findings()

    print(
        f"Nuclei findings loaded: "
        f"{len(nuclei_findings)}"
    )

    # ---------------------------------------------------------
    # Combine
    # ---------------------------------------------------------

    findings = (
        zap_findings +
        nuclei_findings
    )

    print(
        f"Total findings: "
        f"{len(findings)}"
    )

    # ---------------------------------------------------------
    # Correlate
    # ---------------------------------------------------------

    correlations = correlate_findings(
        findings
    )

    # ---------------------------------------------------------
    # Summary
    # ---------------------------------------------------------

    print_summary(
        correlations
    )

    # ---------------------------------------------------------
    # Detailed correlations
    # ---------------------------------------------------------

    print()

    print("=" * 70)

    print("CORRELATIONS")

    print("=" * 70)

    if not correlations:

        print(
            "No valid cross-scanner correlations found."
        )

    else:

        for correlation in correlations:

            print_correlation(
                correlation
            )


# =====================================================================
# ENTRY POINT
# =====================================================================

if __name__ == "__main__":
    main()