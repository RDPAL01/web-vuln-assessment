import re
from pathlib import Path

from finding_schema import Finding


DEFAULT_INPUT_FILE = Path("results/zap-report.txt")


RISK_PATTERN = re.compile(
    r"^Risk=(High|Medium|Low|Informational), "
    r"Confidence=(High|Medium|Low|False Positive)"
)


REQUEST_PATTERN = re.compile(
    r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(.+)$",
    re.IGNORECASE,
)


def clean_count(text):
    return re.sub(r"\s*\(\d+\)$", "", text).strip()


def is_metadata(line):
    return (
        not line
        or line.startswith("file://")
        or line.startswith("ZAP by Checkmarx")
        or re.fullmatch(r"\d+/16", line)
        or re.fullmatch(
            r"\d{2}/\d{2}/\d{4},\s+\d{2}:\d{2}",
            line
        )
    )


def parse_zap_results(
    input_file: str | Path = DEFAULT_INPUT_FILE
):

    input_file = Path(input_file)

    if not input_file.exists():
        raise FileNotFoundError(
            f"ZAP result file not found: {input_file}"
        )

    lines = [
        line.strip()
        for line in input_file.read_text(
            encoding="utf-8"
        ).splitlines()
    ]

    findings = []

    # Find the last Alerts section
    alert_positions = [
        i
        for i, line in enumerate(lines)
        if line == "Alerts"
    ]

    if not alert_positions:
        raise RuntimeError(
            "Alerts section not found"
        )

    start = alert_positions[-1]
    i = start + 1

    current_severity = None
    current_confidence = None
    current_site = None

    while i < len(lines):

        line = lines[i]

        # Stop at Appendix
        if line == "Appendix":
            break

        # New risk/confidence block
        risk_match = RISK_PATTERN.match(line)

        if risk_match:

            current_severity = (
                risk_match.group(1).lower()
            )

            current_confidence = (
                risk_match.group(2).lower()
            )

            i += 1
            current_site = None

            continue

        # Ignore metadata
        if is_metadata(line):
            i += 1
            continue

        # Site
        if (
            line.startswith("http://")
            or line.startswith("https://")
        ):

            current_site = clean_count(line)

            i += 1

            continue

        # Alert name
        alert_name = clean_count(line)

        i += 1

        # Skip metadata
        while (
            i < len(lines)
            and is_metadata(lines[i])
        ):

            i += 1

        if i >= len(lines):
            break

        # HTTP request
        request_match = REQUEST_PATTERN.match(
            lines[i]
        )

        if not request_match:
            continue

        method = request_match.group(1).upper()

        url = request_match.group(2)

        i += 1

        # Join wrapped URL
        while i < len(lines):

            continuation = lines[i]

            if not continuation:
                break

            if continuation == "Appendix":
                break

            if RISK_PATTERN.match(
                continuation
            ):
                break

            if REQUEST_PATTERN.match(
                continuation
            ):
                break

            if continuation.startswith(
                (
                    "http://",
                    "https://",
                    "file://",
                )
            ):
                break

            if (
                continuation.startswith("&")
                or continuation.startswith("?")
                or "=" in continuation
            ):

                url += continuation

                i += 1

            else:
                break

        # Create normalized Finding object
        finding = Finding(

            finding_id=(
                f"ZAP-{len(findings) + 1:04d}"
            ),

            scanner="zap",

            name=alert_name,

            severity=current_severity,

            target=current_site,

            method=method,

            url=url,

            confidence=current_confidence,
        )

        findings.append(finding)

    return findings


if __name__ == "__main__":

    findings = parse_zap_results()

    print(
        f"Total ZAP findings parsed: "
        f"{len(findings)}"
    )

    print()

    for finding in findings:

        print(
            f"{finding.finding_id} | "
            f"{finding.severity} | "
            f"{finding.confidence} | "
            f"{finding.name} | "
            f"{finding.method} "
            f"{finding.url}"
        )