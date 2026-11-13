import re
from html import unescape
from pathlib import Path

from finding_schema import Finding


DEFAULT_INPUT_FILE = Path(
    "results/webgoat-zap-report.html"
)

SEVERITY_MAP = {
    "3": "high",
    "2": "medium",
    "1": "low",
    "0": "informational",
}


def clean_html(text):
    if not text:
        return ""

    text = unescape(text)

    text = re.sub(
        r"<[^>]+>",
        "",
        text
    )

    return text.strip()


def extract_alert_blocks(html):
    pattern = re.compile(
        r'<th class="risk-(\d)">'
        r'\s*([^<]+)'
        r'\s*</th>'
        r'(.*?)(?=<th class="risk-\d">|\Z)',
        re.IGNORECASE | re.DOTALL,
    )

    return pattern.findall(html)


def extract_field(block, field_name):
    pattern = re.compile(
        rf'<td width="20%"[^>]*>'
        rf'\s*{re.escape(field_name)}'
        rf'\s*</td>'
        rf'\s*<td width="80%">(.*?)</td>',
        re.IGNORECASE | re.DOTALL,
    )

    match = pattern.search(block)

    if not match:
        return None

    value = match.group(1)

    if field_name.lower() == "url":

        href_match = re.search(
            r'href="([^"]+)"',
            value,
            re.IGNORECASE,
        )

        if href_match:
            return unescape(
                href_match.group(1)
            ).strip()

    return clean_html(value)


def parse_webgoat_zap_results(
    input_file=DEFAULT_INPUT_FILE
):

    input_file = Path(input_file)

    if not input_file.exists():
        raise FileNotFoundError(
            f"WebGoat ZAP report not found: "
            f"{input_file}"
        )

    html = input_file.read_text(
        encoding="utf-8"
    )

    blocks = extract_alert_blocks(html)

    findings = []
    seen = set()

    for risk_level, alert_name, block in blocks:

        alert_name = clean_html(
            alert_name
        )

        if not alert_name:
            continue

        if alert_name in seen:
            continue

        seen.add(alert_name)

        severity = SEVERITY_MAP.get(
            risk_level,
            "unknown"
        )

        url = extract_field(
            block,
            "URL"
        )

        method = extract_field(
            block,
            "Method"
        )

        parameter = extract_field(
            block,
            "Parameter"
        )

        evidence = extract_field(
            block,
            "Evidence"
        )

        evidence_parts = []

        if evidence:
            evidence_parts.append(
                f"Evidence: {evidence}"
            )

        if parameter:
            evidence_parts.append(
                f"Parameter: {parameter}"
            )

        evidence_parts.append(
            f"Risk level: {risk_level}"
        )

        combined_evidence = "\n".join(
            evidence_parts
        )

        finding = Finding(

            finding_id=(
                f"ZAP-WG-{len(findings) + 1:04d}"
            ),

            scanner="zap",

            name=alert_name,

            severity=severity,

            target=(
                "http://127.0.0.1:8080"
            ),

            method=method,

            url=url,

            confidence=None,

            evidence=combined_evidence,

            description=None,

            category="web-vulnerability",
        )

        findings.append(finding)

    return findings


if __name__ == "__main__":

    findings = parse_webgoat_zap_results()

    print(
        f"Total WebGoat ZAP findings parsed: "
        f"{len(findings)}"
    )

    print()

    for finding in findings:

        print(
            f"{finding.finding_id} | "
            f"{finding.severity} | "
            f"{finding.name}"
        )

        print(
            f"  Method: {finding.method}"
        )

        print(
            f"  URL: {finding.url}"
        )

        print(
            f"  Evidence: {finding.evidence}"
        )

        print()
