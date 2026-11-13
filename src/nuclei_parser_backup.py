import json
from pathlib import Path

from finding_schema import Finding


INPUT_FILE = Path("results/nuclei-results.jsonl")


def extract_evidence(data: dict) -> str | None:
    """
    Extract useful evidence from a Nuclei JSON result.

    Nuclei output structure can vary between templates,
    so several possible fields are checked.
    """

    possible_fields = [
        "matcher-name",
        "matched-at",
        "extracted-results",
        "curl-command",
        "request",
        "response",
    ]

    evidence_parts = []

    for field in possible_fields:

        value = data.get(field)

        if value is None:
            continue

        if isinstance(value, list):

            for item in value:

                if item is not None:
                    evidence_parts.append(
                        str(item)
                    )

        elif isinstance(value, dict):

            evidence_parts.append(
                json.dumps(
                    value,
                    ensure_ascii=False
                )
            )

        else:

            evidence_parts.append(
                str(value)
            )

    if not evidence_parts:
        return None

    return "\n".join(
        evidence_parts
    )


def extract_http_method(data: dict) -> str | None:
    """
    Try to extract HTTP method from Nuclei output.
    """

    method = data.get("method")

    if method:
        return str(method).upper()

    request = data.get("request")

    if isinstance(request, str):

        first_line = request.splitlines()

        if first_line:

            parts = first_line[0].split()

            if parts:

                possible_method = parts[0].upper()

                valid_methods = {
                    "GET",
                    "POST",
                    "PUT",
                    "DELETE",
                    "PATCH",
                    "HEAD",
                    "OPTIONS",
                }

                if possible_method in valid_methods:
                    return possible_method

    return None


def extract_category(info: dict) -> str | None:
    """
    Extract Nuclei template category/type.
    """

    template_type = info.get("type")

    if template_type:
        return str(template_type)

    return None


def extract_description(info: dict) -> str | None:

    description = info.get(
        "description"
    )

    if description:
        return str(description)

    return None


def parse_nuclei_results():

    findings = []

    if not INPUT_FILE.exists():

        raise FileNotFoundError(
            f"Nuclei result file not found: "
            f"{INPUT_FILE}"
        )

    with INPUT_FILE.open(
        "r",
        encoding="utf-8"
    ) as file:

        for line_number, line in enumerate(
            file,
            start=1
        ):

            line = line.strip()

            if not line:
                continue

            try:

                data = json.loads(
                    line
                )

            except json.JSONDecodeError:

                print(
                    f"Warning: Invalid JSON "
                    f"at line {line_number}"
                )

                continue

            info = data.get(
                "info",
                {}
            )

            finding_id = (
                f"NCL-{len(findings) + 1:04d}"
            )

            finding = Finding(

                finding_id=finding_id,

                scanner="nuclei",

                name=info.get(
                    "name",
                    "Unknown"
                ),

                severity=info.get(
                    "severity",
                    "unknown"
                ),

                target=data.get(
                    "host"
                ),

                method=extract_http_method(
                    data
                ),

                url=data.get(
                    "matched-at"
                ),

                confidence=None,

                template_id=data.get(
                    "template-id"
                ),

                evidence=extract_evidence(
                    data
                ),

                description=extract_description(
                    info
                ),

                category=extract_category(
                    info
                ),
            )

            findings.append(
                finding
            )

    return findings


if __name__ == "__main__":

    findings = parse_nuclei_results()

    print(
        f"Total Nuclei findings parsed: "
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
            f"  URL: "
            f"{finding.url}"
        )

        print(
            f"  Method: "
            f"{finding.method}"
        )

        print(
            f"  Template: "
            f"{finding.template_id}"
        )

        print(
            f"  Category: "
            f"{finding.category}"
        )

        if finding.evidence:

            print(
                f"  Evidence: "
                f"{finding.evidence}"
            )

        print(
            "-" * 70
        )