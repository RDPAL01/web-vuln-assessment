import json
from pathlib import Path

from finding_schema import Finding


DEFAULT_INPUT_FILE = Path(
    "results/nuclei-results.jsonl"
)


def extract_evidence(data: dict) -> str | None:
    """
    Extract useful evidence from a Nuclei JSON result.
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

    return "\n".join(evidence_parts)


def extract_http_method(data: dict) -> str | None:
    """
    Extract HTTP method from Nuclei output.
    """

    method = data.get("method")

    if method:
        return str(method).upper()

    request = data.get("request")

    if isinstance(request, str):

        for line in request.splitlines():

            line = line.strip()

            if not line:
                continue

            parts = line.split()

            if not parts:
                continue

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


def extract_request_path(data: dict) -> str | None:
    """
    Extract the HTTP request path from Nuclei request evidence.

    Example:

        GET /WebGoat/ HTTP/1.1

    returns:

        /WebGoat/
    """

    request = data.get("request")

    if not isinstance(request, str):
        return None

    valid_methods = {
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "PATCH",
        "HEAD",
        "OPTIONS",
    }

    for line in request.splitlines():

        line = line.strip()

        if not line:
            continue

        parts = line.split()

        if len(parts) < 2:
            continue

        method = parts[0].upper()

        if method in valid_methods:

            return parts[1]

    return None


def extract_category(info: dict) -> str | None:
    """
    Extract Nuclei template type/category.
    """

    template_type = info.get("type")

    if template_type:
        return str(template_type)

    return None


def extract_description(info: dict) -> str | None:
    """
    Extract Nuclei finding description.
    """

    description = info.get(
        "description"
    )

    if description:
        return str(description)

    return None


def extract_cwe_id(info: dict) -> str | None:
    """
    Extract CWE identifier from Nuclei classification.
    """

    classification = info.get(
        "classification",
        {}
    )

    if not isinstance(
        classification,
        dict
    ):
        return None

    cwe_id = classification.get(
        "cwe-id"
    )

    if isinstance(
        cwe_id,
        list
    ):

        if cwe_id:
            return str(cwe_id[0])

    elif cwe_id:

        return str(cwe_id)

    return None


def parse_nuclei_results(
    input_file: str | Path = DEFAULT_INPUT_FILE
):

    findings = []

    input_file = Path(
        input_file
    )

    if not input_file.exists():

        raise FileNotFoundError(
            f"Nuclei result file not found: "
            f"{input_file}"
        )

    with input_file.open(
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

            if not isinstance(
                info,
                dict
            ):
                info = {}

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

                # IMPORTANT:
                # Use Nuclei canonical URL first.
                # matched-at is only fallback.
                url=(
                    data.get("url")
                    or data.get("matched-at")
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

                cwe_id=extract_cwe_id(
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
        f"Parsed {len(findings)} "
        f"Nuclei findings."
    )

    print()

    for finding in findings:

        print(
            f"{finding.finding_id} | "
            f"{finding.severity} | "
            f"{finding.name} | "
            f"{finding.method} | "
            f"{finding.url}"
        )