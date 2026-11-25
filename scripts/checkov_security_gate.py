#!/usr/bin/env python3
"""
Evaluate Checkov JSON reports using:
1. The lecturer's official severity mapping for the specified Check IDs.
2. Explicitly labelled hypothetical/internal severity mappings for other
   failed Check IDs observed in Build #10.

IMPORTANT:
- HYPOTHETICAL severities are local risk-triage decisions, not official
  Checkov severity metadata and not part of the lecturer's 16-ID mapping.
- Unknown future Check IDs fail closed and stop evaluation.
"""

import json
import sys
from pathlib import Path

REPORTS = {
    "Terraform": ("reports/terraform/checkov-terraform.json", "terraform"),
    "Kubernetes": ("reports/kubernetes/checkov-kubernetes.json", "kubernetes"),
    "Dockerfile": ("reports/dockerfile/checkov-dockerfile.json", "dockerfile"),
}

# Official severity mapping supplied in the lecturer's practicum material.
# Keep this mapping separate from the internal/hypothetical mapping below.
OFFICIAL_SEVERITY_BY_CHECK_ID = {
    # AWS / Terraform
    "CKV_AWS_20": "CRITICAL",
    "CKV_AWS_57": "CRITICAL",
    "CKV_AWS_145": "HIGH",
    "CKV_AWS_21": "MEDIUM",
    "CKV_AWS_24": "HIGH",
    "CKV_AWS_25": "HIGH",
    "CKV_AWS_27": "CRITICAL",
    "CKV_AWS_17": "HIGH",
    "CKV_AWS_8": "MEDIUM",
    "CKV_AWS_79": "MEDIUM",
    # Kubernetes
    "CKV_K8S_16": "CRITICAL",
    "CKV_K8S_20": "HIGH",
    "CKV_K8S_23": "HIGH",
    # Dockerfile
    "CKV_DOCKER_2": "MEDIUM",
    "CKV_DOCKER_3": "HIGH",
    "CKV_DOCKER_7": "MEDIUM",
}

# Internal severity proposals for the additional failed Check IDs observed
# in Build #10. These are NOT official Checkov or lecturer severity values.
HYPOTHETICAL_SEVERITY_BY_CHECK_ID = {
    # AWS / Terraform - IAM
    "CKV_AWS_62": "CRITICAL",
    "CKV_AWS_287": "HIGH",
    "CKV_AWS_288": "HIGH",
    "CKV_AWS_289": "CRITICAL",
    "CKV_AWS_286": "CRITICAL",
    "CKV_AWS_63": "CRITICAL",
    "CKV_AWS_355": "HIGH",
    "CKV_AWS_290": "HIGH",
    "CKV2_AWS_40": "CRITICAL",

    # AWS / Terraform - RDS
    "CKV_AWS_129": "MEDIUM",
    "CKV_AWS_226": "MEDIUM",
    "CKV_AWS_16": "HIGH",
    "CKV_AWS_118": "MEDIUM",
    "CKV_AWS_161": "MEDIUM",
    "CKV_AWS_293": "HIGH",
    "CKV_AWS_157": "MEDIUM",
    "CKV2_AWS_60": "LOW",

    # AWS / Terraform - EC2
    "CKV_AWS_126": "MEDIUM",
    "CKV_AWS_135": "LOW",
    "CKV2_AWS_41": "MEDIUM",

    # AWS / Terraform - S3 and networking
    "CKV_AWS_23": "LOW",
    "CKV_AWS_144": "MEDIUM",
    "CKV_AWS_18": "MEDIUM",
    "CKV2_AWS_61": "LOW",
    "CKV2_AWS_62": "MEDIUM",
    "CKV2_AWS_6": "HIGH",
    "CKV2_AWS_5": "MEDIUM",

    # Kubernetes
    "CKV_K8S_11": "MEDIUM",
    "CKV_K8S_10": "MEDIUM",
    "CKV_K8S_21": "MEDIUM",
    "CKV_K8S_28": "HIGH",
    "CKV_K8S_43": "MEDIUM",
    "CKV_K8S_14": "HIGH",
    "CKV_K8S_8": "MEDIUM",
    "CKV_K8S_13": "MEDIUM",
    "CKV_K8S_12": "MEDIUM",
    "CKV_K8S_37": "HIGH",
    "CKV_K8S_29": "HIGH",
    "CKV_K8S_22": "MEDIUM",
    "CKV_K8S_9": "MEDIUM",
    "CKV_K8S_40": "MEDIUM",
    "CKV_K8S_31": "HIGH",
    "CKV_K8S_38": "HIGH",
    "CKV2_K8S_6": "HIGH",
}

EXPECTED_FRAMEWORK_BY_PREFIX = {
    "CKV_AWS_": "terraform",
    "CKV2_AWS_": "terraform",
    "CKV_K8S_": "kubernetes",
    "CKV2_K8S_": "kubernetes",
    "CKV_DOCKER_": "dockerfile",
    "CKV2_DOCKER_": "dockerfile",
}

BLOCKING_SEVERITIES = {"HIGH", "CRITICAL"}
ALLOWED_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


def fail(message: str) -> None:
    print(f"ERROR: {message}")
    raise SystemExit(2)


def load_datasets(path: Path):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"Cannot parse JSON report {path}: {exc}")

    datasets = data if isinstance(data, list) else [data]
    if not datasets or not all(isinstance(item, dict) for item in datasets):
        fail(f"Unexpected JSON root structure in {path}")
    return datasets


def get_classification(check_id: str):
    """Return (severity, classification_source), or (None, None)."""
    if check_id in OFFICIAL_SEVERITY_BY_CHECK_ID:
        return OFFICIAL_SEVERITY_BY_CHECK_ID[check_id], "OFFICIAL"
    if check_id in HYPOTHETICAL_SEVERITY_BY_CHECK_ID:
        return HYPOTHETICAL_SEVERITY_BY_CHECK_ID[check_id], "HYPOTHETICAL"
    return None, None


def validate_classification_configuration() -> None:
    overlap = set(OFFICIAL_SEVERITY_BY_CHECK_ID) & set(
        HYPOTHETICAL_SEVERITY_BY_CHECK_ID
    )
    if overlap:
        fail(f"Check IDs exist in both official and hypothetical maps: {sorted(overlap)}")

    for source, mapping in (
        ("official", OFFICIAL_SEVERITY_BY_CHECK_ID),
        ("hypothetical", HYPOTHETICAL_SEVERITY_BY_CHECK_ID),
    ):
        invalid = {
            check_id: severity
            for check_id, severity in mapping.items()
            if severity not in ALLOWED_SEVERITIES
        }
        if invalid:
            fail(f"Invalid {source} severity configuration: {invalid}")


def main() -> int:
    validate_classification_configuration()

    blockers = []
    totals = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    source_totals = {
        "OFFICIAL": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
        "HYPOTHETICAL": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
    }
    total_failed = 0

    print("=== Checkov Security Gate: Official + Hypothetical Classification ===")
    print("OFFICIAL     = lecturer's 16-ID severity mapping")
    print("HYPOTHETICAL = internal risk-triage classification; not official Checkov severity")

    for label, (filename, expected_framework) in REPORTS.items():
        path = Path(filename)
        if not path.is_file():
            fail(f"Required report is missing: {filename}")

        datasets = load_datasets(path)
        framework_failed = 0
        framework_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        for dataset in datasets:
            # A summary-only report means Checkov did not produce check results.
            if "results" not in dataset:
                fail(
                    f"{filename} has no 'results' object. "
                    "Verify the target files and framework scan."
                )

            if dataset.get("check_type") != expected_framework:
                fail(
                    f"{filename}: expected check_type={expected_framework!r}, "
                    f"got {dataset.get('check_type')!r}"
                )

            results = dataset.get("results")
            if not isinstance(results, dict):
                fail(f"{filename}: 'results' must be a JSON object")

            failed_checks = results.get("failed_checks")
            passed_checks = results.get("passed_checks")
            skipped_checks = results.get("skipped_checks", [])

            if not isinstance(failed_checks, list):
                fail(f"{filename}: 'results.failed_checks' must be a list")
            if not isinstance(passed_checks, list):
                fail(f"{filename}: 'results.passed_checks' must be a list")
            if not isinstance(skipped_checks, list):
                fail(f"{filename}: 'results.skipped_checks' must be a list")

            summary = dataset.get("summary")
            if not isinstance(summary, dict):
                fail(f"{filename}: missing or invalid summary object")

            if summary.get("resource_count", 0) < 1:
                fail(f"{filename}: resource_count is zero; target was not evaluated")

            if summary.get("parsing_errors", 0):
                fail(f"{filename}: Checkov reported parsing errors")

            if summary.get("failed") != len(failed_checks):
                fail(
                    f"{filename}: summary.failed does not match "
                    "the number of failed_checks"
                )

            framework_failed += len(failed_checks)
            total_failed += len(failed_checks)

            for finding in failed_checks:
                if not isinstance(finding, dict):
                    fail(f"{filename}: malformed entry in failed_checks")

                check_id = finding.get("check_id")
                resource = finding.get("resource", "UNKNOWN")
                if not isinstance(check_id, str) or not check_id:
                    fail(f"{filename}: failed finding has no valid check_id")

                expected_for_id = next(
                    (
                        framework
                        for prefix, framework in EXPECTED_FRAMEWORK_BY_PREFIX.items()
                        if check_id.startswith(prefix)
                    ),
                    None,
                )
                if expected_for_id and expected_for_id != expected_framework:
                    fail(
                        f"{check_id} appeared in {expected_framework} report; "
                        f"expected {expected_for_id}"
                    )

                severity, classification_source = get_classification(check_id)
                if severity is None:
                    fail(
                        f"No severity classification configured for {check_id} "
                        f"in {label} ({resource}). Add a reviewed mapping before "
                        "allowing this finding through the gate."
                    )

                framework_counts[severity] += 1
                totals[severity] += 1
                source_totals[classification_source][severity] += 1

                print(
                    f"{severity:8} | {classification_source:11} | "
                    f"{check_id} | {resource}"
                )

                if severity in BLOCKING_SEVERITIES:
                    blockers.append(
                        (label, severity, classification_source, check_id, resource)
                    )

        print(
            f"{label}: failed={framework_failed}, "
            f"CRITICAL={framework_counts['CRITICAL']}, "
            f"HIGH={framework_counts['HIGH']}, "
            f"MEDIUM={framework_counts['MEDIUM']}, "
            f"LOW={framework_counts['LOW']}"
        )

    print("\n=== Combined Security Gate Summary ===")
    print(f"Total failed checks: {total_failed}")
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        print(f"{severity}: {totals[severity]}")

    print("\nClassification source breakdown:")
    for source in ("OFFICIAL", "HYPOTHETICAL"):
        source_count = sum(source_totals[source].values())
        print(f"{source}: {source_count}")
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            print(f"  {severity}: {source_totals[source][severity]}")

    print(f"\nHIGH/CRITICAL blockers: {len(blockers)}")
    print("Unclassified Check IDs: 0")

    if blockers:
        print("\nSECURITY GATE: FAIL")
        print("Blocking findings:")
        for label, severity, source, check_id, resource in blockers:
            print(
                f"  - {label}: {severity} [{source}] "
                f"{check_id} ({resource})"
            )
        return 1

    print("\nSECURITY GATE: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
