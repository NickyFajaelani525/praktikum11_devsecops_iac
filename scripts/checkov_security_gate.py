#!/usr/bin/env python3
"""Evaluate Checkov JSON reports using the lecturer's Check ID severity mapping."""

import json
import sys
from pathlib import Path

REPORTS = {
    "Terraform": ("reports/terraform/checkov-terraform.json", "terraform"),
    "Kubernetes": ("reports/kubernetes/checkov-kubernetes.json", "kubernetes"),
    "Dockerfile": ("reports/dockerfile/checkov-dockerfile.json", "dockerfile"),
}

# Severity mapping taken from the lecturer's Checkov practicum list.
SEVERITY_BY_CHECK_ID = {
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

EXPECTED_FRAMEWORK_BY_PREFIX = {
    "CKV_AWS_": "terraform",
    "CKV_K8S_": "kubernetes",
    "CKV_DOCKER_": "dockerfile",
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


def main() -> int:
    blockers = []
    unmapped = []
    totals = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    total_failed = 0

    print("=== Checkov Security Gate: Lecturer Check ID Policy ===")

    for label, (filename, expected_framework) in REPORTS.items():
        path = Path(filename)
        if not path.is_file():
            fail(f"Required report is missing: {filename}")

        datasets = load_datasets(path)
        framework_failed = 0
        framework_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        for dataset in datasets:
            # Checkov may emit a summary-only object when it generated no report.
            # For this lab, each input directory is expected to contain scannable IaC.
            if "results" not in dataset:
                fail(
                    f"{filename} has no 'results' object. "
                    "Checkov did not produce check results; verify the target files "
                    "and framework scan before evaluating the gate."
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

            # A zero-resource result is not treated as a clean scan.
            if summary.get("resource_count", 0) < 1:
                fail(
                    f"{filename}: resource_count is zero. "
                    "The target directory was not actually evaluated."
                )

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

                severity = SEVERITY_BY_CHECK_ID.get(check_id)
                if severity is None:
                    print(f"UNMAPPED | {check_id} | {resource}")
                    unmapped.append((label, check_id, resource))
                    continue

                framework_counts[severity] += 1
                totals[severity] += 1
                print(f"{severity:8} | {check_id} | {resource}")

                if severity in BLOCKING_SEVERITIES:
                    blockers.append((label, severity, check_id, resource))

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
    print(f"HIGH/CRITICAL blockers: {len(blockers)}")
    print(f"Unmapped Check IDs: {len(unmapped)}")

    if blockers or unmapped:
        print("\nSECURITY GATE: FAIL")
        if blockers:
            print("Blocking findings:")
            for label, severity, check_id, resource in blockers:
                print(f"  - {label}: {severity} {check_id} ({resource})")
        if unmapped:
            print("Unmapped findings (fail-closed):")
            for label, check_id, resource in unmapped:
                print(f"  - {label}: {check_id} ({resource})")
        return 1

    print("\nSECURITY GATE: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
