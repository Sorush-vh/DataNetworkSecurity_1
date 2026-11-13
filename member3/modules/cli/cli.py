import argparse
import json
import sys
from pathlib import Path


EXIT_CODES = {
    "PASS": 0,
    "VULN_REMAINS": 10,
    "FUNC_REGRESSION": 20,
    "BUILD_OR_CONFIG_ERROR": 30,
    "INCONCLUSIVE": 40
}

PRIORITY = [
    "BUILD_OR_CONFIG_ERROR",
    "VULN_REMAINS",
    "FUNC_REGRESSION",
    "INCONCLUSIVE",
    "PASS"
]


def determine_status(security_status, functional_status, analysis_status):
    statuses = {
        security_status,
        functional_status,
        analysis_status
    }

    for status in PRIORITY:
        if status in statuses:
            return status

    return "INCONCLUSIVE"


def create_report(
    security_status,
    functional_status,
    analysis_status,
    details=None
):
    allowed_statuses = {
        "security_status": {
            "PASS",
            "VULN_REMAINS",
            "INCONCLUSIVE",
            "BUILD_OR_CONFIG_ERROR"
        },
        "functional_status": {
            "PASS",
            "FUNC_REGRESSION",
            "INCONCLUSIVE",
            "BUILD_OR_CONFIG_ERROR"
        },
        "analysis_status": {
            "PASS",
            "INCONCLUSIVE",
            "BUILD_OR_CONFIG_ERROR"
        }
    }

    supplied_statuses = {
        "security_status": security_status,
        "functional_status": functional_status,
        "analysis_status": analysis_status
    }

    for field, value in supplied_statuses.items():
        if value not in allowed_statuses[field]:
            raise ValueError(f"Invalid {field}: {value}")

    if details is not None and not isinstance(details, dict):
        raise ValueError("details must be a dictionary")

    overall_status = determine_status(
        security_status,
        functional_status,
        analysis_status
    )

    return {
        "status": overall_status,
        "exit_code": EXIT_CODES[overall_status],
        "security_status": security_status,
        "functional_status": functional_status,
        "analysis_status": analysis_status,
        "details": details if details is not None else {}
    }


def evaluate_regression_result(result):
    if not isinstance(result, dict):
        raise ValueError("Regression result must be a dictionary")

    status = result.get("status")

    if status == "INCONCLUSIVE":
        return "INCONCLUSIVE", "INCONCLUSIVE"

    if status not in {"PASS", "FAIL"}:
        raise ValueError(f"Unknown regression status: {status}")

    base = result.get("base")
    patched = result.get("patched")
    stability = result.get("stability")

    if not isinstance(base, dict) or not isinstance(patched, dict):
        return "INCONCLUSIVE", "INCONCLUSIVE"

    if not isinstance(stability, dict):
        return "INCONCLUSIVE", "INCONCLUSIVE"

    if stability.get("overall") != "STABLE":
        return "INCONCLUSIVE", "INCONCLUSIVE"

    if base.get("matches_expected_error") is not True:
        return "INCONCLUSIVE", "INCONCLUSIVE"

    same_error_absent = patched.get("same_error_absent")
    expected_behavior = patched.get("expected_behavior")

    if not isinstance(same_error_absent, bool):
        return "INCONCLUSIVE", "INCONCLUSIVE"

    if not isinstance(expected_behavior, bool):
        return "INCONCLUSIVE", "INCONCLUSIVE"

    if not same_error_absent:
        return "VULN_REMAINS", "PASS"

    if not expected_behavior:
        return "PASS", "FUNC_REGRESSION"

    if status == "PASS":
        return "PASS", "PASS"

    return "INCONCLUSIVE", "INCONCLUSIVE"


def save_report(report, output_path):
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, ensure_ascii=False)


def print_report(report):
    print("=" * 45)
    print("Security Patch Validator")
    print("=" * 45)
    print(f"Overall Status : {report['status']}")
    print(f"Security       : {report['security_status']}")
    print(f"Functional     : {report['functional_status']}")
    print(f"Analysis       : {report['analysis_status']}")
    print(f"Exit Code      : {report['exit_code']}")
    print("=" * 45)


def main():
    parser = argparse.ArgumentParser(
        description="Automatic security patch validation tool"
    )

    parser.add_argument(
        "--regression-result",
        help="Path to regression result JSON file"
    )

    parser.add_argument(
        "--output",
        default="reports/report.json",
        help="Path to JSON report"
    )

    parser.add_argument(
        "--security",
        choices=["PASS", "VULN_REMAINS", "INCONCLUSIVE",
                 "BUILD_OR_CONFIG_ERROR"],
        default="INCONCLUSIVE"
    )

    parser.add_argument(
        "--functional",
        choices=["PASS", "FUNC_REGRESSION", "INCONCLUSIVE",
                 "BUILD_OR_CONFIG_ERROR"],
        default="INCONCLUSIVE"
    )

    parser.add_argument(
        "--analysis",
        choices=["PASS", "INCONCLUSIVE", "BUILD_OR_CONFIG_ERROR"],
        default="INCONCLUSIVE"
    )

    args = parser.parse_args()
    details = {}

    if args.regression_result:
        try:
            with open(args.regression_result, encoding="utf-8") as file:
                regression_result = json.load(file)

            security_status, functional_status = (
                evaluate_regression_result(regression_result)
            )
            details["regression"] = regression_result

        except (OSError, json.JSONDecodeError, ValueError) as error:
            print(
                f"Error reading regression result: {error}",
                file=sys.stderr
            )
            return EXIT_CODES["BUILD_OR_CONFIG_ERROR"]
    else:
        security_status = args.security
        functional_status = args.functional

    report = create_report(
        security_status=security_status,
        functional_status=functional_status,
        analysis_status=args.analysis,
        details=details
    )

    save_report(report, args.output)
    print_report(report)

    return report["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
