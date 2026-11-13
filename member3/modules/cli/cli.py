
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
        "details": details or {}
    }


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
        default="PASS"
    )

    args = parser.parse_args()

    report = create_report(
        security_status=args.security,
        functional_status=args.functional,
        analysis_status=args.analysis
    )

    save_report(report, args.output)
    print_report(report)

    return report["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
