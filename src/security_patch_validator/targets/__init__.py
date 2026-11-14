"""Target application manifests and scenario preparation."""

from .manifest import (
    SCENARIOS,
    VERSION_LABELS,
    Target,
    TargetError,
    TargetVersion,
    load_reference_tests,
    load_target,
    materialize_execution_config,
    prepare_git_repo,
    reference_test_map,
)
from .orchestrator import format_scenario_summary, run_scenario

__all__ = [
    "SCENARIOS",
    "VERSION_LABELS",
    "Target",
    "TargetError",
    "TargetVersion",
    "format_scenario_summary",
    "load_reference_tests",
    "load_target",
    "materialize_execution_config",
    "prepare_git_repo",
    "reference_test_map",
    "run_scenario",
]
