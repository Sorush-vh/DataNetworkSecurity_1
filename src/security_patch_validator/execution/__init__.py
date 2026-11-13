"""Person 2's configuration-driven dynamic execution interface."""

from .config import Config, load_config
from .runner import run_suite

__all__ = ["Config", "load_config", "run_suite"]
