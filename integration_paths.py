"""Portable staging-only paths. Importing this module creates no state."""
from pathlib import Path

from settings import STAGING_ROOT

SOURCE_ROOT = Path(__file__).resolve().parent
INTEGRATION_ROOT = STAGING_ROOT / "integration"
