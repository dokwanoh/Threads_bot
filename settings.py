"""Validated, non-secret configuration. Importing this module changes no files.

Defaults are synthetic examples. Configuration never authorizes a social action,
activates a database, clears STOP, or enables an unavailable adapter. All processes
using one ledger must pin the same configuration for its lifetime.
"""
from dataclasses import dataclass
import os
from pathlib import Path
import re
from typing import Mapping


class ConfigurationError(ValueError):
    """Invalid or overlapping configuration must fail before state is opened."""


@dataclass(frozen=True)
class Settings:
    account: str
    blog_host: str
    staging_root: Path
    production_root: Path


def _root(value: str | Path, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise ConfigurationError(f"{label} must be an absolute path")
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ConfigurationError(f"{label} cannot contain a symlink")
    resolved = path.resolve()
    if resolved == Path(resolved.anchor):
        raise ConfigurationError(f"{label} cannot be a filesystem root")
    return resolved


def load_settings(environ: Mapping[str, str] | None = None) -> Settings:
    env = os.environ if environ is None else environ
    account = env.get("THREADS_BOT_ACCOUNT", "example.bot")
    if not re.fullmatch(r"[a-z0-9_.]{1,64}", account):
        raise ConfigurationError("THREADS_BOT_ACCOUNT must be a canonical account handle")
    blog_host = env.get("THREADS_BOT_BLOG_HOST", "blog.example")
    label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    if len(blog_host) > 253 or not re.fullmatch(rf"{label}(?:\.{label})+", blog_host):
        raise ConfigurationError("THREADS_BOT_BLOG_HOST must be a lowercase hostname without a URL or port")
    base = Path(__file__).resolve().parent / ".state"
    staging = _root(env.get("THREADS_BOT_STAGING_ROOT", str(base / "staging")), "Staging root")
    production = _root(env.get("THREADS_BOT_PRODUCTION_ROOT", str(base / "production")), "Production root")
    if staging.is_relative_to(production) or production.is_relative_to(staging):
        raise ConfigurationError("Staging and production roots must be disjoint")
    return Settings(account, blog_host, staging, production)


SETTINGS = load_settings()
ACCOUNT = SETTINGS.account
BLOG_HOST = SETTINGS.blog_host
STAGING_ROOT = SETTINGS.staging_root
PRODUCTION_ROOT = SETTINGS.production_root
