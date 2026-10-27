"""Application configuration from environment variables.

Every setting has a safe default; an invalid value stops the app at startup with an error that
names the variable. The server only ever binds to loopback.
"""

import os
from dataclasses import dataclass
from typing import Mapping, Optional

# Host names the server may bind to and accept in the Host header. Loopback only.
LOOPBACK_HOSTS = ("127.0.0.1", "localhost")

# Room for the non-file form fields (password, placements JSON, options) and multipart framing.
FORM_OVERHEAD_BYTES = 1024 * 1024


class ConfigError(ValueError):
    """Raised for an invalid configuration value. The message names the variable."""


@dataclass(frozen=True)
class Settings:
    host: str = "127.0.0.1"
    port: int = 8501
    max_pdf_bytes: int = 50 * 1024 * 1024
    max_p12_bytes: int = 256 * 1024
    max_placements: int = 1000
    # Requests admitted at once (being uploaded, parsed, queued or signed); more get 503.
    max_in_flight: int = 2

    @property
    def max_request_bytes(self) -> int:
        """Upper bound for a whole request body, enforced while it streams in."""
        return self.max_pdf_bytes + self.max_p12_bytes + FORM_OVERHEAD_BYTES

    @property
    def max_field_bytes(self) -> int:
        """Upper bound for one non-file form field (the placements JSON is the largest)."""
        return max(64 * 1024, self.max_placements * 200)

    @property
    def allowed_origins(self) -> frozenset:
        return frozenset(f"http://{host}:{self.port}" for host in LOOPBACK_HOSTS)


def _int(env: Mapping[str, str], name: str, default: int, minimum: int, maximum: int) -> int:
    raw: Optional[str] = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw.strip())
    except ValueError:
        raise ConfigError(f"{name} must be a whole number, got {raw!r}.") from None
    if not minimum <= value <= maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum}, got {value}.")
    return value


def load_settings(env: Optional[Mapping[str, str]] = None) -> Settings:
    """Read settings from ``env`` (default: the process environment).

    Raises:
        ConfigError: For an invalid value, naming the variable.
    """
    env = os.environ if env is None else env
    defaults = Settings()

    host = (env.get("ESIGN_HOST") or defaults.host).strip()
    if host not in LOOPBACK_HOSTS:
        raise ConfigError(
            f"ESIGN_HOST must be a loopback address ({', '.join(LOOPBACK_HOSTS)}), got {host!r}."
        )

    return Settings(
        host=host,
        port=_int(env, "ESIGN_PORT", defaults.port, 1, 65535),
        max_pdf_bytes=_int(env, "ESIGN_MAX_PDF_MB", 50, 1, 500) * 1024 * 1024,
        max_p12_bytes=_int(env, "ESIGN_MAX_P12_KB", 256, 1, 10 * 1024) * 1024,
        max_placements=_int(env, "ESIGN_MAX_PLACEMENTS", defaults.max_placements, 1, 10000),
        max_in_flight=_int(env, "ESIGN_MAX_IN_FLIGHT", defaults.max_in_flight, 1, 16),
    )
