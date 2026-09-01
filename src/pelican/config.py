"""Configuration for the OSINT MCP server.

All settings come from environment variables (or a local .env file) so the
server runs with zero config by default and only uses API keys for the
sources you explicitly enable. Keys are kept in SecretStr and never logged.
"""

from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv
from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

_loaded: bool = False


def load_env() -> None:
    """Load a .env file from the CWD, the package dir, or ~/.config/pelican."""
    global _loaded
    if _loaded:
        return
    candidates = [
        Path.cwd() / ".env",
        Path(__file__).resolve().parent.parent / ".env",
        Path.home() / ".config" / "pelican" / ".env",
        Path.home() / ".pelican.env",
    ]
    for path in candidates:
        if path.exists():
            load_dotenv(path)
            break
    else:
        load_dotenv()
    _loaded = True


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=None,  # handled by load_env() for control over search path
        case_sensitive=False,
        extra="ignore",
    )

    github_token: SecretStr | None = Field(default=None, alias="GITHUB_TOKEN")
    hibp_api_key: SecretStr | None = Field(default=None, alias="HIBP_API_KEY")
    otx_api_key: SecretStr | None = Field(default=None, alias="OTX_API_KEY")
    shodan_api_key: SecretStr | None = Field(default=None, alias="SHODAN_API_KEY")
    virustotal_api_key: SecretStr | None = Field(
        default=None, alias="VIRUSTOTAL_API_KEY"
    )
    hunter_api_key: SecretStr | None = Field(default=None, alias="HUNTER_API_KEY")

    # Optional bearer token to require on the HTTP transport.
    auth_token: SecretStr | None = Field(default=None, alias="OSINT_MCP_AUTH_TOKEN")

    # Concurrency / timeout tuning
    http_timeout: float = Field(default=15.0, alias="OSINT_MCP_HTTP_TIMEOUT")
    max_concurrency: int = Field(default=8, alias="OSINT_MCP_MAX_CONCURRENCY")

    @classmethod
    def load(cls) -> "Settings":
        load_env()
        return cls()


def _reveal(secret: SecretStr | None) -> str:
    return secret.get_secret_value() if secret else ""


class Config:
    """Convenience object exposing resolved key values (safe to use at runtime)."""

    def __init__(self) -> None:
        self._s = Settings.load()

    @property
    def github_token(self) -> str:
        return _reveal(self._s.github_token)

    @property
    def hibp_api_key(self) -> str:
        return _reveal(self._s.hibp_api_key)

    @property
    def otx_api_key(self) -> str:
        return _reveal(self._s.otx_api_key)

    @property
    def shodan_api_key(self) -> str:
        return _reveal(self._s.shodan_api_key)

    @property
    def virustotal_api_key(self) -> str:
        return _reveal(self._s.virustotal_api_key)

    @property
    def hunter_api_key(self) -> str:
        return _reveal(self._s.hunter_api_key)

    @property
    def auth_token(self) -> str:
        return _reveal(self._s.auth_token)

    @property
    def http_timeout(self) -> float:
        return self._s.http_timeout

    @property
    def max_concurrency(self) -> int:
        return self._s.max_concurrency

    @property
    def source_status(self) -> dict:
        """Map of source name -> whether an API key is configured.

        Borrowed concept from badchars/osint-mcp-server (MIT): lets an
        agent and user see at a glance what's unlocked vs. free-only.
        """
        return {
            "github": bool(self.github_token),
            "hibp": bool(self.hibp_api_key),
            "otx": bool(self.otx_api_key),
            "shodan": bool(self.shodan_api_key),
            "virustotal": bool(self.virustotal_api_key),
            "hunter": bool(self.hunter_api_key),
        }


config = Config()

USER_AGENT = (
    "pelican/0.1.0 "
    "(https://github.com/; +https://modelcontextprotocol.io) "
    "OSINT research for authorized use only"
)
