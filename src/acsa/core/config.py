"""Configuration management for ACSA using Pydantic Settings."""

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application and security boundary settings for ACSA."""

    model_config = SettingsConfigDict(
        env_prefix="ACSA_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # General service settings
    env: str = Field(default="development", description="Execution environment")
    service_name: str = Field(default="acsa-api", description="Service identifier")
    api_host: str = Field(default="127.0.0.1", description="API bind host")
    api_port: int = Field(default=8000, ge=1024, le=65535, description="API port")
    log_level: str = Field(default="INFO", description="Log level")

    # Security boundaries & Sandbox
    workspace_dir: Path = Field(
        default=Path(".acsa_workspaces"),
        description="Base directory for temporary isolated analysis workspaces",
    )
    scan_timeout_seconds: int = Field(
        default=300,
        ge=1,
        le=3600,
        description="Maximum execution timeout for repository scanning",
    )
    max_scan_file_size_bytes: int = Field(
        default=52428800,
        ge=1024,
        description="Maximum file size in bytes to process during AST/manifest parsing (default 50MB)",
    )
    allow_arbitrary_code_execution: bool = Field(
        default=False,
        description="Security constraint: never blindly execute arbitrary repository code",
    )
    allow_npm_lifecycle_scripts: bool = Field(
        default=False,
        description="Security constraint: never blindly run npm install or lifecycle scripts",
    )


@lru_cache
def get_settings() -> Settings:
    """Return cached application settings instance."""
    return Settings()
