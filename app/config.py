"""Application configuration, loaded from environment / .env."""
import os
import secrets

from dotenv import load_dotenv

load_dotenv()


def _bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or "sqlite:///asm.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"connect_args": {"timeout": 15}}

    APP_ENV = os.environ.get("APP_ENV", "development")
    DEBUG = APP_ENV == "development"
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")

    # Security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "0") == "1"
    PERMANENT_SESSION_LIFETIME = 60 * 60 * 8  # 8 hours
    MAX_CONTENT_LENGTH = 8 * 1024 * 1024

    # LLM (OpenAI-compatible). Kept out of the DB and never rendered to the UI.
    LLM_BASE_URL = os.environ.get("LLM_BASE_URL", "").rstrip("/")
    LLM_API_KEY = os.environ.get("LLM_API_KEY", "")
    LLM_MODEL = os.environ.get("LLM_MODEL", "")
    LLM_TEMPERATURE = float(os.environ.get("LLM_TEMPERATURE", "0.2"))
    LLM_MAX_TOKENS = int(os.environ.get("LLM_MAX_TOKENS", "1024"))
    LLM_TIMEOUT = int(os.environ.get("LLM_TIMEOUT", "60"))

    # Login throttling
    LOGIN_MAX_ATTEMPTS = 5
    LOGIN_LOCKOUT_SECONDS = 300

    # Background workers
    JOB_WORKERS = int(os.environ.get("JOB_WORKERS", "2"))

    # Scanner binary overrides
    WEBANALYZE_BINARY = os.environ.get("WEBANALYZE_BINARY", "")
    WHATWEB_BINARY = os.environ.get("WHATWEB_BINARY", "")

    # Directory holding organization policy markdown files
    POLICY_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "policies")
