import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent

class Settings:
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8010"))
    ZENTRIQ_API_KEY: str = os.getenv("ZENTRIQ_API_KEY", "zentriq-local-dev-key")
    API_KEY_AUTH_ENABLED: bool = os.getenv("API_KEY_AUTH_ENABLED", "true").lower() == "true"
    RATE_LIMIT_ENABLED: bool = os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"
    RATE_LIMIT_REQUESTS: int = int(os.getenv("RATE_LIMIT_REQUESTS", "600"))
    RATE_LIMIT_WINDOW_SECONDS: int = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'data' / 'zentriq.db'}")
    LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "mock")
    LLM_BASE_URL: str = os.getenv("LLM_BASE_URL", "")
    LLM_API_KEY: str = os.getenv("LLM_API_KEY", "")
    RELEVANCE_THRESHOLD: float = float(os.getenv("RELEVANCE_THRESHOLD", "0.2"))
    RISK_LOW_THRESHOLD: float = float(os.getenv("RISK_LOW_THRESHOLD", "0.3"))
    RISK_HIGH_THRESHOLD: float = float(os.getenv("RISK_HIGH_THRESHOLD", "0.6"))
    LOG_SENSITIVE_PROMPTS: bool = os.getenv("LOG_SENSITIVE_PROMPTS", "false").lower() == "true"

settings = Settings()
