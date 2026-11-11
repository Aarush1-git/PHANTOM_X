from typing import List, Optional
from pydantic import Field, AnyHttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

    # Core Settings
    PROJECT_NAME: str = "PHANTOM-X"
    PROJECT_DESCRIPTION: str = "Autonomous Application Security Intelligence"
    VERSION: str = "0.1.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    API_V1_STR: str = "/api/v1"
    BACKEND_HOST: str = "0.0.0.0"
    BACKEND_PORT: int = 8000

    # CORS
    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
    ]

    # Security & JWT
    JWT_SECRET_KEY: str = "phantom-dev-secret-key-32-chars-long-minimum!"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 1 day
    ALLOW_DEV_ANONYMOUS_AUDIT: bool = True  # Dev testing mechanism; strictly ignored and blocked in production

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./phantom_x.db"
    DATABASE_URL_SYNC: str = "sqlite:///./phantom_x.db"
    POSTGRES_SERVER: Optional[str] = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: Optional[str] = "phantom"
    POSTGRES_PASSWORD: Optional[str] = "phantom_secret"
    POSTGRES_DB: Optional[str] = "phantom_x_db"

    # Redis & Celery
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/2"

    # AI Engine
    LLM_PROVIDER: str = "mock"  # mock, openai, anthropic, gemini
    DEFAULT_MODEL: str = "mock-agent-v1"
    LLM_TEMPERATURE: float = 0.1
    LLM_MAX_TOKENS: int = 4096
    OPENAI_API_KEY: Optional[str] = None
    ANTHROPIC_API_KEY: Optional[str] = None
    GEMINI_API_KEY: Optional[str] = None

    # Security Engine & Safety Policy
    EXECUTION_MODE: str = "OBSERVE"  # OBSERVE, ACTIVE_VERIFY, ATTACK_SIMULATION
    STRICT_TARGET_AUTHORIZATION: bool = True
    ALLOWED_TARGET_HOSTS: str = "localhost,127.0.0.1,api.example-target.local"
    MAX_CONCURRENT_SECURITY_TESTS: int = 5
    DEFAULT_RATE_LIMIT_RPS: int = 10
    ENFORCE_SYNTHETIC_DATA_ONLY: bool = True

    # Integrations
    ZAP_ENABLED: bool = False
    ZAP_API_URL: str = "http://localhost:8080"
    ZAP_API_KEY: Optional[str] = None
    PLAYWRIGHT_HEADLESS: bool = True
    PLAYWRIGHT_BROWSER: str = "chromium"


settings = Settings()

