from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "SentinelAI"
    app_env: str = "development"
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    api_v1_prefix: str = "/api/v1"
    cors_origins: str = "http://localhost:5173"
    log_level: str = "INFO"
    secret_key: str = "change-me"
    access_token_expire_minutes: int = 30
    database_url: str = (
        "postgresql+psycopg2://sentinelai:sentinelai@postgres:5432/sentinelai"
    )
    redis_url: str = "redis://redis:6379/0"
    openrouter_api_key: str | None = None
    openrouter_model: str = "mistralai/mistral-7b-instruct:free"
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    openrouter_http_referer: str = "http://localhost:5173"
    openrouter_app_name: str = "SentinelAI"
    sentinelai_nlp_model: str = "distilbert-scam-detector"
    sentinelai_nlp_model_dir: str = "backend/models/nlp/distilbert-scam-detector"
    sentinelai_nlp_local_only: bool = True
    sentinelai_nlp_threads: int = 2
    sentinelai_url_model_path: str = "backend/models/url/phishing_url_model_v1.pkl"
    sentinelai_url_model_metadata_path: str = "backend/models/url/phishing_url_model_v1.json"
    interaction_simulation_enabled: bool = True
    interaction_timeout_ms: int = 8000
    interaction_max_actions: int = 4
    interaction_headless: bool = True
    reason_weight_phishing_probability: float = 0.30
    reason_weight_dom_suspicion: float = 0.25
    reason_weight_content_scam_score: float = 0.20
    reason_weight_reputation_score: float = 0.15
    reason_weight_redirect_risk: float = 0.10

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache

def get_settings() -> Settings:
    return Settings()
