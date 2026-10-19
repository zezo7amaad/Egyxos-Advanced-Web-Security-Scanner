from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Egyxos Advanced Web Security Scanner"
    database_url: str = "sqlite:///./egyxos.db"
    gemini_api_key: str | None = None
    gemini_model: str = "gemini-2.0-flash"
    ollama_url: str | None = None
    ollama_model: str = "llama3.2"
    lab_mode: bool = True
    demo_mode: bool = True
    reports_dir: str = "reports"

    model_config = SettingsConfigDict(env_file=".env", env_prefix="", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()
