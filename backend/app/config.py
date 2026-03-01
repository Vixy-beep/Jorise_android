from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    APP_NAME: str = "Guardian"
    DEBUG: bool = True
    DATABASE_URL: str = "sqlite:///./guardian.db"
    CORS_ORIGINS: List[str] = ["*"]
    SECRET_KEY: str = "change-me-in-production"

    model_config = {"env_file": ".env"}


settings = Settings()
