from pydantic import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    DATABASE_URL: str
    SECRET_KEY: str
    ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int
    ZILLOW_API_KEY: str
    PAYPAL_CLIENT_ID: str
    PAYPAL_CLIENT_SECRET: str
    SENTRY_DSN: Optional[str]

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()