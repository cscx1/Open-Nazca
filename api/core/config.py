from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    frontend_url: str = "http://localhost:3000"
    backend_url: str = "http://localhost:8000"
    use_snowflake: bool = True
    use_llm: bool = True
    llm_provider: str = "snowflake_cortex"
    temp_dir: str = "temp_scans"
    reports_dir: str = "reports"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
