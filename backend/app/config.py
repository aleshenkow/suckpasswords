from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str = "postgresql+psycopg://suckpasswords:suckpasswords@db:5432/suckpasswords"

    app_secret_key: str = "change_me"
    app_data_encryption_key: str = ""
    app_access_token_expire_minutes: int = 30

    app_admin_username: str = ""
    app_admin_password: str = ""
    app_admin_email: str = "admin@local"

    ad_enabled: bool = False
    ad_server_uri: str = ""
    ad_base_dn: str = ""
    ad_bind_dn: str = ""
    ad_bind_password: str = ""
    ad_user_filter: str = "(sAMAccountName={username})"
    ad_required_group_dn: str = ""


settings = Settings()
