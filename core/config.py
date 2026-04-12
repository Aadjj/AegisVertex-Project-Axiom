from __future__ import annotations
import os
import yaml
from pathlib import Path
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

try:
    from pydantic_settings import BaseSettings, SettingsConfigDict
    from pydantic import field_validator as validator
except ImportError:
    from pydantic import BaseSettings, validator

class Config(BaseSettings):
    app_name: str = "AegisVertex_Project_Axiom"
    log_level: str = "INFO"
    secrets_dir: Path = Path("secrets")
    qradar_host: str
    qradar_api_token: Optional[str] = None
    qradar_verify_ssl: bool = False
    qradar_request_timeout: int = 30
    qradar_retries_total: int = 5
    qradar_backoff_factor: float = 0.4
    qradar_token_refresh_buffer: int = 300

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )

    @validator("secrets_dir", mode="before")
    @classmethod
    def _resolve_path(cls, v):
        path = Path(v).expanduser()
        if not path.exists():
            path.mkdir(parents=True, mode=0o700)
        return path

    def __init__(self, config_path: str = "config.yaml", **kwargs):
        yaml_data = {}
        path = Path(config_path)
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                yaml_data = yaml.safe_load(f) or {}

        super().__init__(**{**yaml_data, **kwargs})
        self._decrypt_secrets()

    def _decrypt_secrets(self):
        key_file = self.secrets_dir / ".key"

        if not key_file.exists():
            key = ChaCha20Poly1305.generate_key()
            key_file.write_bytes(key)
            key_file.chmod(0o600)

        key = key_file.read_bytes()
        cipher = ChaCha20Poly1305(key)

        token_file = self.secrets_dir / "qradar_api_token.enc"
        if token_file.exists() and not self.qradar_api_token:
            try:
                ct = token_file.read_bytes()
                pt = cipher.decrypt(ct[:12], ct[12:], b"")
                self.qradar_api_token = pt.decode('utf-8')
            except Exception:
                pass

    def save_encrypted(self, key_name: str, value: str):
        key_file = self.secrets_dir / ".key"
        if not key_file.exists():
            self._decrypt_secrets()

        key = key_file.read_bytes()
        cipher = ChaCha20Poly1305(key)
        nonce = os.urandom(12)

        ct = nonce + cipher.encrypt(nonce, value.encode('utf-8'), b"")
        out = self.secrets_dir / f"{key_name}.enc"
        out.write_bytes(ct)
        out.chmod(0o600)