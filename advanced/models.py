from __future__ import annotations
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import List, Optional
from pydantic import BaseModel, Field, ConfigDict, field_validator

class Tactic(str, Enum):
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"

class Technique(BaseModel):
    model_config = ConfigDict(frozen=True)

    tid: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    name: str
    tactic: Tactic

class IntelMatch(BaseModel):
    ioc: str
    source: str
    confidence: int = Field(ge=0, le=100)
    first_seen: datetime
    last_seen: datetime

class APTReport(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    event_id: int
    techniques: List[Technique] = Field(default_factory=list)
    intel_hits: List[IntelMatch] = Field(default_factory=list)
    threat_score: float = Field(ge=0.0, le=100.0)
    is_apt: bool = False
    evidence_dir: Optional[Path] = None

    @field_validator("evidence_dir", mode="before")
    @classmethod
    def ensure_path(cls, v):
        if v is None:
            return None
        return Path(v)