from __future__ import annotations
from datetime import datetime
from typing import List, Optional, Any, Dict
from pydantic import BaseModel, Field, ConfigDict

class QRadarOffense(BaseModel):
    model_config = ConfigDict(populate_by_name=True, arbitrary_types_allowed=True)

    id: int
    description: str
    status: str
    severity: int = Field(ge=0, le=10)
    start_time: datetime
    last_updated_time: datetime
    source_address_ids: List[int] = Field(default_factory=list)
    assigned_to: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()

class QRadarSearch(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    search_id: str
    status: str
    query_expression: str
    completed: bool = False
    progress: int = Field(default=0, ge=0, le=100)

class RawEvent(BaseModel):
    event_id: int
    event_time: datetime
    payload: Dict[str, Any] = Field(default_factory=dict)