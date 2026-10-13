from pydantic import BaseModel
from typing import Optional

class PolicyResponse(BaseModel):
    id: int
    name: str
    description: str
    effect: str
    priority: int
    enabled: bool
    action_types: Optional[list[str]] = None
    destination_patterns: Optional[list[str]] = None
    data_tags: Optional[list[str]] = None
    third_party: Optional[bool] = None

    model_config = {"from_attributes": True}
