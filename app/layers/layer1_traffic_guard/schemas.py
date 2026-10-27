
from pydantic import BaseModel


class TrafficGuardError(BaseModel):
    error: str
    message: str
    request_id: str
