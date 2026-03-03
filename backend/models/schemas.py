from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
from enum import Enum


class LogSource(str, Enum):
    AUTH = "auth"
    NGINX = "nginx"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    UNKNOWN = "unknown"


class ThreatType(str, Enum):
    BRUTE_FORCE = "brute_force"
    SCANNING = "scanning"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    BENIGN = "benign"
    UNKNOWN = "unknown"


class LogEvent(BaseModel):
    """Structured representation of a single parsed log event."""
    id: str
    timestamp: Optional[datetime] = None
    source_ip: Optional[str] = None
    username: Optional[str] = None
    event_type: str
    status: Optional[str] = None
    endpoint: Optional[str] = None       # nginx: request path
    http_method: Optional[str] = None    # nginx: GET, POST, etc.
    http_status_code: Optional[int] = None
    log_source: LogSource
    raw: str


class SuspiciousEvent(BaseModel):
    """A LogEvent that has been flagged by the detection engine."""
    event: LogEvent
    suspicious: bool = True
    reasons: list[str] = Field(default_factory=list)

    # Populated by AI classifier
    severity: Severity = Severity.UNKNOWN
    threat_type: ThreatType = ThreatType.UNKNOWN
    ai_explanation: Optional[str] = None


class AnalysisResult(BaseModel):
    """Full result returned to the frontend after processing a log file."""
    total_events: int
    suspicious_count: int
    high_severity_count: int
    medium_severity_count: int
    low_severity_count: int
    all_events: list[LogEvent]
    suspicious_events: list[SuspiciousEvent]
    ip_summary: dict[str, int]
    log_source: LogSource
    processed_at: datetime = Field(default_factory=datetime.utcnow)


class UploadResponse(BaseModel):
    message: str
    result: AnalysisResult