"""Minimal event-collection API.

A separate client reports an access (who, what, how many rows). The API checks an API key,
validates the input, then hands the event to the same scoring, alert and audit-log code
the dashboard uses (SentinelDB.log_event). Nothing here changes detection logic.

Trust limits, stated plainly:
  * The client reports the row count itself, so the API is only as honest as the client.
    Only the Query Console measures rows on its own.
  * The server stamps the time. Client timestamps are rejected so events cannot be backdated.
  * One shared key from an environment variable, meant for localhost. This is demo-level
    protection, not production security (no TLS, no per-client keys, no rate limiting).
"""
import os
import secrets
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Security
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, ConfigDict, Field, StrictInt

from .database import SentinelDB

API_KEY_ENV = "DATALEAK_API_KEY"
MIN_KEY_LENGTH = 16
MAX_RECORDS = 100_000_000


class EventIn(BaseModel):
    """One reported access. Unknown fields (including 'timestamp') are rejected."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    user_id: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,32}$", examples=["U1011"])
    username: str = Field(pattern=r"^[A-Za-z0-9_.@-]{1,64}$", examples=["farhan.ali"])
    department: str = Field(pattern=r"^[A-Za-z0-9 &_.-]{1,64}$", examples=["Operations"])
    access_type: str = Field(pattern=r"^[A-Za-z0-9 *_.()-]{1,64}$", examples=["Full Table Export"])
    records_accessed: StrictInt = Field(ge=0, le=MAX_RECORDS, examples=[3200])
    query_text: str | None = Field(default=None, max_length=500)


class EventOut(BaseModel):
    log_id: int
    risk_score: int
    risk_level: str
    reason: str
    alert_id: int | None


class AlertOut(BaseModel):
    alert_id: int
    log_id: int
    user_id: str
    username: str
    timestamp: str
    records_accessed: int
    risk_score: int
    risk_level: str
    reason: str
    status: str


def create_app(db: SentinelDB | None = None, api_key: str | None = None) -> FastAPI:
    """Build the app. The key comes from DATALEAK_API_KEY unless passed in (tests)."""
    key = api_key if api_key is not None else os.environ.get(API_KEY_ENV, "")
    if len(key) < MIN_KEY_LENGTH:
        raise RuntimeError(
            f"Set the {API_KEY_ENV} environment variable to a secret of at least {MIN_KEY_LENGTH} characters. "
            'Generate one with: python -c "import secrets; print(secrets.token_urlsafe(24))"'
        )
    database = db or SentinelDB()
    database.init_schema()

    app = FastAPI(
        title="DataLeak Sentinel event API",
        version="1.0",
        description="Report simulated database access events for scoring. Synthetic data only.",
    )
    header = APIKeyHeader(name="X-API-Key", auto_error=False)

    def require_key(provided: str | None = Security(header)) -> None:
        if provided is None or not secrets.compare_digest(provided.encode(), key.encode()):
            raise HTTPException(status_code=401, detail="Missing or invalid API key.",
                                headers={"WWW-Authenticate": "ApiKey"})

    @app.get("/health")
    def health() -> dict:
        try:
            database.table_counts()
        except Exception:
            raise HTTPException(status_code=503, detail="Database not reachable.")
        return {"status": "ok"}

    @app.post("/events", status_code=201, response_model=EventOut, dependencies=[Depends(require_key)])
    def post_event(event: EventIn) -> EventOut:
        result = database.log_event(
            event.user_id, event.username, event.department, event.access_type,
            event.records_accessed, query_text=event.query_text, source="api",
        )
        alerts = database.alerts_df()
        match = alerts[alerts["log_id"] == result["log_id"]]
        alert_id = int(match.iloc[0]["alert_id"]) if not match.empty else None
        return EventOut(**result, alert_id=alert_id)

    @app.get("/alerts", response_model=list[AlertOut], dependencies=[Depends(require_key)])
    def list_alerts(
        limit: int = Query(20, ge=1, le=200),
        status: Literal["New", "Reviewed"] | None = None,
    ) -> list[AlertOut]:
        alerts = database.alerts_df()
        if status:
            alerts = alerts[alerts["status"] == status]
        rows = alerts.head(limit)
        return [
            AlertOut(
                alert_id=int(r.alert_id), log_id=int(r.log_id), user_id=r.user_id, username=r.username,
                timestamp=r.timestamp.strftime("%Y-%m-%d %H:%M:%S"), records_accessed=int(r.records_accessed),
                risk_score=int(r.risk_score), risk_level=r.risk_level, reason=r.reason, status=r.status,
            )
            for r in rows.itertuples()
        ]

    return app
