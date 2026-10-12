"""Greywatch API entry point."""

from typing import Literal

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from backend.app.siem import (
    close_alert,
    get_alert_detail,
    ingest_lines,
    list_alerts,
    list_events,
)

app = FastAPI(
    title="Greywatch API",
    description="Open-source security monitoring and SIEM platform",
    version="0.1.0",
)


class IngestRequest(BaseModel):
    lines: list[str] = Field(min_length=1, max_length=1000)


@app.get("/", tags=["meta"])
def root():
    return {
        "name": "Greywatch",
        "status": "in-development",
        "docs": "/docs",
    }


@app.get("/health", tags=["meta"])
def health():
    return {
        "status": "ok",
        "service": "greywatch-api",
        "version": "0.1.0",
    }


@app.post("/api/v1/events/ingest", tags=["ingestion"])
def ingest(request: IngestRequest):
    """Ingest raw log lines and evaluate configured detection rules."""
    return ingest_lines(request.lines)


@app.get("/api/v1/events", tags=["events"])
def get_events(
    limit: int = Query(default=100, ge=1, le=500),
):
    events = list_events(limit)
    return {"count": len(events), "events": events}


@app.get("/api/v1/alerts", tags=["alerts"])
def get_alerts(
    status: Literal["open", "closed", "all"] = "open",
    limit: int = Query(default=100, ge=1, le=500),
):
    alerts = list_alerts(status=status, limit=limit)
    return {"count": len(alerts), "alerts": alerts}


@app.get("/api/v1/alerts/{alert_id}", tags=["alerts"])
def get_alert(alert_id: int):
    result = get_alert_detail(alert_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return result


@app.post("/api/v1/alerts/{alert_id}/close", tags=["alerts"])
def resolve_alert(alert_id: int):
    if not close_alert(alert_id):
        raise HTTPException(
            status_code=404,
            detail="Open alert not found",
        )

    return {"id": alert_id, "status": "closed"}
