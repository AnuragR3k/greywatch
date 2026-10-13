"""Greywatch API entry point."""

from typing import Literal

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from .siem import (
    close_alert,
    get_alert_detail,
    ingest_lines,
    list_alerts,
    list_events,
)
from . import collector

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


@app.get("/api/v1/journal/status", tags=["journal"])
def journal_status():
    """Report journal-collection checkpoint state and enabled flag."""
    return collector.status()


@app.post("/api/v1/journal/collect", tags=["journal"])
def journal_collect():
    """Trigger a single journal collection cycle.

    Useful for manual collection and verification. Collection is also
    controlled by ``GREYWATCH_JOURNAL_ENABLED``; this endpoint runs one cycle
    regardless of that flag. Returns a summary of the cycle.
    """
    config = collector.get_config()
    result = collector.collect_once(config)
    return {
        "records_seen": result.records_seen,
        "events_ingested": result.events_ingested,
        "alerts": result.new_alerts,
        "fallback_used": result.fallback_used,
        "errors": result.errors,
    }
