from __future__ import annotations

import json
from pathlib import Path
from typing import Any

try:
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect
    from fastapi.middleware.cors import CORSMiddleware
except ModuleNotFoundError as exc:  # pragma: no cover
    raise SystemExit(
        "FastAPI is not installed. Install dependencies from ai-orchestrator/requirements.txt before running the service."
    ) from exc

from .models import TrafficEvent
from .orchestrator import AsocSupervisor


APP_ROOT = Path(__file__).resolve().parents[2]
SPRING_APP_ROOT = APP_ROOT / "spring-boot-app"
supervisor = AsocSupervisor()

app = FastAPI(title="ASOC AI Orchestrator", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/events/traffic")
async def ingest_traffic(payload: dict[str, Any]) -> dict[str, Any]:
    incident = await supervisor.process_traffic_event(TrafficEvent(**payload))
    return incident.to_dict()


@app.post("/events/vuln-scan")
async def ingest_vulnerability_findings(payload: dict[str, Any]) -> dict[str, Any]:
    return {"accepted": True, "payload": payload}


@app.post("/scans/run")
async def run_scan() -> dict[str, Any]:
    findings = await supervisor.run_vulnerability_scan(SPRING_APP_ROOT)
    return {"count": len(findings), "findings": findings}


@app.get("/incidents")
async def list_incidents() -> list[dict[str, Any]]:
    return [incident.to_dict() for incident in supervisor.repository.list_incidents()]


@app.get("/state")
async def state() -> dict[str, Any]:
    return {
        "incidents": [incident.to_dict() for incident in supervisor.repository.list_incidents()],
        "messages": [message.to_dict() for message in supervisor.repository.recent_messages()],
        "blocked": [block.to_dict() for block in supervisor.repository.list_active_blocks()],
        "findings": [finding.to_dict() for finding in supervisor.repository.list_vulnerability_findings()],
    }


@app.websocket("/ws/agent-stream")
async def agent_stream(socket: WebSocket) -> None:
    await socket.accept()
    queue = await supervisor.stream.subscribe()
    try:
        while True:
            payload = await queue.get()
            await socket.send_text(json.dumps(payload))
    except WebSocketDisconnect:
        supervisor.stream.unsubscribe(queue)

