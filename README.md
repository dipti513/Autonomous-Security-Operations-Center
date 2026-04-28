# Zero-Trust ASOC MVP

This repository contains a greenfield Autonomous Security Operations Center (ASOC) demo with three services:

- `spring-boot-app`: the protected application and firewall enforcement API
- `ai-orchestrator`: the LangGraph-style AI security team and audit/event stream
- `react-dashboard`: the live SOC dashboard for incidents, health, and agent chatter

## Architecture

- Spring Boot emits traffic telemetry and exposes deterministic firewall/admin endpoints.
- The AI orchestrator ingests traffic events and vulnerability findings, applies specialist analysis, and decides whether to block an IP.
- The dashboard renders the agent terminal feed and current system state over WebSockets.
- PostgreSQL stores incidents, firewall actions, and audit entries.
- A vector layer is represented by fingerprint storage hooks so the MVP can enrich explanations without making enforcement decisions from retrieval alone.

## Repository Layout

- [spring-boot-app](C:\Users\Aditi\OneDrive\Desktop\ASOC\spring-boot-app)
- [ai-orchestrator](C:\Users\Aditi\OneDrive\Desktop\ASOC\ai-orchestrator)
- [react-dashboard](C:\Users\Aditi\OneDrive\Desktop\ASOC\react-dashboard)
- [ops](C:\Users\Aditi\OneDrive\Desktop\ASOC\ops)

## Local Notes

- The workspace currently has bundled Python and Node runtimes available through Codex.
- Java and Maven are not installed on PATH in this environment, so the Spring Boot service is scaffolded but not executed here.
- The Python service includes runnable unit tests for core detection and orchestration logic.

## Suggested Run Order

1. Start PostgreSQL with pgvector support.
2. Start the Spring Boot app.
3. Start the AI orchestrator.
4. Start the React dashboard.
5. Send traffic events or trigger a vulnerability scan to watch the agents coordinate live.

## AI Orchestrator

Install the Python dependencies, then run:

```powershell
cd ai-orchestrator
$env:ASOC_SPRING_APP_BASE_URL = "http://localhost:8080"
$env:ASOC_ADMIN_TOKEN = "changeme-admin-token"
python -m uvicorn app.main:app --reload --port 8000
```

The responder uses `ASOC_SPRING_APP_BASE_URL` and `ASOC_ADMIN_TOKEN` to call the Spring firewall endpoint. If those are omitted, it falls back to simulated enforcement.

## Spring Boot App

Run the protected application with a JDK 17+ toolchain:

```powershell
cd spring-boot-app
mvn spring-boot:run
```

Admin endpoints require the `X-Admin-Token` header matching `asoc.admin-token` in [application.yml](C:\Users\Aditi\OneDrive\Desktop\ASOC\spring-boot-app\src\main\resources\application.yml).

## React Dashboard

Install frontend packages and run:

```powershell
cd react-dashboard
npm install
npm run dev
```

The dashboard expects the AI orchestrator at `http://localhost:8000`.

## Verification

The Python core logic is covered by unit tests:

```powershell
cd ai-orchestrator
python -m unittest discover -s tests -v
```
