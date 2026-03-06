from __future__ import annotations

import asyncio
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Literal
from uuid import uuid4

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from agents.action_agent import build_dummy_entities, execute_actions, propose_actions
from agents.hitl_agent import apply_human_validation, build_hitl_recommendation
from agents.report_agent import render_report_text
from graph.graph_builder import create_graph

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(
    title="SOC Multi-Agent System API",
    description="RESTful + WebSocket API for automated security incident analysis with HITL validation",
    version="1.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class IncidentRequest(BaseModel):
    incident: str = Field(..., min_length=10, max_length=50000, description="Incident text to analyze")

    @field_validator("incident")
    @classmethod
    def validate_incident_text(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Incident text cannot be empty")
        return v.strip()


class HealthResponse(BaseModel):
    status: str
    version: str


class ReviewDecisionRequest(BaseModel):
    decision: Literal["approved", "rejected"] = "approved"
    reviewer: str = "human-analyst"
    notes: str = ""
    overrides: Dict[str, Any] = Field(default_factory=dict)
    selected_action_ids: list[str] = Field(default_factory=list)


NODE_LABELS = {
    "ioc_agent": "IOC Extraction",
    "mitre_agent": "MITRE Mapping",
    "cve_agent": "CVE Intelligence",
    "investigation_agent": "Investigation Planning",
    "report_agent": "Report Generation",
}
TOTAL_PIPELINE_STEPS = len(NODE_LABELS)

PENDING_REVIEWS: Dict[str, Dict[str, Any]] = {}
REVIEW_LOCK = threading.Lock()

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _map_runtime_error(msg: str) -> Dict[str, Any]:
    if msg.startswith("LLM_RATE_LIMIT:"):
        return {
            "status_code": status.HTTP_429_TOO_MANY_REQUESTS,
            "detail": {
                "error": "rate_limit_exceeded",
                "message": "LLM API rate limit reached. Please try again later.",
                "provider_detail": msg,
            },
        }
    if msg.startswith("LLM_API_ERROR:"):
        return {
            "status_code": status.HTTP_502_BAD_GATEWAY,
            "detail": {
                "error": "llm_api_error",
                "message": "LLM provider API error. Please try again later.",
                "provider_detail": msg,
            },
        }
    if msg.startswith("LLM_ERROR:") or msg.startswith("LLM_UNKNOWN_ERROR:"):
        return {
            "status_code": status.HTTP_500_INTERNAL_SERVER_ERROR,
            "detail": {
                "error": "llm_error",
                "message": "Error communicating with LLM provider.",
                "provider_detail": msg,
            },
        }
    return {
        "status_code": status.HTTP_500_INTERNAL_SERVER_ERROR,
        "detail": {
            "error": "analysis_error",
            "message": "Error during incident analysis",
            "detail": msg,
        },
    }


def _enqueue(loop: asyncio.AbstractEventLoop, queue: "asyncio.Queue[Dict[str, Any]]", event: Dict[str, Any]) -> None:
    loop.call_soon_threadsafe(queue.put_nowait, event)


def _run_graph_worker(
    incident: str,
    loop: asyncio.AbstractEventLoop,
    queue: "asyncio.Queue[Dict[str, Any]]",
) -> None:
    try:
        graph = create_graph()
        initial_state = {"input_text": incident}
        result = dict(initial_state)
        completed_steps = 0

        _enqueue(loop, queue, {"type": "status", "progress": 0, "message": "Pipeline started"})

        for step_output in graph.stream(initial_state):
            for node_name, node_result in step_output.items():
                if isinstance(node_result, dict):
                    result.update(node_result)

                completed_steps += 1
                progress = int((completed_steps / TOTAL_PIPELINE_STEPS) * 100)
                _enqueue(
                    loop,
                    queue,
                    {
                        "type": "step",
                        "node": node_name,
                        "label": NODE_LABELS.get(node_name, node_name),
                        "progress": progress,
                        "message": f"{NODE_LABELS.get(node_name, node_name)} completed",
                    },
                )

        recommendation = build_hitl_recommendation(
            incident_text=incident,
            report=result.get("report", {}) or {},
        )
        dummy_entities = build_dummy_entities(incident, result.get("report", {}) or {})
        proposed_actions = propose_actions(dummy_entities)
        session_id = str(uuid4())
        with REVIEW_LOCK:
            PENDING_REVIEWS[session_id] = {
                "status": "pending_validation",
                "created_at": _utc_now(),
                "incident_preview": incident[:200],
                "result": result,
                "recommendation": recommendation,
                "dummy_entities": dummy_entities,
                "proposed_actions": proposed_actions,
            }

        _enqueue(
            loop,
            queue,
            {
                "type": "validation_required",
                "progress": 100,
                "session_id": session_id,
                "recommendation": recommendation,
                "dummy_entities": dummy_entities,
                "proposed_actions": proposed_actions,
                "message": "Human validation required before action finalization.",
            },
        )

    except RuntimeError as exc:
        mapped = _map_runtime_error(str(exc))
        _enqueue(
            loop,
            queue,
            {
                "type": "error",
                "status_code": mapped["status_code"],
                "detail": mapped["detail"],
            },
        )
    except Exception as exc:
        _enqueue(
            loop,
            queue,
            {
                "type": "error",
                "status_code": status.HTTP_500_INTERNAL_SERVER_ERROR,
                "detail": {
                    "error": "internal_error",
                    "message": "Unexpected error during analysis",
                    "detail": str(exc),
                },
            },
        )
    finally:
        _enqueue(loop, queue, {"type": "done"})


@app.get("/", include_in_schema=False)
async def ui_home():
    index_path = STATIC_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="UI not found")
    return FileResponse(index_path)


@app.get("/health", response_model=HealthResponse)
async def health_check():
    return HealthResponse(status="healthy", version="1.2.0")


@app.post("/analyze")
async def analyze_incident(request: IncidentRequest) -> Dict[str, Any]:
    try:
        graph = create_graph()
        initial_state = {"input_text": request.incident}
        try:
            output = graph.invoke(initial_state)
            return output
        except RuntimeError as exc:
            mapped = _map_runtime_error(str(exc))
            raise HTTPException(status_code=mapped["status_code"], detail=mapped["detail"])
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "internal_error",
                "message": "Unexpected error during analysis",
                "detail": str(exc),
            },
        )


@app.get("/review/{session_id}")
async def get_review(session_id: str) -> Dict[str, Any]:
    with REVIEW_LOCK:
        item = PENDING_REVIEWS.get(session_id)
    if not item:
        raise HTTPException(status_code=404, detail={"error": "not_found", "message": "Review session not found"})

    return {
        "session_id": session_id,
        "status": item.get("status"),
        "created_at": item.get("created_at"),
        "recommendation": item.get("recommendation", {}),
        "dummy_entities": item.get("dummy_entities", {}),
        "proposed_actions": item.get("proposed_actions", []),
    }


@app.post("/review/{session_id}/decision")
async def submit_review_decision(session_id: str, request: ReviewDecisionRequest) -> Dict[str, Any]:
    with REVIEW_LOCK:
        item = PENDING_REVIEWS.get(session_id)
    if not item:
        raise HTTPException(status_code=404, detail={"error": "not_found", "message": "Review session not found"})

    if item.get("status") != "pending_validation":
        raise HTTPException(
            status_code=409,
            detail={"error": "invalid_state", "message": f"Session is '{item.get('status')}'"},
        )

    final_result = apply_human_validation(
        result=item["result"],
        recommendation=item["recommendation"],
        decision=request.decision,
        reviewer=request.reviewer,
        notes=request.notes,
        overrides=request.overrides,
    )
    action_execution_log = []
    if request.decision == "approved" and request.selected_action_ids:
        action_execution_log = execute_actions(
            entities=item.get("dummy_entities", {}),
            actions=item.get("proposed_actions", []),
            selected_action_ids=request.selected_action_ids,
        )

    report = dict(final_result.get("report", {}) or {})
    report["simulated_environment"] = item.get("dummy_entities", {})
    report["response_actions"] = action_execution_log
    final_result["report"] = report
    final_result["report_text"] = render_report_text(final_result.get("report", {}) or {})

    with REVIEW_LOCK:
        item["status"] = "completed"
        item["decision"] = request.decision
        item["reviewed_at"] = _utc_now()
        item["final_result"] = final_result
        item["selected_action_ids"] = request.selected_action_ids

    return {
        "session_id": session_id,
        "status": "completed",
        "decision": request.decision,
        "action_execution_log": action_execution_log,
        "result": final_result,
    }


@app.websocket("/ws/analyze")
async def analyze_incident_stream(websocket: WebSocket):
    await websocket.accept()
    try:
        payload = await websocket.receive_json()
        incident = str(payload.get("incident", "")).strip()
        if len(incident) < 10:
            await websocket.send_json(
                {
                    "type": "error",
                    "status_code": status.HTTP_422_UNPROCESSABLE_ENTITY,
                    "detail": {
                        "error": "validation_error",
                        "message": "Incident text must have at least 10 characters.",
                    },
                }
            )
            await websocket.send_json({"type": "done"})
            return

        loop = asyncio.get_running_loop()
        queue: "asyncio.Queue[Dict[str, Any]]" = asyncio.Queue()
        worker = threading.Thread(target=_run_graph_worker, args=(incident, loop, queue), daemon=True)
        worker.start()

        while True:
            event = await queue.get()
            await websocket.send_json(event)
            if event.get("type") == "done":
                break
    except WebSocketDisconnect:
        return
