import logging
from collections import defaultdict
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.ai.classifier import classify_batch, classify_event
from backend.detection.rules import DetectionEngine
from backend.models.schemas import (
    AnalysisResult,
    LogSource,
    Severity,
    SuspiciousEvent,
    UploadResponse,
)
from backend.parsers.auth_log import AuthLogParser
from backend.parsers.nginx_log import NginxLogParser
from backend.utils.export import export_csv, export_json
from backend.utils.generate_logs import generate_auth_log_content, generate_nginx_log_content

load_dotenv()

MAX_UPLOAD_BYTES = 500_000   # 500 KB

logging.basicConfig(level=logging.DEBUG, format="%(levelname)s │ %(name)s │ %(message)s")
logger = logging.getLogger(__name__)

PARSERS = {
    LogSource.AUTH: AuthLogParser(),
    LogSource.NGINX: NginxLogParser(),
}

detection_engine = DetectionEngine()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Security Log Analyzer started.")
    yield
    logger.info("Shutting down.")


app = FastAPI(
    title="Security Log Analyzer",
    description="Parse, detect, and AI-classify suspicious events in security logs.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="frontend"), name="static")


@app.get("/", include_in_schema=False)
async def serve_ui():
    return FileResponse("frontend/index.html")


@app.post("/analyze", response_model=UploadResponse)
async def analyze_log(
    file: UploadFile = File(...),
    log_type: LogSource = LogSource.AUTH,
):
    content = (await file.read()).decode("utf-8", errors="replace")
    if not content.strip():
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    if len(content.encode()) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=400, detail=f"File too large. Maximum size is {MAX_UPLOAD_BYTES // 1000} KB.")

    parser = PARSERS.get(log_type)
    if not parser:
        raise HTTPException(status_code=400, detail=f"Unsupported log type: {log_type}")

    logger.info("Parsing %s log (%d bytes)…", log_type.value, len(content))
    events = parser.parse_file(content)
    logger.info("Parsed %d events.", len(events))

    suspicious = detection_engine.run(events)
    logger.info("Detected %d suspicious events.", len(suspicious))

    ip_summary: dict[str, int] = defaultdict(int)
    for ev in suspicious:
        if ev.event.source_ip:
            ip_summary[ev.event.source_ip] += 1

    result = AnalysisResult(
        total_events=len(events),
        suspicious_count=len(suspicious),
        high_severity_count=sum(1 for e in suspicious if e.severity == Severity.HIGH),
        medium_severity_count=sum(1 for e in suspicious if e.severity == Severity.MEDIUM),
        low_severity_count=sum(1 for e in suspicious if e.severity == Severity.LOW),
        all_events=events,
        suspicious_events=suspicious,
        ip_summary=dict(ip_summary),
        log_source=log_type,
    )

    return UploadResponse(message="Analysis complete.", result=result)


@app.post("/classify", response_model=SuspiciousEvent)
async def classify_single(event: SuspiciousEvent):
    """Classify a single suspicious event on demand."""
    return await classify_event(event)


@app.get("/demo/{log_type}")
async def demo_log(log_type: LogSource):
    """Return generated demo log content for the given log type."""
    if log_type == LogSource.AUTH:
        content = generate_auth_log_content()
    else:
        content = generate_nginx_log_content()
    return JSONResponse({"content": content, "log_type": log_type.value})


@app.get("/export/json")
async def export_json_route(file_path: str):
    path = export_json(file_path)
    return FileResponse(path, media_type="application/json", filename="suspicious_events.json")


@app.get("/export/csv")
async def export_csv_route(file_path: str):
    path = export_csv(file_path)
    return FileResponse(path, media_type="text/csv", filename="suspicious_events.csv")


@app.get("/health")
async def health():
    return JSONResponse({"status": "ok"})