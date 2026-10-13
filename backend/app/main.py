from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pathlib import Path
import time

from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.db.session import init_db
from backend.app.api.v1 import analyze, policies, audit

app = FastAPI(
    title="ZENTRIQ",
    description="Task-aware runtime security layer for AI agents",
    version="0.1.0",
)

# --- Auth dependency ---
def verify_api_key(request: Request):
    if not settings.API_KEY_AUTH_ENABLED:
        return
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = auth_header[len("Bearer "):]
    if token != settings.ZENTRIQ_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

# --- Rate limiting (simple in-memory) ---
rate_limit_store: dict[str, list[float]] = {}

def check_rate_limit(request: Request):
    if not settings.RATE_LIMIT_ENABLED:
        return
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    window = settings.RATE_LIMIT_WINDOW_SECONDS
    max_requests = settings.RATE_LIMIT_REQUESTS

    if client_ip not in rate_limit_store:
        rate_limit_store[client_ip] = []

    # Prune old entries
    rate_limit_store[client_ip] = [t for t in rate_limit_store[client_ip] if now - t < window]

    if len(rate_limit_store[client_ip]) >= max_requests:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    rate_limit_store[client_ip].append(now)

# --- Register routes ---
app.include_router(
    analyze.router,
    prefix="/api/v1",
    dependencies=[Depends(verify_api_key), Depends(check_rate_limit)],
    tags=["analyze"]
)
app.include_router(
    policies.router,
    prefix="/api/v1",
    dependencies=[Depends(verify_api_key), Depends(check_rate_limit)],
    tags=["policies"]
)
app.include_router(
    audit.router,
    prefix="/api/v1",
    dependencies=[Depends(verify_api_key), Depends(check_rate_limit)],
    tags=["audit"]
)

# --- Dashboard ---
DASHBOARD_DIR = Path(__file__).resolve().parent.parent.parent / "dashboard" / "static"

@app.get("/dashboard")
def serve_dashboard():
    return FileResponse(DASHBOARD_DIR / "index.html")

# Mount static files for CSS/JS
if DASHBOARD_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(DASHBOARD_DIR)), name="static")

@app.get("/health")
def health():
    return {"status": "healthy", "service": "zentriq", "version": "0.1.0"}

@app.on_event("startup")
def on_startup():
    logger.info("Initializing ZENTRIQ database...")
    init_db()
    logger.info("ZENTRIQ started successfully")
