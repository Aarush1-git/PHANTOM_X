import time
import logging
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.config import settings
from app.api.v1.api import api_router
from app.websocket.manager import ws_manager

# Configure logging
logging.basicConfig(
    level=logging.INFO if not settings.DEBUG else logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("phantom_x")

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Autonomous Application Security Intelligence — The application that investigates itself.",
    version=settings.VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.DEBUG else settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request timing and tracing middleware
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


# Centralized exception handlers
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.warning(f"Validation error on {request.url.path}: {exc.errors()}")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": exc.errors(), "body": str(exc.body)},
    )


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error on {request.url.path}: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal server error occurred within PHANTOM-X security runtime."},
    )


# WebSocket Endpoints
@app.websocket("/api/v1/ws/live")
async def websocket_global_feed(websocket: WebSocket):
    await ws_manager.connect_global(websocket)
    try:
        while True:
            # Echo or heartbeat
            data = await websocket.receive_text()
            await websocket.send_json({"event": "PONG", "payload": data})
    except WebSocketDisconnect:
        ws_manager.disconnect_global(websocket)


@app.websocket("/api/v1/ws/{scan_id}")
async def websocket_scan_telemetry(websocket: WebSocket, scan_id: str):
    await ws_manager.connect_scan(scan_id, websocket)
    try:
        while True:
            data = await websocket.receive_text()
            await websocket.send_json({
                "scan_id": scan_id,
                "event": "HEARTBEAT_ACK",
                "received": data
            })
    except WebSocketDisconnect:
        ws_manager.disconnect_scan(scan_id, websocket)


# Root health endpoint
@app.get("/health", tags=["Health"])
async def root_health():
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "tagline": "Discover. Understand. Challenge. Prove. Protect.",
        "version": settings.VERSION,
    }


# Mount API V1
app.include_router(api_router, prefix=settings.API_V1_STR)

