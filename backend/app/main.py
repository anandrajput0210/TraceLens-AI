import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.middleware.request_size_limit import RequestBodySizeLimitMiddleware

from app.api.analyze import router as analyze_router
from app.api.ai import router as ai_router
DEFAULT_ALLOWED_ORIGINS = (
    "http://localhost:3000",
    "http://127.0.0.1:3000",
)


def get_allowed_origins() -> list[str]:
    """Read explicit browser origins from environment with safe local defaults."""
    from urllib.parse import urlsplit

    configured = os.getenv("TRACELENS_ALLOWED_ORIGINS", "").strip()
    if not configured:
        return list(DEFAULT_ALLOWED_ORIGINS)

    origins = [item.strip().rstrip("/") for item in configured.split(",") if item.strip()]
    if not origins:
        raise ValueError("TRACELENS_ALLOWED_ORIGINS must contain explicit origins.")
    if "*" in origins:
        raise ValueError("Wildcard CORS origins are not allowed when credentials are enabled.")

    for origin in origins:
        parsed = urlsplit(origin)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ValueError("TRACELENS_ALLOWED_ORIGINS must contain only HTTP(S) origins, without paths or credentials.")
        try:
            _ = parsed.port
        except ValueError as error:
            raise ValueError("TRACELENS_ALLOWED_ORIGINS contains an invalid port.") from error

    return origins


app = FastAPI(
    title="TraceLens AI",
    description="Context-aware security risk intelligence",
    version="0.1.0",
)

# Reject oversized analyze requests before multipart form parsing buffers them.
app.add_middleware(
    RequestBodySizeLimitMiddleware,
    max_body_size=51000000,
    paths={"/api/analyze"},
)


# =========================================================
# CORS
# =========================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_allowed_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# API ROUTES
# =========================================================
app.include_router(analyze_router)
app.include_router(ai_router)

@app.get("/")
def root():
    return {
        "name": "TraceLens AI",
        "status": "online",
        "message": "Security findings aren't equal.",
    }


@app.get("/api/health")
def health():
    return {
        "status": "healthy",
    }