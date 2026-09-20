from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.analyze import router as analyze_router
from app.api.ai import router as ai_router
app = FastAPI(
    title="TraceLens AI",
    description="Context-aware security risk intelligence",
    version="0.1.0",
)


# =========================================================
# CORS
# =========================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
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