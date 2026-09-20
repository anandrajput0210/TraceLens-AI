from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.services.ai_service import explain_finding


router = APIRouter(
    prefix="/api/ai",
    tags=["AI"],
)


class AIExplainRequest(BaseModel):
    finding: dict


@router.post("/explain")
def explain(request: AIExplainRequest):
    try:
        result = explain_finding(request.finding)

        return {
            "summary": result.get(
                "summary",
                "No summary was generated.",
            ),
            "impact": result.get(
                "impact",
                "No impact explanation was generated.",
            ),
            "recommendation": result.get(
                "recommendation",
                "No recommendation was generated.",
            ),
        }

    except RuntimeError as exc:
        raise HTTPException(
            status_code=503,
            detail=str(exc),
        )

    except Exception as exc:
        print(f"AI service error: {exc}")

        raise HTTPException(
            status_code=500,
            detail="AI reasoning service failed.",
        )