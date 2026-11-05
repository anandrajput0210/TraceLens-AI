import logging
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.services.ai_service import explain_finding


logger = logging.getLogger(__name__)

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
        # Provider exceptions may echo sensitive request details.
        logger.warning(
            "AI reasoning service unavailable (exception type: %s)",
            type(exc).__name__,
        )
        raise HTTPException(
            status_code=503,
            detail="AI service unavailable",
        ) from None

    except Exception as exc:
        # Avoid printing arbitrary provider exception text.
        logger.error(
            "AI reasoning request failed (exception type: %s)",
            type(exc).__name__,
        )
        raise HTTPException(
            status_code=500,
            detail="AI reasoning service failed.",
        ) from None
