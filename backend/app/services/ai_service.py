from google import genai
from google.genai import types

import json
import os
from app.utils.redaction import redact_data


DEFAULT_MODEL = "gemini-3.5-flash-lite"

SYSTEM_PROMPT = """
You are TraceLens AI, a security reasoning assistant.

Your job is NOT to discover new vulnerabilities.
TraceLens has already detected a security finding and calculated
its contextual risk using deterministic repository analysis.

Explain the supplied finding using ONLY the evidence provided.

Rules:
- Do not invent repository behavior.
- Do not claim successful exploitation.
- Do not claim runtime exploitability.
- Treat static reachability as an approximation.
- Treat environment and exposure as inferred context.
- Explain why the contextual risk matters.
- Give practical remediation.
- Keep the response concise and developer-focused.

Return exactly valid JSON:
{
  "summary": "...",
  "impact": "...",
  "recommendation": "..."
}
"""


def explain_finding(finding: dict) -> dict:
    # Explain a pre-computed TraceLens finding with Google's Gemini API.
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY is not configured.")

    model = os.getenv("TRACELENS_AI_MODEL", DEFAULT_MODEL).strip()
    if not model:
        model = DEFAULT_MODEL

    safe_finding = redact_data(finding)
    try:
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model=model,
            contents=json.dumps(safe_finding, indent=2, default=str),
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                response_mime_type="application/json",
                temperature=0.2,
            ),
        )
    except Exception:
        raise RuntimeError("AI service unavailable") from None

    raw_output = getattr(response, "text", None)
    if not isinstance(raw_output, str) or not raw_output.strip():
        raise RuntimeError("AI returned an empty response.")
    try:
        parsed = json.loads(raw_output)
    except json.JSONDecodeError:
        raise RuntimeError("AI returned an invalid JSON response.") from None
    if not isinstance(parsed, dict):
        raise RuntimeError("AI returned an invalid JSON response.")
    return redact_data(parsed)
