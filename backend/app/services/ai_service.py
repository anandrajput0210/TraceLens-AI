import json
import os

from openai import OpenAI


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
    api_key = os.getenv("OPENAI_API_KEY")

    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not configured.")

    client = OpenAI(api_key=api_key)

    response = client.responses.create(
        model="gpt-5.6-luna",
        instructions=SYSTEM_PROMPT,
        input=json.dumps(finding, indent=2),
    )

    raw_output = response.output_text

    try:
        return json.loads(raw_output)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "AI returned an invalid JSON response."
        ) from exc