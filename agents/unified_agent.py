import json
import requests
from typing import Any, Dict, List

from .validators import validate_agent_output

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3"

# ------------------------------------------------------------
# Unified system prompt
# ------------------------------------------------------------

UNIFIED_SYSTEM_PROMPT = """
You are a UNIFIED ANALYSIS AGENT for a phishing email detection system.

You MUST return STRICT JSON ONLY with exactly these top-level keys:
{
  "text": { ... },
  "url": { ... },
  "metadata": { ... }
}

Each sub-object MUST include ALL keys required by the agent schema:
- agent
- version
- view
- task
- verdict ("phishing" | "legitimate" | "unsure")
- confidence (0.0 to 1.0)
- phishing_indicators (list)
- legitimacy_indicators (list)
- evidence (list)
- overall_rationale (string)
- safety_notes (string)

ANALYSIS RULES:
- text: analyze ONLY subject + body text.
- url: analyze ONLY URL strings provided. Do NOT browse.
- metadata: analyze ONLY headers text provided. If no metadata is provided,
  set verdict="unsure" and confidence=0.0 with empty indicators/evidence.

INDICATORS:
- Use ONLY indicators defined by the system. Do not invent new ones.
- If evidence is weak or ambiguous, prefer "unsure".

FORMAT RULES:
- Output valid JSON.
- Use double quotes.
- No comments, no trailing commas, no extra text.
"""

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def _extract_json(raw: Any) -> Dict[str, Any]:
    """Extract a JSON object from model output (fail-safe)."""
    if isinstance(raw, dict):
        return raw
    s = "" if raw is None else str(raw)
    start, end = s.find("{"), s.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return {}
    try:
        return json.loads(s[start:end + 1])
    except Exception:
        return {}

# ------------------------------------------------------------
# Main unified agent
# ------------------------------------------------------------

def run_unified_agent(
    subject: str,
    body: str,
    urls: List[str],
    headers_text: str = "",
) -> Dict[str, Dict[str, Any]]:
    """
    Run a single Ollama call that returns text/url/metadata analyses.
    Returns validated sub-objects ready for combine_agents().
    """

    url_block = "\n".join(urls) if urls else "(no urls provided)"
    headers_block = headers_text.strip() if headers_text else "(no metadata provided)"

    user_prompt = f"""
INPUT:
Subject:
{subject}

Body:
{body}

URLs:
{url_block}

Headers:
{headers_block}

Return STRICT JSON only.
"""

    payload = {
        "model": OLLAMA_MODEL,
        "system": UNIFIED_SYSTEM_PROMPT.strip(),
        "prompt": user_prompt,
        "format": "json",
        "stream": False,
    }

    try:
        resp = requests.post(OLLAMA_URL, json=payload, timeout=180)
        resp.raise_for_status()
        data = resp.json()
        parsed = _extract_json(data.get("response"))
    except Exception:
        parsed = {}

    # Validate each sub-object independently (fail-safe)
    text_obj = validate_agent_output(parsed.get("text", {}), agent_name="text")
    url_obj = validate_agent_output(parsed.get("url", {}), agent_name="url")
    meta_obj = validate_agent_output(parsed.get("metadata", {}), agent_name="metadata")

    return {
        "text": text_obj,
        "url": url_obj,
        "metadata": meta_obj,
    }


# ------------------------------------------------------------
# Manual smoke test
# ------------------------------------------------------------

if __name__ == "__main__":
    sample_subject = "Important: Verify your account immediately"
    sample_body = (
        "Dear user,\n\n"
        "We detected unusual activity in your account. "
        "Please verify your password within 24 hours.\n\n"
        "Visit https://secure-paypaI.com/login to continue."
    )
    sample_urls = ["https://secure-paypaI.com/login"]
    sample_headers = ""  # dataset has no metadata

    out = run_unified_agent(
        subject=sample_subject,
        body=sample_body,
        urls=sample_urls,
        headers_text=sample_headers,
    )

    print(json.dumps(out, indent=2))
