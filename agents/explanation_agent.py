import json
import requests
from typing import Dict, Any

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3"

EXPLANATION_SYSTEM_PROMPT = """
You are an EXPLANATION AGENT in a phishing email detection system.

GOAL
- Explain the FINAL decision to a non-technical user.
- Do NOT re-evaluate or change the verdict.
- Do NOT introduce new evidence.
- Use ONLY the provided verdict, indicators, and evidence.

STYLE
- Clear and concise
- Calm, non-alarming language
- Bullet points if helpful
- simplied english

OUTPUT
- Plain text explanation only
"""

def run_explanation_agent(final_result: Dict[str, Any]) -> str:
    prompt = (
        EXPLANATION_SYSTEM_PROMPT.strip()
        + "\n\nINPUT:\n"
        + json.dumps(final_result, indent=2)
        + "\n\nExplain the decision."
    )

    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
    }

    try:
        resp = requests.post(OLLAMA_URL, json=payload, timeout=60)
        resp.raise_for_status()
        return resp.json().get("response", "").strip()
    except Exception:
        return "Explanation unavailable."
