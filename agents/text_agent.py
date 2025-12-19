import json
import requests
from typing import Dict, Any

from .validators import validate_agent_output

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3"

TEXT_AGENT_SYSTEM_PROMPT = """
You are the TEXT AGENT in a multi-agent phishing email detection system.

GOAL
- Analyze ONLY the textual content (subject + body) of a single email.
- Decide whether the email is phishing, legitimate, or unsure.
- Identify concrete indicators that justify your decision.
- Produce a STRICT JSON object as output, with no extra text.

INPUT VIEW
- You see only:
    - Subject line
    - Email body text
- You MUST NOT assume anything about:
    - Network logs, browser behavior, user history, attachments, or headers.

PHISHING DEFINITION
A phishing email attempts to trick the user into:
- Revealing credentials or sensitive data
- Clicking malicious links
- Transferring money or value
- Installing malware
- Performing actions that benefit an attacker

TEXT-BASED PHISHING INDICATORS
- urgent_threat_or_deadline
- credential_harvesting
- financial_gain_or_reward
- impersonation_of_trusted_entity
- unexpected_or_unusual_request
- language_style_anomaly
- mismatched_context_or_recipient
- excessive_click_or_open_pressure

LEGITIMATE INDICATORS (OPTIONAL)
- reasonable_business_context
- informational_only_no_action_required
- professional_tone_and_language
- no_sensitive_data_requested

DECISION LOGIC
- phishing: strong phishing indicators present
- legitimate: benign content, no phishing indicators
- unsure: weak, ambiguous, or conflicting evidence

OUTPUT FORMAT (STRICT JSON ONLY)

{
  "agent": "text",
  "version": "1.0",
  "view": "text_only",
  "task": "email_phishing_detection",
  "verdict": "phishing | legitimate | unsure",
  "confidence": 0.0,
  "phishing_indicators": [],
  "legitimacy_indicators": [],
  "evidence": [],
  "overall_rationale": "",
  "safety_notes": ""
}

JSON RULES
- Use double quotes
- No comments
- No trailing commas
- If input is empty or invalid, choose "unsure"
"""

# ---------------------------------------------------------------------
# JSON extraction (FAIL-SAFE)
# ---------------------------------------------------------------------

def _extract_json_from_text(raw: str) -> Dict[str, Any]:
    """
    Extract the first JSON object from model output.
    If parsing fails, return empty dict (validator will downgrade safely).
    """
    if not raw:
        return {}

    start = raw.find("{")
    end = raw.rfind("}")

    if start == -1 or end == -1 or end <= start:
        return {}

    json_str = raw[start:end + 1]

    try:
        return json.loads(json_str)
    except json.JSONDecodeError:
        return {}

# ---------------------------------------------------------------------
# Main agent function
# ---------------------------------------------------------------------

def run_text_agent(subject: str, body: str) -> dict:
    """
    Call local Llama 3 (via Ollama /api/generate) to analyze one email.
    Returns a validated Python dict.
    """
    MAX_CHARS = 2000
    if len(body) > MAX_CHARS:
        body = body[:MAX_CHARS] + "\n\n[TRUNCATED]"
    email_text = f"Subject: {subject}\n\nBody:\n{body}"

    prompt = (
        TEXT_AGENT_SYSTEM_PROMPT.strip()
        + "\n\nINPUT:\n"
        + email_text
        + "\n\nReturn STRICT JSON only."
    )

    payload = {
        "model": OLLAMA_MODEL,
        "system": TEXT_AGENT_SYSTEM_PROMPT.strip(),
        "prompt": email_text + "\n\nReturn STRICT JSON only.",
        "format": "json",
        "stream": False,
    }

    try:
        resp = requests.post(
            "http://localhost:11434/api/generate",
            json=payload,
            timeout=180
        )
        resp.raise_for_status()
        data = resp.json()

        raw_content = data.get("response", {})
        if isinstance(raw_content, dict):
            parsed = raw_content
        else:
            parsed = _extract_json_from_text(str(raw_content))

    except Exception as e:
        print("TEXT AGENT ERROR:", repr(e))
        parsed = {}

    return validate_agent_output(parsed, agent_name="text")

# ---------------------------------------------------------------------
# Manual test
# ---------------------------------------------------------------------

if __name__ == "__main__":
    test_subject = "Important: Verify your account immediately"
    test_body = (
        "Dear user,\n\n"
        "We detected unusual activity in your account. "
        "If you do not verify your password within 24 hours, "
        "your account will be closed.\n\n"
        "Please click the link below.\n\n"
        "Security Team"
    )

    result = run_text_agent(test_subject, test_body)
    print(json.dumps(result, indent=2))