import json
import requests
from typing import Any, Dict

from .validators import validate_agent_output

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3"

METADATA_AGENT_SYSTEM_PROMPT = """
You are the METADATA AGENT in a multi-agent phishing email detection system.

GOAL
- Analyze ONLY email metadata / headers provided as text fields.
- Decide whether the email is phishing, legitimate, or unsure.
- Identify concrete indicators that justify your decision.
- Output STRICT JSON only.

INPUT VIEW
- You may see fields like:
  - From, Reply-To, To, Return-Path, Message-ID, Date
  - SPF/DKIM/DMARC results (if provided)
- You MUST NOT assume email body meaning or URL contents.

PHISHING INDICATORS (metadata-based)
- from_domain_mismatch
- reply_to_mismatch
- display_name_impersonation
- spf_fail_or_softfail
- dkim_fail
- dmarc_fail
- suspicious_sender_domain
- unusual_message_id_domain
- external_sender_claims_internal

LEGITIMATE INDICATORS (optional)
- spf_pass
- dkim_pass
- dmarc_pass
- consistent_from_and_reply_to
- known_org_domain (only if clearly shown in metadata)

OUTPUT FORMAT (STRICT JSON ONLY)

{
  "agent": "metadata",
  "version": "1.0",
  "view": "metadata_only",
  "task": "email_phishing_detection",
  "verdict": "phishing | legitimate | unsure",
  "confidence": 0.0,
  "phishing_indicators": [],
  "legitimacy_indicators": [],
  "evidence": [
    {
      "indicator": "reply_to_mismatch",
      "text_quote": "Reply-To: attacker@evil.com",
      "explanation": "Reply-To differs from From domain, common in impersonation."
    }
  ],
  "overall_rationale": "",
  "safety_notes": ""
}

JSON RULES
- Include ALL keys shown above (never omit keys)
- confidence must be 0.0 to 1.0
- evidence must be a list of objects (indicator, text_quote, explanation)
"""

def run_metadata_agent(headers_text: str) -> Dict[str, Any]:
    prompt = (
        METADATA_AGENT_SYSTEM_PROMPT.strip()
        + "\n\nINPUT:\n"
        + (headers_text.strip() if headers_text else "(no metadata provided)")
        + "\n\nReturn STRICT JSON only."
    )

    payload = {
        "model": OLLAMA_MODEL,
        "system": METADATA_AGENT_SYSTEM_PROMPT.strip(),
        "prompt": (headers_text.strip() if headers_text else "(no metadata provided)") + "\n\nReturn STRICT JSON only.",
        "format": "json",
        "stream": False,
    }

    try:
        resp = requests.post(OLLAMA_URL, json=payload, timeout=180)
        resp.raise_for_status()

        data = resp.json()
        
        raw_content = data.get("response", {})
        if isinstance(raw_content, dict):
            parsed = raw_content
        else:
            # If response is string for any reason, attempt parse
            s = str(raw_content)
            start = s.find("{")
            end = s.rfind("}")
            parsed = {}
            if start != -1 and end != -1 and end > start:
                try:
                    parsed = json.loads(s[start:end + 1])
                except Exception:
                    parsed = {}

    except Exception as e:

        parsed = {}


    return validate_agent_output(parsed, agent_name="metadata")

if __name__ == "__main__":
    sample_headers = (
        "From: \"Microsoft Security\" <security-alert@m1crosoft-support.com>\n"
        "Reply-To: helpdesk@evil.com\n"
        "Return-Path: bounce@randommailer.net\n"
        "Authentication-Results: spf=fail dkim=fail dmarc=fail\n"
    )
    result = run_metadata_agent(sample_headers)
    print(json.dumps(result, indent=2))