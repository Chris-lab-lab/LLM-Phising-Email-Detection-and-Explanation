import json
import re
import requests
from typing import Any, Dict, List

from .validators import validate_agent_output

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3"

URL_AGENT_SYSTEM_PROMPT = """
You are the URL AGENT in a multi-agent phishing email detection system.

GOAL
- Analyze ONLY URL strings (and optional anchor text if provided).
- Decide whether the URL set is phishing, legitimate, or unsure.
- Identify concrete indicators that justify your decision.
- Output STRICT JSON only (no extra text).

INPUT VIEW
- You see only URLs as strings (and optional anchor text).
- You MUST NOT assume email body meaning, sender identity, headers, or attachments.
- Do NOT browse the web. Do NOT claim to have visited the URL.

URL-BASED PHISHING INDICATORS
- ip_based_url
- url_shortener
- suspicious_tld
- typosquatting_or_lookalike_domain
- suspicious_subdomain_depth
- credential_path_or_login_lure
- unusual_query_params
- mismatch_display_vs_link (if anchor provided)

LEGITIMATE INDICATORS (OPTIONAL)
- well_known_domain
- consistent_brand_domain
- https_present (weak indicator)
- simple_url_structure

DECISION LOGIC
- phishing: strong URL red flags present
- legitimate: URLs look normal, no red flags
- unsure: too few URLs, ambiguous, or conflicting

OUTPUT FORMAT (STRICT JSON ONLY)

{
  "agent": "url",
  "version": "1.0",
  "view": "url_only",
  "task": "email_phishing_detection",
  "verdict": "phishing | legitimate | unsure",
  "confidence": 0.0,
  "phishing_indicators": [],
  "legitimacy_indicators": [],
  "evidence": [
  {
    "indicator": "ip_based_url",
    "text_quote": "http://192.168.0.5/update",
    "explanation": "IP-based URLs are uncommon in legitimate login/update flows and often used in phishing."
  }
  ],
  "overall_rationale": "",
  "safety_notes": ""
}

JSON RULES
- Use double quotes
- No comments, no trailing commas
- confidence must be 0.0 to 1.0
- You MUST include ALL keys shown in the output format.
- Do NOT omit verdict/confidence/indicators/evidence/overall_rationale even if unsure.
- evidence MUST be a list of objects with keys: indicator, text_quote, explanation.

"""

def _extract_json_from_text(raw: str) -> Dict[str, Any]:
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

def extract_urls_from_text(text: str) -> List[str]:
    if not text:
        return []
    # Basic URL regex sufficient for student project
    pattern = r"(https?://[^\s)>\]]+)"
    return re.findall(pattern, text)

def run_url_agent(urls: List[str]) -> Dict[str, Any]:
    url_block = "\n".join(urls) if urls else "(no urls provided)"

    prompt = (
        URL_AGENT_SYSTEM_PROMPT.strip()
        + "\n\n"
        + "INPUT:\n"
        + f"URLs:\n{url_block}\n"
        + "\nReturn STRICT JSON only."
    )

    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "format": "json",
        "stream": False,
    }

    try:
        resp = requests.post(OLLAMA_URL, json=payload, timeout=60)
        resp.raise_for_status()
        data = resp.json()

        # /api/generate returns text in "response"
        raw_content = data.get("response", {})

        if isinstance(raw_content, dict):
            parsed = raw_content
        else:
            parsed = _extract_json_from_text(raw_content)

    except Exception:
        parsed = {}

    return validate_agent_output(parsed, agent_name="url")

if __name__ == "__main__":
    # Quick manual test
    sample_text = "Please verify: https://secure-paypaI.com/login?session=123 and http://192.168.0.5/update"
    urls = extract_urls_from_text(sample_text)
    result = run_url_agent(urls)
    print(json.dumps(result, indent=2))