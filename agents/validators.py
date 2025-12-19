# agents/validators.py

from __future__ import annotations
from typing import Any, Dict, List

from .schema import (
    ALLOWED_VERDICTS,
    PHISHING_INDICATORS,
    LEGITIMACY_INDICATORS,
    REQUIRED_KEYS,
)

def _safe_unsure(agent_name: str, reason: str) -> Dict[str, Any]:
    return {
        "agent": agent_name,
        "version": "1.0",
        "view": f"{agent_name}_only" if agent_name != "metadata" else "metadata_only",
        "task": "email_phishing_detection",
        "verdict": "unsure",
        "confidence": 0.0,
        "phishing_indicators": [],
        "legitimacy_indicators": [],
        "evidence": [],
        "overall_rationale": reason,
        "safety_notes": "",
    }

def validate_agent_output(obj: Dict[str, Any], agent_name: str) -> Dict[str, Any]:
    # Basic type check
    if not isinstance(obj, dict):
        return _safe_unsure(agent_name, "Agent output is not a JSON object (dict).")

    # Required keys
    missing = REQUIRED_KEYS - set(obj.keys())
    if missing:
        return _safe_unsure(agent_name, f"Agent output missing keys: {sorted(missing)}")

    # Verdict
    verdict = obj.get("verdict")
    if verdict not in ALLOWED_VERDICTS:
        return _safe_unsure(agent_name, f"Invalid verdict: {verdict!r}")

    # Confidence
    conf = obj.get("confidence")
    try:
        conf = float(conf)
    except Exception:
        return _safe_unsure(agent_name, f"Confidence is not a number: {conf!r}")
    conf = max(0.0, min(1.0, conf))
    obj["confidence"] = conf

    # Indicators normalize to list[str], filter unknown
    def _normalize_list(value: Any) -> List[str]:
        if value is None:
            return []
        if isinstance(value, list):
            return [str(x) for x in value]
        return [str(value)]

    p_inds = _normalize_list(obj.get("phishing_indicators"))
    l_inds = _normalize_list(obj.get("legitimacy_indicators"))

    obj["phishing_indicators"] = [x for x in p_inds if x in PHISHING_INDICATORS]
    obj["legitimacy_indicators"] = [x for x in l_inds if x in LEGITIMACY_INDICATORS]

    # Evidence should be list
    ev = obj.get("evidence")
    if not isinstance(ev, list):
        obj["evidence"] = []

    # Agent name consistency (don’t hard-fail, just overwrite)
    obj["agent"] = agent_name

    return obj
# agents/text_agent.py