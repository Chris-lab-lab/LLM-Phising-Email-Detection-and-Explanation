from typing import Dict, Any, Iterable

# -----------------------------
# Scoring configuration
# -----------------------------

PHISHING_SCORE = {
    "phishing": 1.0,
    "unsure": 0.0,
    "legitimate": -1.0,
}

AGENT_WEIGHTS = {
    "text": 0.4,
    "url": 0.4,
    "metadata": 0.2,
}

HARD_METADATA_INDICATORS = {
    "spf_fail_or_softfail",
    "dkim_fail",
    "dmarc_fail",
    "reply_to_mismatch",
}

PHISHING_THRESHOLD = 0.3
LEGITIMATE_THRESHOLD = -0.3


# -----------------------------
# Helper utilities
# -----------------------------

def _safe_float(x: Any) -> float:
    try:
        return float(x)
    except Exception:
        return 0.0


def _collect_unique(agent_results: Iterable[Dict[str, Any]], key: str):
    out = set()
    for r in agent_results:
        out.update(r.get(key, []))
    return list(out)


# -----------------------------
# Main orchestration logic
# -----------------------------

def combine_agents(
    text_result: Dict[str, Any],
    url_result: Dict[str, Any],
    metadata_result: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Combine agent outputs into a single phishing verdict.

    This function is agnostic to how agents are executed:
    - works with 3 separate Ollama calls
    - works with 1 unified Ollama call
    """

    agents = {
        "text": text_result,
        "url": url_result,
        "metadata": metadata_result,
    }

    # -------------------------
    # HARD OVERRIDE (metadata)
    # -------------------------
    meta_verdict = metadata_result.get("verdict", "unsure")
    meta_conf = _safe_float(metadata_result.get("confidence", 0.0))
    meta_inds = set(metadata_result.get("phishing_indicators", []))

    if (
        AGENT_WEIGHTS.get("metadata", 0.0) > 0
        and meta_verdict == "phishing"
        and meta_conf >= 0.7
        and meta_inds & HARD_METADATA_INDICATORS
    ):
        return {
            "verdict": "phishing",
            "score": 1.0,
            "phishing_indicators": list(meta_inds),
            "legitimacy_indicators": metadata_result.get(
                "legitimacy_indicators", []
            ),
            "evidence": metadata_result.get("evidence", []),
        }

    # -------------------------
    # Weighted scoring
    # -------------------------
    weighted_sum = 0.0
    total_weight = 0.0

    for name, result in agents.items():
        weight = AGENT_WEIGHTS.get(name, 0.0)
        if weight <= 0:
            continue

        verdict = result.get("verdict", "unsure")
        confidence = _safe_float(result.get("confidence", 0.0))
        score = PHISHING_SCORE.get(verdict, 0.0)

        weighted_sum += score * confidence * weight
        total_weight += weight

    final_score = weighted_sum / total_weight if total_weight > 0 else 0.0

    # -------------------------
    # Final verdict
    # -------------------------
    if final_score > PHISHING_THRESHOLD:
        final_verdict = "phishing"
    elif final_score < LEGITIMATE_THRESHOLD:
        final_verdict = "legitimate"
    else:
        final_verdict = "unsure"

    return {
        "verdict": final_verdict,
        "score": round(final_score, 3),
        "phishing_indicators": _collect_unique(
            agents.values(), "phishing_indicators"
        ),
        "legitimacy_indicators": _collect_unique(
            agents.values(), "legitimacy_indicators"
        ),
        "evidence": sum(
            (a.get("evidence", []) for a in agents.values()), []
        ),
    }
