# agents/schema.py

ALLOWED_VERDICTS = {"phishing", "legitimate", "unsure"}

PHISHING_INDICATORS = {
    # --- text-based ---
    "urgent_threat_or_deadline",
    "credential_harvesting",
    "financial_gain_or_reward",
    "impersonation_of_trusted_entity",
    "unexpected_or_unusual_request",
    "language_style_anomaly",
    "mismatched_context_or_recipient",
    "excessive_click_or_open_pressure",

    # --- url-based ---
    "ip_based_url",
    "url_shortener",
    "suspicious_tld",
    "typosquatting_or_lookalike_domain",
    "suspicious_subdomain_depth",
    "credential_path_or_login_lure",
    "unusual_query_params",
    "mismatch_display_vs_link",

    # --- metadata-based ---
    "from_domain_mismatch",
    "reply_to_mismatch",
    "display_name_impersonation",
    "spf_fail_or_softfail",
    "dkim_fail",
    "dmarc_fail",
    "suspicious_sender_domain",
    "unusual_message_id_domain",
    "external_sender_claims_internal",
}

LEGITIMACY_INDICATORS = {
    "reasonable_business_context",
    "informational_only_no_action_required",
    "professional_tone_and_language",
    "no_sensitive_data_requested",
}

REQUIRED_KEYS = {
    "agent",
    "version",
    "view",
    "task",
    "verdict",
    "confidence",
    "phishing_indicators",
    "legitimacy_indicators",
    "evidence",
    "overall_rationale",
    "safety_notes",
}