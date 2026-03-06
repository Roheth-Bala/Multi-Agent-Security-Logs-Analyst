from __future__ import annotations

import json
from typing import Any, Dict, List

from app.config import call_llm, extract_json_block


def build_hitl_recommendation(
    incident_text: str,
    report: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Builds a human-approval package with:
    - inferred involved parties (5W1H - Who)
    - proposed response actions
    """
    report_summary = {
        "executive_summary": report.get("executive_summary", ""),
        "technical_summary": report.get("technical_summary", ""),
        "involved_parties": report.get("involved_parties", {}),
        "ioc_section": report.get("ioc_section", {}),
        "mitre_mapping": report.get("mitre_mapping", []),
    }

    system_prompt = (
        "You are a SOC L2 analyst. Infer likely involved parties and response actions "
        "from an incident report draft. Be conservative and explicit about confidence."
    )

    user_prompt = f"""
Incident text:
{incident_text}

Report draft context:
{json.dumps(report_summary, ensure_ascii=False)}

Return ONLY valid JSON with this exact schema:
{{
  "involved_parties": {{
    "affected_users": ["user1", "..."],
    "suspicious_accounts": ["acct1", "..."],
    "threat_actor": {{
      "attribution": "Unknown",
      "confidence": "low",
      "indicators": ["..."]
    }},
    "incident_responders": ["SOC L2", "IR lead"]
  }},
  "proposed_actions": [
    "Action 1",
    "Action 2",
    "Action 3"
  ],
  "reasoning_summary": "1-3 lines on why these were suggested"
}}

Rules:
- If unknown, keep values as "Unknown" with low confidence.
- Do not fabricate identities with certainty.
- Keep proposed_actions practical and SOC-executable.
"""

    try:
        response = call_llm(
            [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            provider="groq",
            temperature=0.1,
            max_tokens=800,
        )
        parsed = json.loads(extract_json_block(response))
        return _normalize_hitl_payload(parsed)
    except Exception:
        return _fallback_recommendation(report)


def apply_human_validation(
    result: Dict[str, Any],
    recommendation: Dict[str, Any],
    decision: str,
    reviewer: str,
    notes: str = "",
    overrides: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """
    Applies human decision to the final report payload.
    """
    final_result = dict(result)
    report = dict(final_result.get("report", {}) or {})

    chosen_parties = recommendation.get("involved_parties", {})
    if overrides:
        chosen_parties = _merge_involved_parties(chosen_parties, overrides)

    if decision == "approved":
        report["involved_parties"] = chosen_parties
        report["validated_actions"] = recommendation.get("proposed_actions", [])
    else:
        report["involved_parties"] = report.get("involved_parties", {})
        report["validated_actions"] = []

    report["human_validation"] = {
        "decision": decision,
        "reviewer": reviewer or "human-analyst",
        "notes": notes,
    }

    final_result["report"] = report
    final_result["hitl"] = {
        "decision": decision,
        "recommendation": recommendation,
    }
    return final_result


def _merge_involved_parties(base: Dict[str, Any], overrides: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(base)
    for key, value in (overrides or {}).items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            nested = dict(merged[key])
            nested.update(value)
            merged[key] = nested
        else:
            merged[key] = value
    return merged


def _normalize_hitl_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    involved = payload.get("involved_parties", {}) or {}
    threat_actor = involved.get("threat_actor", {}) or {}

    normalized = {
        "involved_parties": {
            "affected_users": _as_list(involved.get("affected_users")),
            "suspicious_accounts": _as_list(involved.get("suspicious_accounts")),
            "threat_actor": {
                "attribution": str(threat_actor.get("attribution", "Unknown")),
                "confidence": str(threat_actor.get("confidence", "low")).lower(),
                "indicators": _as_list(threat_actor.get("indicators")),
            },
            "incident_responders": _as_list(involved.get("incident_responders")) or ["SOC L2"],
        },
        "proposed_actions": _as_list(payload.get("proposed_actions")),
        "reasoning_summary": str(payload.get("reasoning_summary", "")).strip(),
    }
    return normalized


def _fallback_recommendation(report: Dict[str, Any]) -> Dict[str, Any]:
    iocs = report.get("ioc_section", {}) or {}
    has_iocs = any(
        bool(iocs.get(k))
        for k in ("ips", "domains", "urls", "emails")
    )
    actions: List[str] = [
        "Validate suspicious indicators against SIEM and EDR telemetry.",
        "Contain impacted hosts/accounts pending verification.",
    ]
    if has_iocs:
        actions.append("Block confirmed malicious IOCs at DNS/Firewall/Proxy layers.")

    return {
        "involved_parties": {
            "affected_users": [],
            "suspicious_accounts": [],
            "threat_actor": {
                "attribution": "Unknown",
                "confidence": "low",
                "indicators": [],
            },
            "incident_responders": ["SOC L2"],
        },
        "proposed_actions": actions,
        "reasoning_summary": "Generated using deterministic fallback due to model parsing constraints.",
    }


def _as_list(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if value is None:
        return []
    v = str(value).strip()
    return [v] if v else []
