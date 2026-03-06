from __future__ import annotations

import re
from typing import Any, Dict, List
from uuid import uuid4


def build_dummy_entities(incident_text: str, report: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Build an in-memory lab state from incident text + report context.
    This is intentionally synthetic and safe (no real external execution).
    """
    involved = report.get("involved_parties", {}) or {}
    ioc = report.get("ioc_section", {}) or {}

    affected_users = _unique_strs(involved.get("affected_users", []))
    suspicious_accounts = _unique_strs(involved.get("suspicious_accounts", []))

    parsed_users = _extract_user_candidates(incident_text)
    parsed_cloud = _extract_cloud_accounts(incident_text)
    parsed_hosts = _extract_terminal_candidates(incident_text)

    all_users = _unique_strs(affected_users + suspicious_accounts + parsed_users)
    users = [
        {
            "id": f"user-{idx+1}",
            "username": user,
            "status": "active",
            "risk": "high" if user in suspicious_accounts else "medium",
        }
        for idx, user in enumerate(all_users[:8])
    ]

    clouds = [
        {
            "id": f"cloud-{idx+1}",
            "account": acct,
            "status": "active",
            "risk": "high",
        }
        for idx, acct in enumerate(parsed_cloud[:6])
    ]

    ips = [str(x).strip() for x in ioc.get("ips", []) if str(x).strip()]
    host_candidates = _unique_strs(parsed_hosts + ips)
    terminals = [
        {
            "id": f"terminal-{idx+1}",
            "endpoint": endpoint,
            "status": "connected",
            "risk": "high" if endpoint in ips else "medium",
        }
        for idx, endpoint in enumerate(host_candidates[:8])
    ]

    return {
        "users": users,
        "cloud_accounts": clouds,
        "terminals": terminals,
    }


def propose_actions(entities: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """
    Propose meaningful SOC actions for the synthetic in-memory entities.
    """
    actions: List[Dict[str, Any]] = []

    for user in entities.get("users", []):
        username = user.get("username", "unknown")
        actions.append(
            _make_action(
                action_type="force_password_reset",
                target_kind="user",
                target_id=user["id"],
                title=f"Force password reset for {username}",
                summary="Reset credentials and terminate active sessions.",
                risk="medium",
            )
        )
        if user.get("risk") == "high":
            actions.append(
                _make_action(
                    action_type="disable_user_account",
                    target_kind="user",
                    target_id=user["id"],
                    title=f"Disable account {username}",
                    summary="Temporarily disable account pending IR validation.",
                    risk="high",
                )
            )

    for cloud in entities.get("cloud_accounts", []):
        actions.append(
            _make_action(
                action_type="revoke_cloud_tokens",
                target_kind="cloud_account",
                target_id=cloud["id"],
                title=f"Revoke tokens for {cloud.get('account', 'cloud-account')}",
                summary="Invalidate active API keys/sessions on cloud account.",
                risk="high",
            )
        )

    for terminal in entities.get("terminals", []):
        actions.append(
            _make_action(
                action_type="isolate_terminal",
                target_kind="terminal",
                target_id=terminal["id"],
                title=f"Isolate endpoint {terminal.get('endpoint', 'unknown')}",
                summary="Network isolate endpoint to contain lateral movement.",
                risk="high" if terminal.get("risk") == "high" else "medium",
            )
        )

    return actions[:20]


def execute_actions(
    entities: Dict[str, List[Dict[str, Any]]],
    actions: List[Dict[str, Any]],
    selected_action_ids: List[str],
) -> List[Dict[str, Any]]:
    """
    Execute selected actions against in-memory state only.
    """
    selected = set(selected_action_ids)
    execution_log: List[Dict[str, Any]] = []

    users = {item["id"]: item for item in entities.get("users", [])}
    clouds = {item["id"]: item for item in entities.get("cloud_accounts", [])}
    terminals = {item["id"]: item for item in entities.get("terminals", [])}

    for action in actions:
        action_id = action.get("action_id")
        if action_id not in selected:
            continue

        target_kind = action.get("target_kind")
        target_id = action.get("target_id")
        outcome = "applied"
        message = "Action applied in in-memory lab state."

        if target_kind == "user" and target_id in users:
            if action.get("action_type") == "disable_user_account":
                users[target_id]["status"] = "disabled"
            elif action.get("action_type") == "force_password_reset":
                users[target_id]["status"] = "password_reset_required"
        elif target_kind == "cloud_account" and target_id in clouds:
            clouds[target_id]["status"] = "tokens_revoked"
        elif target_kind == "terminal" and target_id in terminals:
            terminals[target_id]["status"] = "isolated"
        else:
            outcome = "skipped"
            message = "Target not found in current in-memory state."

        execution_log.append(
            {
                "action_id": action_id,
                "title": action.get("title", ""),
                "target_kind": target_kind,
                "target_id": target_id,
                "outcome": outcome,
                "message": message,
            }
        )

    entities["users"] = list(users.values())
    entities["cloud_accounts"] = list(clouds.values())
    entities["terminals"] = list(terminals.values())
    return execution_log


def _make_action(
    action_type: str,
    target_kind: str,
    target_id: str,
    title: str,
    summary: str,
    risk: str,
) -> Dict[str, Any]:
    return {
        "action_id": str(uuid4()),
        "action_type": action_type,
        "target_kind": target_kind,
        "target_id": target_id,
        "title": title,
        "summary": summary,
        "risk": risk,
        "requires_human_approval": True,
        "status": "pending_approval",
    }


def _extract_user_candidates(text: str) -> List[str]:
    email_matches = re.findall(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", text or "")
    user_key_matches = re.findall(r"(?i)\b(?:user|username|account)\s*[:=]\s*([A-Za-z0-9._-]{3,})", text or "")
    return _unique_strs(email_matches + user_key_matches)


def _extract_cloud_accounts(text: str) -> List[str]:
    aws = re.findall(r"\barn:aws:[A-Za-z0-9:/._-]+\b", text or "")
    azure = re.findall(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", text or "")
    gcp = re.findall(r"\b[A-Za-z0-9._-]+@[A-Za-z0-9._-]+\.iam\.gserviceaccount\.com\b", text or "")
    return _unique_strs(aws + azure + gcp)


def _extract_terminal_candidates(text: str) -> List[str]:
    host = re.findall(r"(?i)\b(?:host|hostname|endpoint|workstation|server)\s*[:=]\s*([A-Za-z0-9._-]{3,})", text or "")
    return _unique_strs(host)


def _unique_strs(items: List[Any]) -> List[str]:
    seen = set()
    out: List[str] = []
    for item in items:
        value = str(item).strip()
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out
