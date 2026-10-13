from backend.app.security.models import Relevance

# Keywords that indicate dangerous actions
DANGEROUS_KEYWORDS = {
    "delete_all", "drop_database", "rm_rf", "format_disk", "wipe",
    "exfiltrate", "steal", "inject", "exploit", "attack",
    "destroy", "corrupt", "bypass_security", "disable_auth",
    "ransomware", "malware", "backdoor"
}

# Keywords indicating privilege escalation
ESCALATION_KEYWORDS = {
    "write", "delete", "exec", "upload", "escalate", "grant",
    "privesc", "sudo", "admin", "root", "chmod", "chown",
    "privilege", "escalation", "permission"
}

def classify_relevance(action_type: str, description: str, task_id: str | None, session_id: str | None) -> Relevance:
    """Classify the relevance of an action to the current task/session context.
    Deterministic: same inputs always produce the same classification."""
    action_lower = action_type.lower()
    desc_lower = description.lower()
    combined = f"{action_lower} {desc_lower}"

    # Check for dangerous actions first
    for keyword in DANGEROUS_KEYWORDS:
        if keyword in combined.replace(" ", "_") or keyword in combined:
            return Relevance.DANGEROUS

    # If no task/session context, we can't determine relevance
    if not task_id and not session_id:
        return Relevance.UNRELATED

    # Task-relevant action types that are generally safe
    relevant_action_types = {
        "read_file", "read", "query", "search", "list", "get",
        "analyze", "summarize", "fetch", "view", "inspect"
    }

    # Potentially relevant but needs caution
    potentially_relevant_types = {
        "write_file", "write", "create", "update", "modify",
        "send", "notify", "transform", "process"
    }

    # Unrelated / risky action types
    unrelated_types = {
        "upload", "external_send", "external_upload",
        "network_call", "install", "configure"
    }

    if action_lower in relevant_action_types:
        return Relevance.RELEVANT
    elif action_lower in potentially_relevant_types:
        return Relevance.POTENTIALLY_RELEVANT
    elif action_lower in unrelated_types:
        return Relevance.UNRELATED

    # Check description for relevance hints
    if any(w in desc_lower for w in ["task", "assigned", "requested", "required"]):
        return Relevance.POTENTIALLY_RELEVANT

    return Relevance.UNRELATED
