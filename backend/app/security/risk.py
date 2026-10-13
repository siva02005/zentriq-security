from backend.app.security.models import Relevance, RiskLevel
from backend.app.core.config import settings

SENSITIVE_TAGS = {
    "pii", "credentials", "secret", "password", "api_key", "token",
    "ssn", "credit_card", "health", "financial", "confidential",
    "internal", "classified", "sensitive"
}

EXTERNAL_DESTINATIONS = {
    "external", "public", "third-party", "cloud", "s3", "gcs",
    "dropbox", "drive", "slack", "webhook"
}

def compute_risk(
    relevance: Relevance,
    data_tags: list[str],
    third_party: bool,
    destination: str | None
) -> tuple[RiskLevel, float]:
    """Compute risk level and score deterministically.
    Returns (RiskLevel, risk_score 0.0-1.0)."""
    score = 0.0

    # Base score from relevance
    relevance_scores = {
        Relevance.RELEVANT: 0.05,
        Relevance.POTENTIALLY_RELEVANT: 0.25,
        Relevance.UNRELATED: 0.45,
        Relevance.DANGEROUS: 0.85,
    }
    score = relevance_scores[relevance]

    # Sensitive data tags increase risk
    tag_set = {t.lower() for t in data_tags}
    sensitive_matches = tag_set & SENSITIVE_TAGS
    score += len(sensitive_matches) * 0.1

    # Third party increases risk
    if third_party:
        score += 0.15

    # External destination increases risk
    if destination:
        dest_lower = destination.lower()
        if any(ext in dest_lower for ext in EXTERNAL_DESTINATIONS):
            score += 0.2

    # Clamp to [0.0, 1.0]
    score = round(min(max(score, 0.0), 1.0), 2)

    # Determine risk level from score
    if score < settings.RISK_LOW_THRESHOLD:
        level = RiskLevel.LOW
    elif score < settings.RISK_HIGH_THRESHOLD:
        level = RiskLevel.MEDIUM
    else:
        level = RiskLevel.HIGH

    return level, score
