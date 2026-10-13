from enum import Enum

class Relevance(str, Enum):
    RELEVANT = "RELEVANT"
    POTENTIALLY_RELEVANT = "POTENTIALLY_RELEVANT"
    UNRELATED = "UNRELATED"
    DANGEROUS = "DANGEROUS"

class Decision(str, Enum):
    ALLOW = "ALLOW"
    RESTRICT = "RESTRICT"
    BLOCK = "BLOCK"

class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
