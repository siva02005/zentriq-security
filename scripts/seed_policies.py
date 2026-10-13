"""Seed default ZENTRIQ security policies. Idempotent."""
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.app.db.session import init_db, SessionLocal
from backend.app.models.policy import Policy

DEFAULT_POLICIES = [
    {
        "name": "allow-task-relevant-low-risk",
        "description": "Allow actions that are relevant to the current task and have low risk",
        "effect": "ALLOW",
        "priority": 10,
        "action_types": None,
        "destination_patterns": None,
        "data_tags": None,
        "third_party": None,
    },
    {
        "name": "restrict-unrelated-file-access",
        "description": "Restrict file access that is unrelated to the current task",
        "effect": "RESTRICT",
        "priority": 20,
        "action_types": ["read_file"],
        "destination_patterns": None,
        "data_tags": None,
        "third_party": None,
    },
    {
        "name": "block-unrelated-upload",
        "description": "Block uploads and external sends that are unrelated to the task or contain sensitive data",
        "effect": "BLOCK",
        "priority": 30,
        "action_types": ["upload", "external_send"],
        "destination_patterns": ["external", "public", "third-party"],
        "data_tags": ["pii", "credentials", "secret", "confidential"],
        "third_party": None,
    },
    {
        "name": "block-permission-escalation",
        "description": "Block any action that attempts privilege escalation",
        "effect": "BLOCK",
        "priority": 5,
        "action_types": None,
        "destination_patterns": None,
        "data_tags": None,
        "third_party": None,
    },
    {
        "name": "allow-approved-third-party",
        "description": "Allow actions involving approved third-party services when task-relevant",
        "effect": "ALLOW",
        "priority": 15,
        "action_types": None,
        "destination_patterns": None,
        "data_tags": None,
        "third_party": True,
    },
]

def seed():
    init_db()
    db = SessionLocal()
    try:
        for policy_data in DEFAULT_POLICIES:
            existing = db.query(Policy).filter(Policy.name == policy_data["name"]).first()
            if existing:
                # Update existing
                for key, value in policy_data.items():
                    setattr(existing, key, value)
                print(f"  Updated: {policy_data['name']}")
            else:
                policy = Policy(**policy_data, enabled=True)
                db.add(policy)
                print(f"  Created: {policy_data['name']}")
        db.commit()
        print(f"\n[OK] Seeded {len(DEFAULT_POLICIES)} policies successfully")
    except Exception as e:
        db.rollback()
        print(f"[ERROR] Error seeding policies: {e}")
        raise
    finally:
        db.close()

if __name__ == "__main__":
    print("Seeding ZENTRIQ policies...")
    seed()
