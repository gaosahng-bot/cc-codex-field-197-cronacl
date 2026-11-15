from __future__ import annotations
from typing import Any

def inspect_job(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "user": obj.get("user"),
        "schedule": obj.get("schedule"),
        "cmd": obj.get("cmd"),
        "cwd": obj.get("cwd"),
        "nonce": obj.get("nonce"),
    }

def admit_job(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "cmd": obj.get("cmd")}
