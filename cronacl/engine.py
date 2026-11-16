from __future__ import annotations
import base64
import hashlib
import hmac
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

def _signing_input(obj: dict) -> str:
    return "v1|{kid}|{user}|{schedule}|{cmd}|{cwd}|{iat}|{nonce}".format(
        kid=obj.get("kid"),
        user=obj.get("user"),
        schedule=obj.get("schedule"),
        cmd=obj.get("cmd"),
        cwd=obj.get("cwd"),
        iat=obj.get("iat"),
        nonce=obj.get("nonce"),
    )

def admit_job(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    cmd = obj.get("cmd")

    user = obj.get("user")
    users = policy.get("users", {})
    ucfg = users.get(user)
    if ucfg is None:
        reasons.append("user_not_allowed")
        ucfg = {}

    schedule = obj.get("schedule")
    fields = schedule.split(" ") if isinstance(schedule, str) else []
    if len(fields) != policy.get("schedule_fields", 5) or any(f == "" for f in fields):
        reasons.append("bad_schedule_fields")
    else:
        hour_field = fields[1]
        try:
            hour = int(hour_field)
        except ValueError:
            reasons.append("hour_not_allowed")
        else:
            if hour not in ucfg.get("sched_hours", []):
                reasons.append("hour_not_allowed")
        if policy.get("forbid_wildcard_dow") and fields[4] != "*":
            reasons.append("dow_not_allowed")

    if not isinstance(cmd, str) or not any(
        cmd.startswith(p) for p in ucfg.get("cmd_prefixes", [])
    ):
        reasons.append("cmd_prefix_not_allowed")
    if isinstance(cmd, str) and any(
        s in cmd for s in policy.get("cmd_deny_substrings", [])
    ):
        reasons.append("cmd_deny_substring")

    cwd = obj.get("cwd")
    if cwd not in ucfg.get("cwd_allow", []):
        reasons.append("cwd_not_allowed")
    if isinstance(cwd, str) and any(
        s in cwd for s in policy.get("cwd_deny_substrings", [])
    ):
        reasons.append("cwd_deny_substring")

    kid = obj.get("kid")
    key = keys.get("keys", {}).get(kid)
    if key is None:
        reasons.append("unknown_key")
    elif key.get("status") != "active":
        reasons.append("key_revoked")
    else:
        digest = hmac.new(
            bytes.fromhex(key["secret"]),
            _signing_input(obj).encode("utf-8"),
            hashlib.sha256,
        ).digest()
        expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        if not hmac.compare_digest(expected, str(obj.get("sig"))):
            reasons.append("bad_signature")

    iat = obj.get("iat")
    if not isinstance(iat, int):
        reasons.append("bad_iat")
    else:
        if iat > now_unix + policy.get("clock_skew_seconds", 0):
            reasons.append("iat_in_future")
        if iat < now_unix - policy.get("max_age_seconds", 0):
            reasons.append("iat_too_old")

    nonce = obj.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        reasons.append("bad_nonce")
    elif nonce in store.get("items", {}):
        reasons.append("nonce_replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "cmd": cmd}

    store["items"][nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "cmd": cmd}
