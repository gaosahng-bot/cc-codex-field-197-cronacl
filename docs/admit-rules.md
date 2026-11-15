# cronacl admit rules

## Signing input
`v1|{kid}|{user}|{schedule}|{cmd}|{cwd}|{iat}|{nonce}`

## Schedule
Split schedule on spaces; must have schedule_fields parts. Hour field (index 1) must be int ∈ users[user].sched_hours (fixtures use numeric hour, not `*`).

## Gates
user ∈ users; cmd startswith cmd_prefixes and reject deny substrings; cwd ∈ cwd_allow and reject deny substrings;
HMAC+revoke; time; nonce allow-only.
