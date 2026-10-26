"""Every table and column name the backend code mentions must exist in the database.

Usage: python check_code_columns.py <psql connection args...>   e.g.  -h /tmp -p 5544 -U postgres -d t2
Heuristic (regex over backend/app/*.py): per `table("x")` call it collects select()/eq()/order() column names and
dict-literal keys on the same line, plus the audit/security event bases built in main.py. It is a drift detector, not a proof."""
import collections, glob, os, re, subprocess, sys

APP = os.path.join(os.path.dirname(__file__), "..", "..", "backend", "app")
EXTRA = {"audit_logs": {"user_id", "organization_id", "application_id", "employee_id", "request_id", "action", "risk_score", "tokens_used", "latency_ms", "model", "cost", "reason", "metadata"},
         "security_events": {"user_id", "organization_id", "application_id", "employee_id", "event_type", "severity", "risk_score", "details"}}
NOT_COLUMNS = {"alerts", "api_key", "policy", "count", "settings", "connections", "tokens", "domains", "reviews", "providers", "identity", "application", "organization", "verified", "instructions", "tls", "note", "type"}  # response-dict keys, not columns

def psql(sql):
    out = subprocess.run(["psql", "-At", "-F", "|", *sys.argv[1:], "-c", sql], capture_output=True, text=True, check=True).stdout
    return [line.split("|") for line in out.splitlines() if line]

used = collections.defaultdict(set)
for path in glob.glob(os.path.join(APP, "*.py")):
    for line in open(path):
        for t in re.findall(r'table\("([a-z_]+)"\)', line):
            start = line.index(f'table("{t}")')
            nxt = line.find('table("', start + 8)
            seg = line[start:nxt if nxt > 0 else None]          # stop at the next table() call on the same line
            seg = re.split(r"\.execute\(\)", seg)[0]            # ...and at the end of this query chain
            used[t]
            for m in re.findall(r'\.select\("([^"*]+)"', seg):
                used[t] |= {c.strip() for c in m.split(",")}
            used[t] |= set(re.findall(r'\.(?:eq|neq|gte|lte|in_|ilike|order)\("([a-z_]+)"', seg))
            used[t] |= set(re.findall(r'"([a-z_]+)"\s*:', seg)) - NOT_COLUMNS
for t, cols in EXTRA.items():
    used[t] |= cols
LEGACY = {"ai_firewall_cache", "ai_firewall_rate_limits", "webhook_configs"}  # in modules main.py never imports
have = collections.defaultdict(set)
for t, c in psql("select table_name, column_name from information_schema.columns where table_schema='public'"):
    have[t].add(c)
bad = 0
for t in sorted(used):
    if t in LEGACY:
        continue
    if t not in have:
        print(f"MISSING TABLE {t}"); bad += 1; continue
    for c in sorted(used[t] - have[t] - {"count"}):
        print(f"MISSING COLUMN {t}.{c}"); bad += 1
print("drift findings:", bad)
sys.exit(1 if bad else 0)
