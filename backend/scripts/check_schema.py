"""Compare the tables/columns/RPCs the backend uses with a real Postgres schema.

Two sources of "what the code uses":
  1. tests: run `RECORD_DB_USAGE=usage.json pytest` - the fake database records every table and column touched
     (exact, but only for code paths the tests exercise);
  2. static: a regex pass over app/*.py for table("x")...execute() chains (approximate, covers untested paths).

Usage: python scripts/check_schema.py --usage usage.json --psql "psql -h /tmp -p 5544 -U postgres -d aifw_migration_test"
Exit status 1 if anything the code uses is missing from the database.
"""
import argparse, glob, json, re, subprocess, sys
from collections import defaultdict


def static_usage():
    use = defaultdict(set)
    for path in glob.glob("app/*.py"):
        src = open(path).read()
        for m in re.finditer(r'table\("([a-z_]+)"\)(.{0,900}?)\.execute\(\)', src, re.S):
            table, chain = m.group(1), m.group(2)
            use[table]
            for col in re.findall(r'\.(?:eq|neq|gte|lte|gt|lt|order|in_|is_)\(\s*"([A-Za-z_]+)"', chain):
                use[table].add(col)
            for sel in re.findall(r'\.select\(\s*"([^"]*)"', chain):
                use[table].update(c.strip() for c in sel.split(",") if c.strip() and c.strip() != "*" and "(" not in c and not c.strip().startswith("count"))
            if re.search(r"\.(insert|upsert|update)\(", chain):
                use[table].update(re.findall(r'"([a-z_]+)"\s*:', chain))
    rpcs = set()
    for path in glob.glob("app/*.py"):
        rpcs.update(re.findall(r'rpc\(\s*"([a-z_]+)"', open(path).read()))
    return use, rpcs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--usage", required=True)
    ap.add_argument("--psql", required=True, help="psql command line for the database to check")
    args = ap.parse_args()

    def q(sql):
        out = subprocess.run(args.psql.split() + ["-At", "-F", "|", "-c", sql], capture_output=True, text=True, check=True).stdout
        return [line.split("|") for line in out.strip().splitlines() if line]

    db_cols = defaultdict(set)
    for t, c in q("select table_name, column_name from information_schema.columns where table_schema='public'"):
        db_cols[t].add(c)
    db_funcs = {r[0] for r in q("select proname from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname='public'")}

    recorded = json.load(open(args.usage))
    need = defaultdict(set)
    for table, entry in recorded.items():
        if table == "__rpc__":
            continue
        need[table].update(entry["write"]); need[table].update(entry["read"])
    static, rpcs = static_usage()
    for table, cols in static.items():
        need[table].update(cols)
    for call in recorded.get("__rpc__", {}).get("ops", []):
        rpcs.add(call.split("(")[0])

    problems = []
    for table in sorted(need):
        if table not in db_cols:
            problems.append(f"missing table: {table}")
            continue
        for col in sorted(need[table] - db_cols[table]):
            problems.append(f"missing column: {table}.{col}")
    for fn in sorted(rpcs - db_funcs):
        problems.append(f"missing function: {fn}")
    print(f"checked {len(need)} tables, {len(rpcs)} functions")
    for p in problems:
        print("  " + p)
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
