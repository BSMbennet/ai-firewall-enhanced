"""In-memory stand-in for the parts of supabase-py that the backend uses.

It is deliberately small and strict:

* It implements the query-builder surface the application actually calls
  (select/insert/upsert/update/delete, eq/neq/in_/gte/lte, order/limit/offset,
  maybe_single, execute, rpc) and the GoTrue calls (auth.get_user, auth.admin.*).
* It enforces the unique constraints the application relies on, so duplicate
  inserts fail the way Postgres would.
* It is **not** Postgres and it does not model Row Level Security. Tests that use
  it prove application-level authorization and business logic only; database-level
  tenant isolation must be tested against a real Supabase branch (see
  docs/KNOWN_LIMITATIONS.md).
"""
from __future__ import annotations

import copy
import threading
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Optional

UNIQUE = {
    "api_keys": [("key_hash",)],
    "organization_members": [("organization_id", "user_id")],
    "profiles": [("id",)],
    "organizations": [("slug",)],
    "usage_counters": [("organization_id", "period_start")],
    "scim_tokens": [("token_hash",)],
}

DEFAULTS: Dict[str, Callable[[], Dict[str, Any]]] = {
    "api_keys": lambda: {"is_active": True, "scopes": ["chat"]},
    "applications": lambda: {"status": "active"},
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


USAGE: Dict[str, Dict[str, set]] = {}  # table -> {"write": cols, "read": cols, "ops": ops}; dumped by conftest when RECORD_DB_USAGE is set


def _record_usage(q) -> None:
    entry = USAGE.setdefault(q.table, {"write": set(), "read": set(), "ops": set(), "on_conflict": set()})
    entry["ops"].add(q.op)
    if q.op in ("insert", "upsert", "update"):
        for item in q.payload if isinstance(q.payload, list) else [q.payload]:
            entry["write"].update(item.keys())
    if q.op == "upsert" and q.on_conflict:
        entry["on_conflict"].add(q.on_conflict)
    entry["read"].update(col for _, col, _ in q.filters)
    if q._order:
        entry["read"].add(q._order[0])
    if q._cols not in ("*", ""):
        entry["read"].update(c.strip() for c in q._cols.split(",") if c.strip() and "(" not in c)


class Resp:
    def __init__(self, data: Any, count: Optional[int] = None):
        self.data = data
        self.count = count


class Query:
    def __init__(self, db: "FakeDB", table: str):
        self.db = db
        self.table = table
        self.op = "select"
        self.filters: List[tuple] = []
        self.payload: Any = None
        self.on_conflict: Optional[str] = None
        self._order: Optional[tuple] = None
        self._limit: Optional[int] = None
        self._offset = 0
        self._single = False
        self._count: Optional[str] = None
        self._cols = "*"

    # -- builders -----------------------------------------------------------------
    def select(self, cols: str = "*", count: Optional[str] = None):
        self.op, self._cols, self._count = "select", cols, count
        return self

    def insert(self, payload):
        self.op, self.payload = "insert", payload
        return self

    def upsert(self, payload, on_conflict: Optional[str] = None):
        self.op, self.payload, self.on_conflict = "upsert", payload, on_conflict
        return self

    def update(self, payload):
        self.op, self.payload = "update", payload
        return self

    def delete(self):
        self.op = "delete"
        return self

    def eq(self, col, val):
        self.filters.append(("eq", col, val)); return self

    def neq(self, col, val):
        self.filters.append(("neq", col, val)); return self

    def in_(self, col, vals):
        self.filters.append(("in", col, list(vals))); return self

    def gte(self, col, val):
        self.filters.append(("gte", col, val)); return self

    def lte(self, col, val):
        self.filters.append(("lte", col, val)); return self

    def is_(self, col, val):
        self.filters.append(("is", col, val)); return self

    def order(self, col, desc: bool = False):
        self._order = (col, desc); return self

    def limit(self, n: int):
        self._limit = n; return self

    def offset(self, n: int):
        self._offset = n; return self

    def maybe_single(self):
        self._single = True; return self

    # -- execution ----------------------------------------------------------------
    def _match(self, row: Dict[str, Any]) -> bool:
        for op, col, val in self.filters:
            cell = row.get(col)
            if op == "eq" and cell != val:
                return False
            if op == "neq" and cell == val:
                return False
            if op == "in" and cell not in val:
                return False
            if op == "gte" and (cell is None or cell < val):
                return False
            if op == "lte" and (cell is None or cell > val):
                return False
            if op == "is" and not (((val is None or val == "null") and cell is None) or cell == val):
                return False
        return True

    def execute(self) -> Resp:
        with self.db.lock:
            rows = self.db.tables.setdefault(self.table, [])
            self.db.calls.append((self.op, self.table))
            _record_usage(self)
            if self.op == "select":
                matched = [r for r in rows if self._match(r)]
                total = len(matched)
                if self._order:
                    col, desc = self._order
                    matched.sort(key=lambda r: (r.get(col) is None, r.get(col)), reverse=desc)
                matched = matched[self._offset:]
                if self._limit is not None:
                    matched = matched[: self._limit]
                if self._cols not in ("*", ""):
                    wanted = [c.strip() for c in self._cols.split(",")]
                    matched = [{c: r[c] for c in wanted if c in r} for r in matched]
                out = [copy.deepcopy(r) for r in matched]
                if self._single:
                    return Resp(out[0] if out else None, total)
                return Resp(out, total if self._count else None)
            if self.op == "insert":
                if self.table in self.db.fail_inserts:
                    raise RuntimeError(f"simulated insert failure on {self.table}")
                return Resp(self._insert_many(rows, self.payload))
            if self.op == "upsert":
                keys = [k.strip() for k in (self.on_conflict or "id").split(",")]
                out = []
                for item in self.payload if isinstance(self.payload, list) else [self.payload]:
                    existing = next((r for r in rows if all(r.get(k) == item.get(k) for k in keys)), None)
                    if existing is not None:
                        existing.update(copy.deepcopy(item))
                        out.append(copy.deepcopy(existing))
                    else:
                        out.extend(self._insert_many(rows, item))
                return Resp(out)
            if self.op == "update":
                out = []
                for r in rows:
                    if self._match(r):
                        r.update(copy.deepcopy(self.payload))
                        out.append(copy.deepcopy(r))
                return Resp(out)
            if self.op == "delete":
                gone = [r for r in rows if self._match(r)]
                self.db.tables[self.table] = [r for r in rows if r not in gone]
                return Resp(copy.deepcopy(gone))
        raise AssertionError(f"unsupported op {self.op}")

    def _insert_many(self, rows: List[Dict[str, Any]], payload) -> List[Dict[str, Any]]:
        out = []
        for item in payload if isinstance(payload, list) else [payload]:
            row = {**DEFAULTS.get(self.table, lambda: {})(), **copy.deepcopy(item)}
            row.setdefault("id", str(uuid.uuid4()))
            row.setdefault("created_at", _now())
            for cols in UNIQUE.get(self.table, []):
                if any(all(r.get(c) == row.get(c) for c in cols) for r in rows):
                    raise RuntimeError(f"duplicate key value violates unique constraint on {self.table}{cols}")
            rows.append(row)
            out.append(copy.deepcopy(row))
        return out


class FakeAuthAdmin:
    def __init__(self, db: "FakeDB"):
        self.db = db

    def get_user_by_id(self, user_id):
        u = self.db.users.get(user_id)
        return SimpleNamespace(user=SimpleNamespace(id=user_id, email=(u or {}).get("email")))

    def invite_user_by_email(self, email):
        uid = str(uuid.uuid4())
        self.db.users[uid] = {"email": email, "banned": False}
        return SimpleNamespace(user=SimpleNamespace(id=uid, email=email))

    def update_user_by_id(self, user_id, attrs):
        self.db.auth_calls.append(("update_user_by_id", user_id, attrs))
        if self.db.fail_auth_admin:
            raise RuntimeError("GoTrue unavailable")
        user = self.db.users.setdefault(user_id, {"email": None})
        if "ban_duration" in attrs:
            user["banned"] = attrs["ban_duration"] not in ("none", None)
        return SimpleNamespace(user=SimpleNamespace(id=user_id))


class FakeAuth:
    """Tokens are the literal string ``test-token:<user_id>``."""

    def __init__(self, db: "FakeDB"):
        self.db = db
        self.admin = FakeAuthAdmin(db)

    def get_user(self, jwt: str):
        prefix = "test-token:"
        if not jwt.startswith(prefix):
            raise RuntimeError("invalid JWT")
        uid = jwt[len(prefix):]
        user = self.db.users.get(uid)
        if user is None or user.get("banned"):
            raise RuntimeError("user not found or banned")
        return SimpleNamespace(user=SimpleNamespace(id=uid, email=user.get("email"),
                                                    identities=user.get("identities", [])))


class FakeClient:
    def __init__(self, db: "FakeDB"):
        self.db = db
        self.auth = FakeAuth(db)

    def table(self, name: str) -> Query:
        return Query(self.db, name)

    def rpc(self, name: str, params: Dict[str, Any]):
        return RpcCall(self.db, name, params)


class RpcCall:
    def __init__(self, db, name, params):
        self.db, self.name, self.params = db, name, params

    def execute(self) -> Resp:
        USAGE.setdefault("__rpc__", {"write": set(), "read": set(), "ops": set(), "on_conflict": set()})["ops"].add(
            f"{self.name}({','.join(sorted(self.params))})")
        with self.db.lock:
            rows = self.db.tables.setdefault("usage_counters", [])
            org, period = self.params.get("p_organization_id"), self.params.get("p_period_start")
            row = next((r for r in rows if r["organization_id"] == org and r["period_start"] == period), None)
            if row is None:
                row = {"id": str(uuid.uuid4()), "organization_id": org, "period_start": period,
                       "request_count": 0, "blocked_count": 0, "tokens_used": 0}
                rows.append(row)
            if self.name == "consume_gateway_usage":
                limit = self.params.get("p_limit")
                if limit is not None and row["request_count"] >= limit:
                    return Resp([{"allowed": False, "request_count": row["request_count"]}])
                row["request_count"] += 1
                return Resp([{"allowed": True, "request_count": row["request_count"]}])
            if self.name == "record_gateway_outcome":
                row["blocked_count"] += 1 if self.params.get("p_blocked") else 0
                row["tokens_used"] += max(0, int(self.params.get("p_tokens") or 0))
                return Resp(None)
        raise AssertionError(f"unsupported rpc {self.name}")


class FakeDB:
    def __init__(self):
        self.tables: Dict[str, List[Dict[str, Any]]] = {}
        self.users: Dict[str, Dict[str, Any]] = {}
        self.calls: List[tuple] = []
        self.auth_calls: List[tuple] = []
        self.fail_auth_admin = False
        self.fail_inserts: set = set()
        self.lock = threading.RLock()
        self.client = FakeClient(self)

    # -- seeding helpers used by tests --------------------------------------------
    def add_org(self, name: str) -> str:
        org_id = str(uuid.uuid4())
        self.tables.setdefault("organizations", []).append(
            {"id": org_id, "name": name, "slug": name.lower().replace(" ", "-"), "created_at": _now()})
        return org_id

    def add_member(self, org_id: str, role: str, status: str = "active", email: Optional[str] = None) -> str:
        uid = str(uuid.uuid4())
        email = email or f"{role}-{uid[:6]}@example.test"
        self.users[uid] = {"email": email, "banned": False}
        self.tables.setdefault("profiles", []).append(
            {"id": uid, "organization_id": org_id, "role": role, "full_name": role})
        self.tables.setdefault("organization_members", []).append(
            {"id": str(uuid.uuid4()), "organization_id": org_id, "user_id": uid, "email": email,
             "full_name": role, "role": role, "status": status, "created_at": _now()})
        return uid

    def rows(self, table: str, **where) -> List[Dict[str, Any]]:
        return [r for r in self.tables.get(table, []) if all(r.get(k) == v for k, v in where.items())]

    @staticmethod
    def token(user_id: str) -> Dict[str, str]:
        return {"Authorization": f"Bearer test-token:{user_id}"}
