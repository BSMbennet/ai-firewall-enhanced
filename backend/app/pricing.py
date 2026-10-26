"""Optional, operator-supplied price table. Nothing is shipped: prices change and an invented number would end up in
audit records and invoices. Without a configured entry for a model the cost is None (recorded as 0 in audit_logs).

``MODEL_PRICES_JSON`` = {"meta/llama-3.1-8b-instruct": {"input_per_1k": 0.0002, "output_per_1k": 0.0002, "currency": "USD", "as_of": "2026-10-01"}}
An entry without a valid ``as_of`` date, or with negative / non-numeric prices, is ignored (and logged once).
"""
from __future__ import annotations

import json
import logging
import os
from datetime import date
from typing import Dict, Optional

logger = logging.getLogger("aifirewall.pricing")
_warned = set()


def _load() -> Dict[str, dict]:
    raw = os.getenv("MODEL_PRICES_JSON", "").strip()
    if not raw:
        return {}
    try:
        table = json.loads(raw)
        if not isinstance(table, dict):
            raise ValueError("not an object")
    except ValueError:
        if "json" not in _warned:
            _warned.add("json"); logger.error("MODEL_PRICES_JSON is not a valid JSON object; costs will not be computed")
        return {}
    valid = {}
    for model, entry in table.items():
        try:
            date.fromisoformat(str(entry["as_of"]))
            i, o = float(entry["input_per_1k"]), float(entry["output_per_1k"])
            if i < 0 or o < 0:
                raise ValueError("negative")
            valid[str(model).strip().lower()] = {"input": i, "output": o}
        except (KeyError, TypeError, ValueError):
            if model not in _warned:
                _warned.add(model); logger.error("price entry for %s ignored (needs input_per_1k, output_per_1k, as_of)", model)
    return valid


def estimate_cost(model: str, prompt_tokens: int, completion_tokens: int) -> Optional[float]:
    entry = _load().get(str(model or "").strip().lower())
    if entry is None:
        return None
    return round((prompt_tokens * entry["input"] + completion_tokens * entry["output"]) / 1000, 6)
