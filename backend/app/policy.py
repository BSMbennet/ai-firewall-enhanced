"""Resolution of an organisation's security-policy toggles (pure, no I/O).

Semantics (tested in tests/test_policy.py):
* Protections default to ON. A missing, null or unrecognised value counts as ON - a bad row never weakens security.
* An organisation may hold several policies; a protection is OFF only if every policy that states a value turns it off
  (i.e. the most restrictive policy wins).
* PRIVATE_KEY material is blocked regardless of any toggle (see detection.BLOCKING_PII_CATEGORIES).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Optional

_TRUE = {"true", "t", "1", "yes", "on"}
_FALSE = {"false", "f", "0", "no", "off"}


def _as_bool(value: Any) -> Optional[bool]:
    """True/False for an explicit value; None when absent or not understood."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in _TRUE:
            return True
        if lowered in _FALSE:
            return False
    return None


@dataclass(frozen=True)
class Protections:
    pii: bool = True                 # redact PII in prompts and score it
    prompt_injection: bool = True    # block/review prompt-injection attempts
    sensitive_content: bool = True   # filter the provider's response (secret/PII leakage, harmful content)


def effective_protections(policies: Iterable[dict]) -> Protections:
    resolved = {}
    for key, column in (("pii", "pii_protection"), ("prompt_injection", "prompt_injection_protection"),
                        ("sensitive_content", "sensitive_content_protection")):
        states = [_as_bool(p.get(column)) for p in policies]
        explicit = [s for s in states if s is not None]
        resolved[key] = True if not explicit else any(explicit)
    return Protections(**resolved)
