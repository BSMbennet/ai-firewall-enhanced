"""Deterministic request inspection: prompt-injection rules and PII / secret detectors.

Design notes (see docs/DETECTION_EVALUATION.md for measured behaviour and docs/KNOWN_LIMITATIONS.md for residual risk):

* Everything here is deterministic pattern matching with validation (Luhn, calendar dates). It is **one signal**, not a
  complete defence: paraphrases, other languages, encodings and novel attacks are not detected.
* Text is normalised before matching (Unicode NFKC, zero-width/format characters removed, common Cyrillic/Greek
  look-alikes mapped to Latin, whitespace collapsed, case-folded) and a de-spaced view catches "i g n o r e" spelling.
* Findings carry rule ids and categories - never the matched text - so alerts and logs cannot leak the content.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from datetime import date
from typing import Callable, Dict, List, Sequence, Tuple

# --------------------------------------------------------------------------------------------------
# Normalisation
# --------------------------------------------------------------------------------------------------

_HOMOGLYPHS = str.maketrans({
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d",
    "һ": "h", "ɡ": "g", "к": "k", "м": "m", "н": "h", "т": "t", "в": "b",
    # Greek
    "ο": "o", "ν": "v", "α": "a", "ρ": "p", "ι": "i", "κ": "k", "τ": "t", "ε": "e",
})
_SPACED_LETTERS = re.compile(r"\b(?:[a-z][ .\-_*]){2,}[a-z]\b")
_WHITESPACE = re.compile(r"\s+")


def strip_invisible(text: str) -> str:
    """NFKC-normalise and drop zero-width / format characters (but keep the original case and layout)."""
    text = unicodedata.normalize("NFKC", text)
    return "".join(ch for ch in text if unicodedata.category(ch) != "Cf")


def normalize_views(text: str) -> List[str]:
    """Views of ``text`` that rules are matched against: normalised, plus a de-spaced variant when it differs."""
    raw = strip_invisible(text).translate(_HOMOGLYPHS).casefold()
    # De-space *before* collapsing whitespace: in "i g n o r e  a l l" the double space is what separates the words.
    despaced = _WHITESPACE.sub(" ", _SPACED_LETTERS.sub(lambda m: re.sub(r"[ .\-_*]", "", m.group(0)), raw))
    base = _WHITESPACE.sub(" ", raw)
    return [base] if despaced == base else [base, despaced]


# --------------------------------------------------------------------------------------------------
# Injection rules
# --------------------------------------------------------------------------------------------------

HIGH, MEDIUM, LOW = 0.95, 0.65, 0.4  # >= 0.8 blocks; >= 0.5 holds for review; below only adds to the risk score


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    severity: float
    pattern: "re.Pattern[str]"


@dataclass(frozen=True)
class InjectionFinding:
    rule_id: str
    category: str
    severity: float


_VERB = r"(?:ignor(?:e|es|ed|ing)|disregard(?:s|ed|ing)?|forget(?:s|ting)?|override(?:s|n)?|overrul(?:e|es|ed|ing)|bypass(?:es|ed|ing)?|skip(?:s|ped|ping)?|abandon(?:s|ed|ing)?|discard(?:s|ed|ing)?|dismiss(?:es|ed|ing)?)"
_STRONG = r"(?:all|any|every|previous|prior|above|earlier|preceding|former|original|initial|system|safety|security|your|ur|ure|yer|these|those)"
_MOD = r"(?:previous|prior|above|earlier|preceding|former|original|initial|system|safety|security|content|given|existing|other|current|internal|of|your|the|my|these|those|all)"
_NOUN = r"(?:instructions?|prompts?|rules?|directives?|guidelines?|polic(?:y|ies)|constraints?|restrictions?|safeguards?|guardrails?|programming|training|commands?)"
_SECRETISH = r"(?:system|initial|hidden|original|developer|internal|secret|confidential)"
_EXFIL_VERB = r"(?:reveal|show|print|repeat|output|display|leak|disclose|expose|dump|recite|tell me|give me|share|write out|paste|list|state)"


def _r(rule_id: str, category: str, severity: float, pattern: str, flags: int = re.IGNORECASE) -> Rule:
    return Rule(rule_id, category, severity, re.compile(pattern, flags))


INJECTION_RULES: Sequence[Rule] = (
    # --- instruction override -------------------------------------------------------------------
    _r("override.ignore_instructions", "instruction_override", HIGH,
       rf"\b{_VERB}\b(?:\W+(?:the|a|my|this|that|these|those|of))?\W+{_STRONG}(?:\W+{_MOD}){{0,3}}\W+{_NOUN}\b"),
    _r("override.forget_everything", "instruction_override", HIGH,
       r"\b(?:forget|ignore|disregard)\w*\W+(?:everything|anything)\b(?:\W+\w+){0,3}?\W+(?:above|before|earlier|previously|so far|said)\b"),
    _r("override.stop_following", "instruction_override", HIGH,
       rf"\b(?:do not|don'?t|stop|no longer|never)\W+(?:follow|following|obey|obeying|adhere to|comply with|comply)\W+(?:\w+\W+){{0,2}}?{_NOUN}\b"),
    _r("override.ignore_given_before", "instruction_override", HIGH,
       rf"\b{_VERB}\b\W+(?:\w+\W+){{0,3}}?{_NOUN}\W+(?:\w+\W+){{0,4}}?(?:given|received|told|provided)\W+(?:\w+\W+){{0,2}}?(?:before|earlier|previously|prior)\b"),
    _r("override.new_instructions", "instruction_override", MEDIUM,
       r"\b(?:your\W+)?new\W+(?:instructions?|rules|directives?|task)\W*(?::|are\b|is\b)"),
    _r("override.end_of_prompt", "instruction_override", MEDIUM,
       r"\b(?:end|stop)\W+of\W+(?:the\W+)?(?:system\W+)?(?:prompt|instructions)\b"),
    # --- chat-template / role markers smuggled into user text -----------------------------------
    _r("marker.chat_template_tokens", "role_injection", HIGH,
       r"<\|(?:im_start|im_end|system|assistant|user|endoftext)\|>|\[/?inst\]|<<\s*/?sys\s*>>"),
    _r("marker.system_prompt_label", "role_injection", HIGH, r"\b(?:system prompt|system message)\s*:"),
    _r("marker.role_line", "role_injection", MEDIUM, r"(?m)^\W*(?:system|developer)\s*:"),
    # --- system-prompt exfiltration ---------------------------------------------------------------
    _r("exfil.reveal_system_prompt", "prompt_exfiltration", HIGH,
       rf"\b{_EXFIL_VERB}\b(?:\W+\w+){{0,3}}?\W+(?:your|the|its|this|that|all|any)\W+(?:\w+\W+){{0,2}}?{_SECRETISH}\W+(?:prompt|instructions?|message|rules|configuration)\b"),
    _r("exfil.what_is_your_prompt", "prompt_exfiltration", HIGH,
       rf"\bwhat\W+(?:is|are|were)\W+(?:your|the)\W+(?:\w+\W+){{0,2}}?{_SECRETISH}\W+(?:prompt|instructions?|message)\b"),
    _r("exfil.repeat_above", "prompt_exfiltration", HIGH,
       r"\b(?:repeat|print|output|show|display|recite)\W+(?:\w+\W+){0,3}?(?:above|before this|so far)\b(?:\W+\w+){0,4}?\W*(?:verbatim|line|words|text|message|starting|beginning)?"),
    _r("exfil.send_data_to_url", "prompt_exfiltration", MEDIUM,
       r"\b(?:send|post|upload|forward|email|exfiltrate|transmit|leak)\w*\b(?:\W+\w+){0,6}?\W+(?:to|at)\W+https?://"),
    # --- jailbreak / persona -----------------------------------------------------------------------
    _r("jailbreak.persona_dan", "jailbreak", HIGH,
       r"\byou\W+are\W+now\W+(?:\w+\W+){0,3}?(?:dan|developer mode|jailbroken|unrestricted|unfiltered|uncensored|evil)\b|\bdo anything now\b"),
    _r("jailbreak.pretend_unrestricted", "jailbreak", HIGH,
       r"\bpretend\W+(?:you\W+are|you'?re|to\W+be)\W+(?:\w+\W+){0,4}?(?:evil|unrestricted|uncensored|unfiltered|no\W+(?:rules|restrictions|limits|ethics)|without\W+(?:any\W+)?(?:rules|restrictions|limits|filters|ethics|guidelines))"),
    _r("jailbreak.act_without_restrictions", "jailbreak", HIGH,
       r"\bact\W+as\b(?:\W+\w+){0,6}?\W+(?:without|with\W+no)\W+(?:\w+\W+){0,2}?(?:restrictions?|filters?|rules|limits|guidelines|ethics|censorship)\b"),
    _r("jailbreak.bypass_safety", "jailbreak", HIGH,
       r"\b(?:bypass|circumvent|evade|get\W+around)\w*\W+(?:\w+\W+){0,2}?(?:safety|ai|moderation|content|security)\W+(?:filters?|policy|policies|guardrails?|checks?|measures|controls|firewall|restrictions)\b"),
    _r("jailbreak.disable_filters", "jailbreak", MEDIUM,
       r"\b(?:disable|turn\W+off|deactivate|switch\W+off)\W+(?:\w+\W+){0,2}?(?:safety|ai|moderation|content|security)\W+(?:filters?|policy|policies|guardrails?|checks?|measures|controls|firewall)\b"),
    _r("jailbreak.developer_mode", "jailbreak", MEDIUM, r"\bdeveloper\W+mode\W+(?:\w+\W+){0,2}?(?:enabled|activated|engaged|output)\b"),
    _r("jailbreak.named_jailbreak", "jailbreak", MEDIUM,
       r"\bjailbreak(?:s|ed|ing)?\W+(?:\w+\W+){0,3}?(?:prompt|mode|you|assistant|ai|model|llm|chatgpt)\b"),
    _r("jailbreak.no_guidelines_persona", "jailbreak", MEDIUM,
       r"\bwith(?:out)?\W+no\W+(?:\w+\W+){0,2}?(?:guidelines|restrictions|rules|limits|filters|ethics|morals)\b"),
    # --- rules added after the first held-out evaluation (docs/DETECTION_EVALUATION.md) -----------------
    _r("exfil.show_your_prompt", "prompt_exfiltration", MEDIUM,
       rf"\b{_EXFIL_VERB}\b(?:\W+\w+){{0,2}}?\W+your\W+(?:system\W+)?(?:prompt|instructions?)\b"),
    _r("exfil.instructions_you_were_given", "prompt_exfiltration", MEDIUM,
       r"\bwhat\W+(?:\w+\W+){0,3}?(?:instructions|rules|prompt)\W+(?:you|were\W+you)\W+(?:were\W+)?(?:given|told|programmed|configured)\b"),
    _r("override.system_override_label", "instruction_override", MEDIUM, r"\b(?:system|admin|administrator|developer)\W+override\b"),
    _r("override.protocols_disabled", "instruction_override", MEDIUM,
       r"\b(?:safety|security)\W+(?:protocols?|filters?|guardrails?|restrictions?)\W+(?:are\W+|have\W+been\W+)?(?:disabled|off|removed|lifted)\b"),
    _r("override.your_rules_updated", "instruction_override", MEDIUM,
       r"\byour\W+(?:instructions?|rules|guidelines|restrictions)\W+(?:have\W+been|has\W+been|were|are)\W+(?:updated|changed|replaced|removed|lifted|revoked)\b"),
    _r("override.comply_without_question", "instruction_override", MEDIUM,
       r"\b(?:comply|obey)\w*\W+(?:\w+\W+){0,6}?without\W+(?:question|hesitation|refusal|refusing)\b"),
    # --- legacy rules kept from the original detector ----------------------------------------------
    _r("legacy.output_confidential", "prompt_exfiltration", HIGH, r"\boutput\W+(?:sensitive|confidential|secret)\b"),
    _r("legacy.show_how_to_hack", "harmful_request", HIGH, r"\bshow\W+me\W+(?:how|steps)\W+to\W+(?:hack|exploit)\b"),
    _r("legacy.decode_then_act", "encoded_payload", MEDIUM,
       r"\b(?:decode|decipher)\W+(?:\w+\W+){0,4}?(?:base64|hex|rot13|binary)\b(?:\W+\w+){0,8}?\W+(?:and|then)\W+(?:follow|execute|run|obey|do)\b"),
    _r("legacy.encoded_decode", "encoded_payload", LOW, r"\b(?:base64|hex|rot13)\b.*\bdecode\b"),
)


def find_injection(text: str) -> List[InjectionFinding]:
    """All distinct rules that match any normalised view of ``text`` (highest severity first)."""
    found: Dict[str, InjectionFinding] = {}
    for view in normalize_views(text):
        for rule in INJECTION_RULES:
            if rule.rule_id not in found and rule.pattern.search(view):
                found[rule.rule_id] = InjectionFinding(rule.rule_id, rule.category, rule.severity)
    return sorted(found.values(), key=lambda f: (-f.severity, f.rule_id))


def injection_score(findings: Sequence[InjectionFinding]) -> float:
    """Highest severity, nudged up by 0.05 per additional distinct category (capped at 1.0)."""
    if not findings:
        return 0.0
    categories = {f.category for f in findings}
    return min(1.0, findings[0].severity + 0.05 * (len(categories) - 1))


# --------------------------------------------------------------------------------------------------
# PII / secrets
# --------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class PIIFinding:
    category: str
    start: int
    end: int


def luhn_valid(digits: str) -> bool:
    if not digits.isdigit():
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _valid_sa_id(raw: str) -> bool:
    digits = re.sub(r"[ -]", "", raw)
    if len(digits) != 13 or not digits.isdigit() or not luhn_valid(digits):
        return False
    yy, mm, dd = int(digits[0:2]), int(digits[2:4]), int(digits[4:6])
    for century in (1900, 2000):  # two-digit year is ambiguous; either century with a real calendar date is accepted
        try:
            date(century + yy, mm, dd)
            break
        except ValueError:
            continue
    else:
        return False
    return digits[10] in "01"  # citizenship digit: 0 = citizen, 1 = permanent resident


def _valid_card(raw: str) -> bool:
    digits = re.sub(r"[ -]", "", raw)
    if not 13 <= len(digits) <= 19 or not luhn_valid(digits):
        return False
    return digits[0] in "3456" or 2221 <= int(digits[:4]) <= 2720


def _always(_: str) -> bool:
    return True


@dataclass(frozen=True)
class PIIDetector:
    category: str
    pattern: "re.Pattern[str]"
    validator: Callable[[str], bool] = _always


# Earlier entries win when matches overlap (more specific / more dangerous first).
PII_DETECTORS: Sequence[PIIDetector] = (
    PIIDetector("PRIVATE_KEY", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----(?:[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----)?")),
    PIIDetector("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    PIIDetector("PROVIDER_KEY", re.compile(
        r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}"
        r"|[sr]k_live_[0-9A-Za-z]{16,}|sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}|(?:aifw|scim|whsec)_[A-Za-z0-9_-]{16,})")),
    PIIDetector("API_KEY", re.compile(r"(?i)\b(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{20,50}")),
    PIIDetector("PASSWORD", re.compile(r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*['\"]?[^\s'\"]{4,}")),
    PIIDetector("SA_ID", re.compile(r"(?<![\d])\d{6}[ -]?\d{4}[ -]?\d{3}(?![\d])"), _valid_sa_id),
    PIIDetector("CREDIT_CARD", re.compile(r"(?<![\d])(?:\d[ -]?){12,18}\d(?![\d])"), _valid_card),
    PIIDetector("SSN", re.compile(r"(?<![\d-])\d{3}-\d{2}-\d{4}(?![\d-])")),
    # Local part and domain are length-bounded (RFC 5321 limits are 64 / 255). Unbounded `+` here made matching quadratic on
# long runs of email-safe characters with no "@" (about 1 s per 20k characters).
    PIIDetector("EMAIL", re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}")),
    PIIDetector("SA_PHONE", re.compile(r"(?<![\d+])(?:\+27|0027|0)[ -]?[1-9]\d[ -]?\d{3}[ -]?\d{4}(?![\d])")),
    PIIDetector("PHONE", re.compile(r"(?<![\d+])\+\d{1,3}[-.\s]?\(?\d{2,3}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}(?![\d])")),
)


def find_pii(text: str) -> List[PIIFinding]:
    """Non-overlapping findings over the invisible-character-stripped text, in document order."""
    view = strip_invisible(text)
    accepted: List[PIIFinding] = []
    for detector in PII_DETECTORS:
        for match in detector.pattern.finditer(view):
            if not detector.validator(match.group(0)):
                continue
            start, end = match.span()
            if any(start < f.end and f.start < end for f in accepted):
                continue
            accepted.append(PIIFinding(detector.category, start, end))
    return sorted(accepted, key=lambda f: f.start)


def pii_categories(text: str) -> set:
    return {f.category for f in find_pii(text)}


def redact(text: str) -> str:
    """Replace every finding with ``[REDACTED_<CATEGORY>]``. Operates on the invisible-character-stripped text."""
    view = strip_invisible(text)
    pieces: List[str] = []
    cursor = 0
    for finding in find_pii(text):
        pieces.append(view[cursor:finding.start])
        pieces.append(f"[REDACTED_{finding.category}]")
        cursor = finding.end
    pieces.append(view[cursor:])
    return "".join(pieces)


BLOCKING_PII_CATEGORIES = frozenset({"PRIVATE_KEY"})  # never forwarded, even redacted
