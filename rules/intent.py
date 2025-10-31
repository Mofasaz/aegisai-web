# rules/intent.py
import re

# Add/adjust patterns as you wish. They are matched case-insensitively.
RISKY_PATTERNS = [
    r"\bemail\b.*\b(crew|roster|schedules)\b.*\b(external|outside|gmail|yahoo|personal)\b",
    r"\bshare\b.*\b(payroll|salary|pii|passport|visa)\b",
    r"\bdownload\b.*\b(employee\s*records|confidential|restricted)\b",
    r"\bexport\b.*\b(hr|crew|employee|payroll|confidential)\b",
]

def match_risky_intent(q: str) -> str | None:
    for pat in RISKY_PATTERNS:
        if re.search(pat, q, flags=re.IGNORECASE):
            return pat
    return None
