from typing import List, Dict, Any, Tuple
from api.models import LogEvent, Anomaly
import yaml, re, threading, hashlib
from datetime import datetime

# Global cache + lock
_RULES_CACHE: List[Dict[str, Any]] = []
_LOCK = threading.RLock()
ALLOW_WORDS = ("permit", "permitted", "allowed", "allow", "authorised", "authorized")
DENY_WORDS  = ("forbid", "forbidden", "prohibit", "prohibited", "deny", "blocked", "not allowed")


def _normalize_rule_dict(d: Dict[str, Any]) -> Dict[str, Any]:
    """Light canonicalization so comparisons are stable."""
    out = dict(d)
    # Normalize strings
    for k, v in list(out.items()):
        if isinstance(v, str):
            out[k] = v.strip()
        elif isinstance(v, list):
            # de-dupe lists of strings while preserving order
            if all(isinstance(x, str) for x in v):
                out[k] = list(dict.fromkeys([x.strip() for x in v]))
    # Lowercase some common fields for matching
    for k in ("category", "action", "role", "system", "resource"):
        if k in out and isinstance(out[k], str):
            out[k] = out[k].strip()
    return out


def _rule_signature(d: Dict[str, Any]) -> Tuple:
    """
    A coarse signature to spot duplicates near-identically scoped rules.
    Adjust the keys to match your schema.
    """
    keys = ("category", "role", "system", "resource", "action")
    sig = tuple((k, (d.get(k) or "") if isinstance(d.get(k), str) else tuple(d.get(k) or [])) for k in keys)
    # also include any simple ‘when’ conditions you use (e.g., status/time windows)
    conds = d.get("when") or {}
    # compress ‘when’ to stable pairs (only simple equals / lists considered)
    flat = []
    for k, v in sorted(conds.items()):
        if isinstance(v, list):
            flat.append((k, tuple(sorted(v))))
        else:
            flat.append((k, v))
    return ("sig", sig, tuple(flat))


def _similar_rule(existing: Dict[str, Any], new: Dict[str, Any]) -> bool:
    """Duplicate if signatures match exactly."""
    return _rule_signature(existing) == _rule_signature(new)


def _contradict_rule(existing: Dict[str, Any], new: Dict[str, Any]) -> bool:
    """
    Naive contradiction detector:
      - same scope (role/system/resource/action)
      - one 'effect' says allow/permit while the other says deny/block/flag high severity
    Tune based on your schema: effect, decision, severity, action_on_violation, etc.
    """
    scope_keys = ("role", "system", "resource", "action")
    same_scope = all((existing.get(k) or "") == (new.get(k) or "") for k in scope_keys)

    def _effect(d: Dict[str, Any]) -> str:
        # try explicit effect/decision fields first; fallback to severity/action_on_violation text
        for key in ("effect", "decision"):
            if key in d and isinstance(d[key], str):
                return d[key].strip().lower()
        text = " ".join(str(d.get(k, "")) for k in ("severity", "action_on_violation", "note", "description"))
        t = text.lower()
        if any(w in t for w in DENY_WORDS):
            return "deny"
        if any(w in t for w in ALLOW_WORDS):
            return "allow"
        # If severity very low and action is "log only", treat as allow-ish
        if "log only" in t or "informational" in t:
            return "allowish"
        return "unknown"

    return same_scope and { _effect(existing), _effect(new) } == {"allow", "deny"}


def _validate_against_existing(new_rule: Dict[str, Any], existing_rules: List[Dict[str, Any]]) -> Tuple[List[str], List[str]]:
    """
    Returns (errors, warnings) about duplicates or conflicts vs. existing rules.
    """
    errs, warns = [], []
    new_id = (new_rule.get("id") or "").strip()
    if new_id and any((r.get("id") or "").strip() == new_id for r in existing_rules):
        errs.append(f"Rule id '{new_id}' already exists.")

    for r in existing_rules:
        if _similar_rule(r, new_rule):
            warns.append(f"Possible duplicate of existing rule '{r.get('id') or r.get('name') or 'unknown'}' (same scope/conditions).")
        elif _contradict_rule(r, new_rule):
            errs.append(f"New rule appears to contradict existing rule '{r.get('id') or r.get('name') or 'unknown'}' for the same scope.")

    # De-dupe messages (preserve order)
    errs = list(dict.fromkeys(errs))
    warns = list(dict.fromkeys(warns))
    return errs, warns


def _policy_sanity_check(new_rule: Dict[str, Any], role: str | None) -> Tuple[List[str], List[str]]:
    """
    Deterministic (no LLM) sanity pass: if nearby clauses strongly 'permit' something
    the rule tries to 'deny', raise a warning/error. Vice-versa too.
    """
    errs, warns = [], []
    q_terms = [new_rule.get("action"), new_rule.get("system"), new_rule.get("resource"), new_rule.get("category")]
    q = " ".join([t for t in q_terms if t]).strip()
    if not q:
        return errs, warns

    clauses = _load_policy_clauses_for_query(q, role)
    if not clauses:
        warns.append("No related policies found for this scope; please review.")
        return errs, list(dict.fromkeys(warns))

    # compress clauses text
    texts = []
    for c in clauses:
        txt = (c.get("clause_text") or c.get("content") or "").strip()
        if txt:
            texts.append(txt.lower())

    combined = " \n".join(texts)
    rule_text = " ".join(str(new_rule.get(k, "")) for k in ("effect", "decision", "severity", "action_on_violation", "description")).lower()

    policy_allows = any(w in combined for w in ALLOW_WORDS)
    policy_denies  = any(w in combined for w in DENY_WORDS)

    rule_is_denyish  = any(w in rule_text for w in DENY_WORDS) or ("high" in rule_text and "block" in rule_text)
    rule_is_allowish = any(w in rule_text for w in ALLOW_WORDS) or ("log only" in rule_text)

    if policy_allows and rule_is_denyish:
        errs.append("Policy clauses appear to permit this behavior, but the suggested rule would deny/block it.")
    if policy_denies and rule_is_allowish:
        warns.append("Policy clauses appear to prohibit this behavior, but the suggested rule is weak (allow/log). Consider raising severity.")

    return list(dict.fromkeys(errs)), list(dict.fromkeys(warns))


# Optional: stronger (LLM) check—off by default
ENABLE_LLM_POLICY_CHECK = False

def _llm_policy_conflict_check(rule_yaml: str, clauses: List[Dict[str, Any]]) -> Tuple[List[str], List[str]]:
    """
    If you want a secondary LLM gate. Returns (errors, warnings).
    """
    if not ENABLE_LLM_POLICY_CHECK:
        return [], []
    policy_blob = "\n\n".join((c.get("clause_text") or c.get("content") or "").strip() for c in clauses if (c.get("clause_text") or c.get("content")))
    if not policy_blob.strip():
        return [], []

    prompt = f"""You are a compliance validator.
Rule (YAML):
---
{rule_yaml}
---

Policy excerpts:
---
{policy_blob[:8000]}
---

Tasks:
1) Say "ERROR:" if the rule contradicts the policy (policy allows but rule denies, or policy forbids but rule allows).
2) Say "WARNING:" if the rule duplicates an already typical control or seems redundant.
3) Otherwise say "OK".
Only return short bullet points, max 3 lines."""
    try:
        txt = _llm_short_check(prompt)  # implement using your chat model (NOT an embedding model)
    except Exception:
        return [], ["LLM policy check skipped due to runtime error."]

    errs, warns = [], []
    for line in txt.splitlines():
        l = line.strip()
        if l.lower().startswith("error"):
            errs.append(l)
        elif l.lower().startswith("warning"):
            warns.append(l)
    return list(dict.fromkeys(errs)), list(dict.fromkeys(warns))


def load_rules_from_file(path: str) -> List[Dict[str, Any]]:
    """Read YAML file and return list under `rules:` (empty list if missing)."""
    with open(path, "r", encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}
    rules = doc.get("rules", [])
    if not isinstance(rules, list):
        raise ValueError("rules.yaml must contain a top-level `rules: []` list")
    return rules

def set_rules(rules: List[Dict[str, Any]]) -> None:
    with _LOCK:
        # optionally validate/normalize here
        _RULES_CACHE.clear()
        _RULES_CACHE.extend(rules)

def get_rules() -> List[Dict[str, Any]]:
    with _LOCK:
        return list(_RULES_CACHE)

def _parse_iso(ts: str) -> datetime:
    # Handles "Z" and "+HH:MM" forms
    ts = ts.replace("Z", "+00:00") if ts.endswith("Z") else ts
    return datetime.fromisoformat(ts)

def between_hours(ts: str, start: int, end: int) -> bool:
    h = _parse_iso(ts).hour
    if start <= end:
        return start <= h < end
    return (h >= start) or (h < end)

def _get(d: Dict[str, Any], path: str):
    cur = d
    for p in path.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    return cur

def eval_rule(rule: Dict[str, Any], ev: Dict[str, Any]) -> bool:
    def check(cond: Dict[str, Any]) -> bool:
        field = cond["field"]; op = cond["op"]; val = cond.get("value")
        v = _get(ev, field) if "." in field else ev.get(field)

        if op == "equals": return v == val
        if op == "in":     return v in val
        if op == "in_set": return isinstance(val, list) and v in val
        if op == "gt":     return (v or 0) > val
        if op == "gte":    return (v or 0) >= val
        if op == "regex":  return bool(re.search(val, v or "", flags=re.I))
        if op == "not_regex": return not bool(re.search(val, v or "", flags=re.I))
        if op == "between_hours": return between_hours(v, val[0], val[1])
        return False

    clause = rule["when"]
    if "all" in clause: return all(check(c) for c in clause["all"])
    if "any" in clause: return any(check(c) for c in clause["any"])
    return False

# def analyze_events(events: List[LogEvent]) -> List[Anomaly]:
#    cfg = yaml.safe_load(open("rules/rules.yaml").read())
#    weights = cfg["meta"]["score_weights"]; rules = cfg["rules"]
#    anomalies: List[Anomaly] = []
#    for e in events:
#        ev = e.dict(); hit_ids, reasons = [], []
#        for r in rules:
#            if eval_rule(r, ev):
#                hit_ids.append(r["id"]); reasons.append(r["explain"])
#        if hit_ids:
#            score = min(100, sum(weights.get(i, 10) for i in hit_ids))
#            anomalies.append(Anomaly(event_id=e.event_id, signals=hit_ids, risk_score=score, explain="; ".join(reasons)))
#    return anomalies

# -------- Existing function, now reads from the cache ----------
def analyze_events(events: List[Dict[str, Any]]):
    """
    Your existing anomaly engine.
    IMPORTANT: This should read get_rules() at evaluation time,
    so a /rules/reload immediately affects new calls.
    """
    rules = get_rules()
    anomalies = []
    for ev in events:
        # ... your existing matching logic using `rules` ...
        # Example placeholder:
        matched_signals = []
        risk = 0
        for r in rules:
            # (pseudo) check `match` and `conditions`
            # if matched: matched_signals.append(r['id']); risk += r.get('risk_points', 0)
            pass
        if matched_signals:
            anomalies.append({
                "event_id": ev.get("event_id", ""),
                "signals": matched_signals,
                "risk_score": min(100, max(10, risk)),
                "explain": "Matched rules: " + ", ".join(matched_signals),
            })
    return anomalies




