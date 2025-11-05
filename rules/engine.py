from typing import List, Dict, Any, Tuple
from api.models import LogEvent, Anomaly
import yaml, re, threading, hashlib
from datetime import datetime
from ruamel.yaml import YAML
_yaml = YAML(typ="safe")

# Global cache + lock
_RULES_CACHE: List[Dict[str, Any]] = []
_LOCK = threading.RLock()

def _canonical_rule(yaml_text: str) -> Tuple[dict, str]:
    """
    Returns (rule_dict, canonical_fingerprint).
    We sort keys, normalize lists, and hash only the meaningful parts
    so near-identical YAMLs map to the same fingerprint.
    """
    doc = _yaml.load(yaml_text) or {}
    if not isinstance(doc, dict):
        return {}, ""

    # Keep only meaningful keys for dedupe/conflict checks
    keep = {k: doc.get(k) for k in ("name", "category", "severity", "effect", "where", "then")}
    # Normalize:
    def _norm(x):
        if isinstance(x, dict):
            return {k: _norm(x[k]) for k in sorted(x)}
        if isinstance(x, list):
            return sorted((_norm(i) for i in x), key=lambda v: str(v))
        return x
    canon = _norm(keep)

    # Fingerprint uses only effect + where predicates
    fp_src = {"effect": canon.get("effect"), "where": canon.get("where")}
    fp = hashlib.sha256(str(fp_src).encode("utf-8")).hexdigest()
    return canon, fp

def _predicates_overlap(a_where: dict, b_where: dict) -> bool:
    """
    Heuristic: treat “overlap” as all shared keys compatible.
    - Exact string equality matches
    - Lists: any intersection
    - Missing key in either → assume overlap (conservative)
    """
    if not isinstance(a_where, dict) or not isinstance(b_where, dict):
        return False
    keys = set(a_where.keys()) & set(b_where.keys())
    for k in keys:
        av, bv = a_where.get(k), b_where.get(k)
        if isinstance(av, list) or isinstance(bv, list):
            aset = set(av if isinstance(av, list) else [av])
            bset = set(bv if isinstance(bv, list) else [bv])
            if not (aset & bset):
                return False
        else:
            if av is not None and bv is not None and str(av) != str(bv):
                return False
    return True


def _effect_opposes(a: str, b: str) -> bool:
    a = (a or "").lower()
    b = (b or "").lower()
    denyish   = {"deny","block","flag_high","escalate"}
    allowish  = {"allow","permit"}
    if (a in denyish and b in allowish) or (b in denyish and a in allowish):
        return True
    return False

def _iter_active_rules():
    # Replace with your store: DB, file, or in-memory list
    for r in ACTIVE_RULES:
        # each r is a dict with fields similar to suggested YAML
        yield r


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



