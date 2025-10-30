from typing import List, Dict, Any
from api.models import LogEvent, Anomaly
import yaml, re
from datetime import datetime

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

def analyze_events(events: List[LogEvent]) -> List[Anomaly]:
    cfg = yaml.safe_load(open("rules/rules.yaml").read())
    weights = cfg["meta"]["score_weights"]; rules = cfg["rules"]
    anomalies: List[Anomaly] = []
    for e in events:
        ev = e.dict(); hit_ids, reasons = [], []
        for r in rules:
            if eval_rule(r, ev):
                hit_ids.append(r["id"]); reasons.append(r["explain"])
        if hit_ids:
            score = min(100, sum(weights.get(i, 10) for i in hit_ids))
            anomalies.append(Anomaly(event_id=e.event_id, signals=hit_ids, risk_score=score, explain="; ".join(reasons)))
    return anomalies


