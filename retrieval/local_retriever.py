import json
from pathlib import Path
from typing import List, Dict, Optional

# Simple keyword search over local policies.jsonl, with grade filtering
def load_policies(path: str = "data/policies.jsonl") -> List[Dict]:
    out = []
    for ln in Path(path).read_text().splitlines():
        if ln.strip(): out.append(json.loads(ln))
    return out

POLICIES = None

def get_chunks(query: str, user_grade: Optional[str]) -> List[Dict]:
    global POLICIES
    POLICIES = POLICIES or load_policies()
    q = query.lower()
    # grade filter: public OR allowed_grades contains user_grade
    def allowed(rec):
        if rec.get("visibility", "public") == "public": return True
        if not user_grade: return False
        return user_grade in (rec.get("allowed_grades") or [])
    # naive ranking by keyword hits
    scored = []
    for r in POLICIES:
        if not allowed(r):
            continue
        text = (r.get("chunk_text","" ) + " " + " ".join(r.get("tags",[]))).lower()
        score = sum(1 for tok in q.split() if tok in text)
        if score > 0: scored.append((score, r))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [r for _, r in scored[:5]]
