# api/quality.py
import json
from typing import List, Dict, Any
from api.chains import get_llm

def judge_answer(answer: str, snippets: List[str]) -> Dict[str, Any]:
    llm = get_llm()
    sys = ("You are a strict policy auditor. Score groundedness 0..1 ONLY from provided snippets. "
           "Return JSON: {\"grounding_score\": float, \"issues\": [string]}. No extra text.")
    user = f"Answer:\n{answer}\n\nSnippets:\n" + "\n---\n".join(snippets)
    out = llm.invoke([{"role":"system","content":sys},{"role":"user","content":user}])
    try:
        return json.loads(getattr(out, 'content', str(out)))
    except Exception:
        return {"grounding_score": 0.6, "issues": ["Non-JSON judge output"]}
