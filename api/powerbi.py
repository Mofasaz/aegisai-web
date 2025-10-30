import os, time, json, requests
from typing import Dict, Any

TENANT = os.getenv("PBI_TENANT_ID", "")
CLIENT_ID = os.getenv("PBI_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("PBI_CLIENT_SECRET", "")
SCOPE = "https://analysis.windows.net/powerbi/api/.default"
AUTH_URL=lambda f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"
GROUP_ID = os.getenv("PBI_GROUP_ID", "")
DATASET_ID = os.getenv("PBI_DATASET_ID", "")
TABLE = os.getenv("PBI_TABLE", "attestations")

_session = requests.Session()
_token_cache = Dict[str, Any] = {"expires_at": 0, "access_token": None}

def _get_token() -> str:
    if not TENANT or not CLIENT_ID or not CLIENT_SECRET:
        raise RuntimeError("Power BI not configured")
    now = time.time()
    if _token_cache["access_token"] and now < _token_cache["expires"] - 60:
        return _token_cache["access_token"]
    r = _session.post(AUTH_URL(), data={
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "client_credentials",
        "scope": SCOPE,
    }, timeout=20)
    
    r.raise_for_status(); tok = r.json()
    _token_cache.update({"access_token": tok["access_token"], "expires": now + int(tok.get("expires_in", 3599))})
    return _token_cache["access_token"]

def push_rows(rows):
    token = _get_token()
    url = f"https://api.powerbi.com/v1.0/myorg/groups/{GROUP_ID}/datasets/{DATASET_ID}/tables/{TABLE}/rows"
    hdrs = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    r = _session.post(url, headers=hdrs, data=json.dumps({"rows": rows}), timeout=20)
    r.raise_for_status(); return True


