# api/auth.py
import base64, json, os
from typing import Optional, List
from fastapi import Request, HTTPException, Header
from pydantic import BaseModel

# -------------------------------------------------------------------
# Config
# -------------------------------------------------------------------
AUTH_MODE = os.getenv("AUTH_MODE", "easyauth").lower()  # none | apikey | easyauth
API_KEY   = os.getenv("API_KEY")  # used only when AUTH_MODE=apikey

# Optional demo-grade if you want a default grade in dev:
DEMO_GRADE = os.getenv("DEMO_GRADE", None)

# -------------------------------------------------------------------
# Principal model
# -------------------------------------------------------------------
class UserPrincipal(BaseModel):
    oid: str
    name: Optional[str] = None
    upn: Optional[str] = None
    roles: List[str] = []
    groups: List[str] = []
    job_title: Optional[str] = None
    extension_grade: Optional[str] = None

    @property
    def grade(self) -> Optional[str]:
        # 1) explicit extension
        if self.extension_grade:
            return self.extension_grade
        # 2) job title
        if self.job_title:
            return self.job_title
        # 3) app role like 'Grade.CabinCrew' -> 'Cabin Crew'
        for r in self.roles or []:
            if isinstance(r, str) and r.lower().startswith("grade."):
                g = r.split(".", 1)[-1].strip().replace("_", " ")
                return g
        # 4) demo default
        if DEMO_GRADE:
            return DEMO_GRADE
        return None

# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------
def _b64_json(s: str) -> dict:
    try:
        return json.loads(base64.b64decode(s).decode("utf-8")) or {}
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid principal header: {e}")

def _claim_map(claims_list: list) -> dict:
    """
    Turns EasyAuth 'claims': [{'typ':..., 'val':...}] into a dict,
    normalizing a few common claim URIs/keys.
    """
    m = {}
    for c in claims_list or []:
        t = c.get("typ")
        v = c.get("val")
        if not t:
            continue
        m[t] = v
        # Also store short keys for convenience
        short = t.rsplit("/", 1)[-1].lower()
        m.setdefault(short, v)
    return m

def _extract_grade_from_claims(claims: dict) -> Optional[str]:
    """
    Best-effort grade extraction from various possible claim keys.
    """
    # custom extension examples (adjust to your tenant’s schema names)
    for k in ("extension_userGrade", "extension_usergrade", "ext_userGrade", "ext_grade"):
        if k in claims:
            return claims[k]
    # AAD jobTitle may appear as short 'jobtitle' or URI form
    for k in ("jobTitle", "jobtitle", "http://schemas.microsoft.com/identity/claims/jobtitle"):
        if k in claims:
            return claims[k]
    return None

# -------------------------------------------------------------------
# Modes
# -------------------------------------------------------------------
def require_user(
    request: Request,
    x_api_key: Optional[str] = Header(None),
) -> UserPrincipal:
    """
    Returns a UserPrincipal or raises HTTPException(401).
    Behavior controlled by AUTH_MODE env var.
    """
    mode = AUTH_MODE

    # -----------------------------
    # Mode: none (DEV/DEMO)
    # -----------------------------
    if mode == "none":
        return UserPrincipal(
            oid="demo-oid",
            name="Demo User",
            upn="demo@example.com",
            roles=[],
            groups=[],
            job_title=DEMO_GRADE,
            extension_grade=DEMO_GRADE,
        )

    # -----------------------------
    # Mode: apikey
    # -----------------------------
    if mode == "apikey":
        if not API_KEY or x_api_key != API_KEY:
            raise HTTPException(status_code=401, detail="Invalid API key")
        # You can optionally pass grade via a header in dev (e.g., x-user-grade)
        demo_grade = request.headers.get("x-user-grade") or DEMO_GRADE
        return UserPrincipal(
            oid="apikey-oid",
            name="API Key User",
            upn=None,
            roles=request.headers.get("x-user-roles", "").split(",") if request.headers.get("x-user-roles") else [],
            groups=[],
            job_title=demo_grade,
            extension_grade=demo_grade,
        )

    # -----------------------------
    # Mode: easyauth (Default for PROD)
    # -----------------------------
    if mode == "easyauth":
        hdr = request.headers.get("X-MS-CLIENT-PRINCIPAL")
        if not hdr:
            raise HTTPException(status_code=401, detail="No principal header (Easy Auth off?).")

        raw = _b64_json(hdr)
        claims = _claim_map(raw.get("claims", []))

        name = (
            claims.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name")
            or claims.get("name")
        )
        oid = (
            claims.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier")
            or claims.get("oid")
            or claims.get("objectidentifier")
        )
        upn = (
            claims.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn")
            or claims.get("upn")
            or claims.get("preferred_username")
        )

        if not oid:
            raise HTTPException(status_code=401, detail="Missing oid claim.")

        # roles: EasyAuth often puts them in userRoles (array) on root
        roles_raw = raw.get("userRoles") or []
        if isinstance(roles_raw, str):
            roles_raw = [roles_raw]

        # groups may be present (optional)
        groups = raw.get("groups") or []

        # grade from custom extensions or jobTitle
        ext_grade = _extract_grade_from_claims(claims)

        return UserPrincipal(
            oid=oid,
            name=name,
            upn=upn,
            roles=roles_raw,
            groups=groups,
            job_title=ext_grade,           # keep also in job_title for your .grade fallback
            extension_grade=ext_grade
        )

    # Unknown mode
    raise HTTPException(status_code=401, detail=f"Unsupported AUTH_MODE '{mode}'")
