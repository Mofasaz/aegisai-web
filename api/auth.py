import base64, json
from typing import Optional, List
from fastapi import Request, HTTPException, Depends
from pydantic import BaseModel

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
        for r in self.roles:
            if r.lower().startswith("grade."):
                g = r.split(".", 1)[1].strip()
                return g.replace("_", " ")
        return None

def _read_principal(request: Request) -> dict:
    hdr = request.headers.get("X-MS-CLIENT-PRINCIPAL")
    if not hdr:
        raise HTTPException(status_code=401, detail="No principal header (Easy Auth off?).")
    try:
        payload = base64.b64decode(hdr).decode("utf-8")
        return json.loads(payload) or {}
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid principal header.")

def require_user(request: Request):
    raw = _read_principal(request)
    # raw has fields: "auth_typ", "claims": [{"typ": "...", "val": "..."}], etc.
    claims = {c.get("typ"): c.get("val") for c in raw.get("claims", [])}
    # Common claim types from Easy Auth (AAD):
    # http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name
    # http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier (oid)
    # http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn
    # roles: "roles"
    name = claims.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name")
    oid = claims.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier") or claims.get("oid")
    upn = claims.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn")
    roles_raw = raw.get("userRoles", []) or []
    # Optional custom claims
    job_title = claims.get("jobTitle")
    extension_grade = claims.get("extension_userGrade") or claims.get("extension_usergrade")

    if not oid:
        raise HTTPException(status_code=401, detail="Missing oid claim.")
    return UserPrincipal(
        oid=oid, name=name, upn=upn,
        roles=roles_raw, groups=raw.get("groups", []),
        job_title=job_title, extension_grade=extension_grade
    )
