import re, calendar
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Any
from zoneinfo import ZoneInfo

GST_TZ = ZoneInfo("Asia/Dubai")
MONTH_RE = re.compile(r"\b(in\s+)?(jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)\b(?:\s+(\d{4}))?", re.I)
LAST_MONTH_RE = re.compile(r"\b(last|past)\s+month\b", re.I)

_LAST_WINDOW_PATTERNS = [
    (re.compile(r"\b(last|past)\s+week\b", re.I), timedelta(days=7)),
    (re.compile(r"\b(last|past)\s+(\d+)\s*days?\b", re.I), None),
    (re.compile(r"\b(last|past)\s+(\d+)\s*hours?\b", re.I), None),
    (re.compile(r"\byesterday\b", re.I), "yesterday"),
    (re.compile(r"\btoday\b", re.I), "today"),
]

_OUTSIDE_HOURS_RE = re.compile(
    r"\boutside\s*(\d{1,2}:\d{2})\s*[–\-]\s*(\d{1,2}:\d{2})\s*(?:\b(?:gst|uae time)\b)?",
    re.I
)

ROLE_EQ = {"cabin crew": "Cabin Crew", "ground staff": "Ground Staff", "pilot": "Pilot", "it admin": "IT Admin"}
ROLE_FAMILY_TERMS = {"cargo", "hr", "hr personnel", "hr managers", "hr manager", "hr coordinator"}


ACTION_HINTS = {
    "login": ["login","sign-in","signin","sign_in","auth"],
    "failed login": ["failed login","login failed","auth failure"],
    "access_denied": ["access_denied","access denied","forbidden"],
    "data access": ["data access","read","view"],
    "download": ["download","export"],
    "upload": ["upload","ingest"],
    "delete": ["delete","remove","purge"],
    "vpn": ["vpn","remote access","anyconnect","globalprotect"],
    "security scan": ["vulnerability scan","nmap","qualys","scan"],
    "timeout": ["timeout","session timeout"],
    "logout": ["logout","sign out","signout"],
}

LOCATION_NEG_DXB_RE = re.compile(r"\b(non[-\s]?dxb|outside\s+dxb)\b", re.I)
LOCATION_POS_DXB_RE = re.compile(r"\b(?:in\s+)?dxb\b", re.I)

def _month_bounds(month:int, year:int, tz=GST_TZ):
    start = datetime(year, month, 1, tzinfo=tz)
    last_day = calendar.monthrange(year, month)[1]
    end = datetime(year, month, last_day, 23, 59, 59, 999000, tzinfo=tz)
    return start.astimezone(ZoneInfo("UTC")), end.astimezone(ZoneInfo("UTC"))


def _infer_month_from_text(query:str, now:datetime|None=None):
    now = now or datetime.now(tz=GST_TZ)
    # last month
    m = LAST_MONTH_RE.search(query or "")
    if m:
        year = now.year
        month = now.month - 1 or 12
        if month == 12:
            year -= 1
        return _month_bounds(month, year)
    # named month
    m = MONTH_RE.search(query or "")
    if m:
        name = m.group(2).lower()
        year = int(m.group(3)) if m.group(3) else now.year
        month = ["jan","feb","mar","apr","may","jun","jul","aug","sep","oct","nov","dec"].index(name[:3]) + 1
        return _month_bounds(month, year)
    return (None, None)


def _parse_hhmm(s: str) -> Tuple[int, int]:
    h, m = s.split(":")
    return int(h), int(m)


def _infer_time_window(query: str, now: Optional[datetime] = None) -> Tuple[Optional[datetime], Optional[datetime]]:
    """Return (time_min, time_max) in UTC if query implies a time range; else (None, None)."""
    if not query:
        return None, None
    now = now or datetime.now(tz=GST_TZ)

    for pat, spec in _LAST_WINDOW_PATTERNS:
        m = pat.search(query)
        if not m:
            continue
        if spec == "yesterday":
            start = (now - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
            end   = start + timedelta(days=1)
        elif spec == "today":
            start = now.replace(hour=0, minute=0, second=0, microsecond=0)
            end   = start + timedelta(days=1)
        elif isinstance(spec, timedelta):
            start = now - spec
            end   = now
        else:
            # dynamic windows like "last 3 days" / "last 12 hours"
            num = int(m.group(2))
            unit_word = m.group(0).lower()
            if "hour" in unit_word:
                delta = timedelta(hours=num)
            else:
                delta = timedelta(days=num)
            start = now - delta
            end   = now

        # convert to UTC for storage/filters
        return start.astimezone(ZoneInfo("UTC")), end.astimezone(ZoneInfo("UTC"))
    # if none matched, try month phrases:
    tmin, tmax = _infer_month_from_text(query, now or datetime.now(tz=GST_TZ))
    if tmin and tmax:
        return tmin, tmax
    return None, None


def _extract_outside_hours(query: str) -> Optional[Tuple[Tuple[int,int], Tuple[int,int]]]:
    """Return ((start_h,start_m), (end_h,end_m)) if 'outside H:MM–H:MM' appears."""
    if not query:
        return None
    m = _OUTSIDE_HOURS_RE.search(query)
    if not m:
        return None
    start_hm = _parse_hhmm(m.group(1))
    end_hm   = _parse_hhmm(m.group(2))
    return start_hm, end_hm


def interpret_query(query: Optional[str]) -> Dict[str, Any]:
    intent = {
        "search_text": query or "",
        "must_terms": [],
        "filters": {},          # eq filters
        "not_filters": {},      # negative eq filters
        "outside_hours": None,  # ((h,m),(h,m)) GST
        "inside_hours": None,   # support “peak hours”
        "time_min": None, "time_max": None,
        "system_terms": [],     # e.g., payroll system
    }
    q = (query or "").lower()

    # roles
    for phrase, exact in ROLE_EQ.items():
        if phrase in q:
            intent["filters"]["user_role"] = exact
            break
        else:
            # no exact match → look for families that should be keyword-only
            for fam in ROLE_FAMILY_TERMS:
                if fam in q:
                    # use as must-term to hit 'Cargo Supervisor', 'Cargo Manager', 'HR Manager', etc.
                    intent["must_terms"].append("cargo" if "cargo" in fam else "hr")
                    # do NOT set filters["user_role"] here
                    break

    # statuses
    if "success" in q and "failed" in q:
        pass
    elif "failed" in q or "failure" in q:
        intent["filters"]["status"] = "failed"
    elif "success" in q:
        intent["filters"]["status"] = "success"

    # actions
    for action, hints in ACTION_HINTS.items():
        if any(h in q for h in hints):
            # we’ll just push these into search_text to help recall
            intent["must_terms"].append(action)

    # location
    if LOCATION_NEG_DXB_RE.search(q):
        intent["not_filters"]["location"] = "DXB"
    elif LOCATION_POS_DXB_RE.search(q):
        intent["filters"]["location"] = "DXB"

    # systems (simple keyword → system field)
    if "payroll" in q:
        intent["filters"]["system"] = "Payroll"

    # peak / non-peak hours (default window)
    PEAK = ((8,0),(18,0))
    if "peak hour" in q:
        intent["inside_hours"] = PEAK
    if "non-peak" in q or "off-peak" in q:
        intent["outside_hours"] = PEAK

    # explicit outside-hours (already supported)
    oh = _extract_outside_hours(query or "")
    if oh:
        intent["outside_hours"] = oh

    # time windows
    tmin, tmax = _infer_time_window(query or "")
    intent["time_min"], intent["time_max"] = tmin, tmax
    return intent


def outside_hours_predicate(ts_utc: datetime, start_hm: Tuple[int,int], end_hm: Tuple[int,int]) -> bool:
    """
    Keep events where local GST time is *outside* [start, end).
    """
    local = ts_utc.astimezone(GST_TZ)
    h, m = local.hour, local.minute

    sh, sm = start_hm
    eh, em = end_hm

    start_minutes = sh*60 + sm
    end_minutes   = eh*60 + em
    cur_minutes   = h*60 + m

    if start_minutes <= end_minutes:
        # normal range (e.g., 05:00–23:00)
        return not (start_minutes <= cur_minutes < end_minutes)
    else:
        # overnight range (e.g., 23:00–05:00)
        return not (cur_minutes >= start_minutes or cur_minutes < end_minutes)
