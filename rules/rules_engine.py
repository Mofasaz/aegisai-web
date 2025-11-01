# rules_engine.py
from __future__ import annotations
import os, datetime
from typing import Tuple
import yaml

_RULES_PATH = os.environ.get("AEGIS_RULES_PATH", os.path.abspath("rules.yaml"))
_RULES_YAML = ""  # in-memory cache

def _ensure_file():
    global _RULES_YAML
    if not os.path.exists(_RULES_PATH):
        with open(_RULES_PATH, "w", encoding="utf-8") as f:
            f.write("# AegisAI detection rules (YAML)\n")
    with open(_RULES_PATH, "r", encoding="utf-8") as f:
        _RULES_YAML = f.read()

def load_rules() -> str:
    """Initialize / get current YAML (string)."""
    global _RULES_YAML
    if not _RULES_YAML:
        _ensure_file()
    return _RULES_YAML

def get_rules_yaml() -> str:
    return load_rules()

def validate_yaml_block(yaml_text: str) -> Tuple[bool, str]:
    """Lightweight schema sanity check; returns (ok, message)."""
    try:
        data = yaml.safe_load(yaml_text)
    except Exception as e:
        return False, f"Invalid YAML: {e}"
    if not isinstance(data, dict):
        return False, "YAML root must be a mapping (object)."
    # minimal keys often used by rules:
    required = ["rule_id", "title", "enabled", "severity"]
    missing = [k for k in required if k not in data]
    if missing:
        return False, f"Missing required key(s): {', '.join(missing)}"
    return True, "ok"

def append_rule_yaml(yaml_text: str) -> None:
    """Append a rule block to the file with a delimiter and update cache."""
    global _RULES_YAML
    load_rules()  # ensure file exists
    stamp = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
    block = f"\n\n# --- appended {stamp} ---\n" + yaml_text.strip() + "\n"
    with open(_RULES_PATH, "a", encoding="utf-8") as f:
        f.write(block)
    _RULES_YAML += block

def reload_rules() -> int:
    """Reload from disk; returns line count for quick feedback."""
    global _RULES_YAML
    _ensure_file()
    return len(_RULES_YAML.splitlines())
