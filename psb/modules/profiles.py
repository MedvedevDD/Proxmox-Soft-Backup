import json
from pathlib import Path


def profile_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "profiles"


def load_profiles() -> list[dict]:
    profiles = []
    for path in sorted(profile_dir().glob("*.json")):
        profiles.append(json.loads(path.read_text(encoding="utf-8")))
    return profiles
