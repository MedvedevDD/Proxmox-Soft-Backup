import json
from pathlib import Path

MANIFEST_DIR = Path(__file__).with_name("manifests")

def load_manifests() -> list[dict]:
    manifests=[]
    for path in sorted(MANIFEST_DIR.glob("*.json")):
        data=json.loads(path.read_text(encoding="utf-8"))
        if data.get("schema_version") != 1 or not data.get("id"):
            raise ValueError(f"Invalid application manifest: {path}")
        data["manifest_path"]=str(path)
        manifests.append(data)
    return manifests
