import json
from pathlib import Path

MANIFEST_DIR = Path(__file__).with_name("manifests")


def _validate_recovery_order(data: dict, path: Path) -> None:
    recovery_order = data.get("recovery_order")
    if recovery_order is None:
        return
    if not isinstance(recovery_order, list) or not recovery_order:
        raise ValueError(f"Invalid recovery_order in application manifest: {path}")
    if len(recovery_order) != len(set(recovery_order)):
        raise ValueError(f"Duplicate component in recovery_order: {path}")

    component_kinds = {
        component.get("kind")
        for component in data.get("components", [])
        if component.get("kind")
    }
    unknown = [kind for kind in recovery_order if kind not in component_kinds]
    if unknown:
        raise ValueError(
            f"Unknown component kinds in recovery_order for {path}: {unknown}"
        )


def load_manifests() -> list[dict]:
    manifests = []
    for path in sorted(MANIFEST_DIR.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("schema_version") != 1 or not data.get("id"):
            raise ValueError(f"Invalid application manifest: {path}")
        _validate_recovery_order(data, path)
        data["manifest_path"] = str(path)
        manifests.append(data)
    return manifests
