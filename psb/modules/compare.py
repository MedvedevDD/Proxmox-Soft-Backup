import fnmatch
import hashlib
import io
import json
import os
import tarfile
import zipfile
from pathlib import Path

from .host import host_inventory
from .scanner import scan_system

# Compare is intentionally conservative: volatile data never contributes to drift.
TYPE_WEIGHTS = {
    "configuration": 40,
    "database": 35,
    "credentials": 25,
    "secrets": 25,
    "plugins": 15,
    "application": 12,
    "binary": 10,
    "state": 8,
    "systemd": 5,
    "service": 5,
    "source": 3,
    "logs": 0,
}

RUNTIME_PATTERNS = (
    "*.log",
    "*.log.*",
    "*.pid",
    "*.lock",
    "*.tmp",
    "*.swp",
    "*/log/*",
    "*/logs/*",
    "*/tmp/*",
    "*/temp/*",
    "*/cache/*",
    "*/run/*",
    "*/runtime/*",
)


def _version_confidence(source: str, application_id: str = "") -> int:
    source = (source or "none").lower()
    if source.startswith("package:"):
        return 100
    if source == "path":
        return 90
    if source == "command":
        # Older PSB versions used a generic number parser for HSM and produced 54.2.
        return 30 if application_id == "home-server-monitor" else 95
    if source in {"file", "api"}:
        return 100
    return 0


def _ignored(name: str) -> bool:
    normalized = name.replace("\\", "/").lstrip("./")
    return any(fnmatch.fnmatch(normalized, pattern) for pattern in RUNTIME_PATTERNS)


def _hash_parts(parts: list[str]) -> str:
    digest = hashlib.sha256()
    for part in sorted(parts):
        digest.update(part.encode("utf-8", "surrogateescape"))
        digest.update(b"\0")
    return digest.hexdigest()


def _current_signature(paths: list[str], ignore_runtime: bool = True) -> tuple[str | None, int, int]:
    parts: list[str] = []
    ignored = 0
    for raw in paths:
        path = Path(raw)
        if not path.exists() and not path.is_symlink():
            continue
        items = [path] if path.is_file() or path.is_symlink() else [path] + sorted(path.rglob("*"))
        for item in items:
            relative = str(item).lstrip("/")
            if ignore_runtime and _ignored(relative):
                ignored += 1
                continue
            try:
                if item.is_symlink():
                    parts.append(f"L|{relative}|{os.readlink(item)}")
                elif item.is_dir():
                    parts.append(f"D|{relative}")
                elif item.is_file():
                    digest = hashlib.sha256()
                    with item.open("rb") as handle:
                        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                            digest.update(chunk)
                    parts.append(f"F|{relative}|{digest.hexdigest()}")
            except (OSError, PermissionError) as exc:
                parts.append(f"E|{relative}|{type(exc).__name__}")
    return (_hash_parts(parts) if parts else None), len(parts), ignored


def _tar_signature(data: bytes, ignore_runtime: bool = True) -> tuple[str | None, int, int]:
    parts: list[str] = []
    ignored = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for member in archive.getmembers():
            name = member.name.lstrip("/")
            if ignore_runtime and _ignored(name):
                ignored += 1
                continue
            if member.issym() or member.islnk():
                parts.append(f"L|{name}|{member.linkname}")
            elif member.isdir():
                parts.append(f"D|{name}")
            elif member.isfile():
                extracted = archive.extractfile(member)
                digest = hashlib.sha256()
                if extracted:
                    for chunk in iter(lambda: extracted.read(1024 * 1024), b""):
                        digest.update(chunk)
                parts.append(f"F|{name}|{digest.hexdigest()}")
    return (_hash_parts(parts) if parts else None), len(parts), ignored


def _load_package(path: Path) -> tuple[zipfile.ZipFile, dict]:
    if not path.is_file():
        raise RuntimeError(f"PSB package not found: {path}")
    try:
        archive = zipfile.ZipFile(path, "r")
        manifest = json.loads(archive.read("manifest.json"))
    except Exception as exc:
        raise RuntimeError(f"Cannot read PSB package {path}: {exc}") from exc
    return archive, manifest


def _package_model(path: Path) -> dict:
    archive, manifest = _load_package(path)
    applications: dict[str, dict] = {}
    host_components: dict[str, dict] = {}
    profile = manifest.get("backup", {}).get("profile", "production")

    for application in manifest.get("applications", []):
        components: dict[str, dict] = {}
        for component in application.get("components", []):
            artifacts = component.get("artifacts", [])
            backed_up = bool(component.get("selected", True) and artifacts)
            signature = None
            entries = 0
            ignored_entries = 0
            if backed_up:
                try:
                    signature, entries, ignored_entries = _tar_signature(archive.read(artifacts[0]["path"]))
                except Exception:
                    signature = artifacts[0].get("sha256")
            component_type = component.get("type", "data")
            components[component["id"]] = {
                "id": component["id"],
                "type": component_type,
                "sources": component.get("sources", []),
                "present": component.get("present", False),
                "selected": component.get("selected", True),
                "backed_up": backed_up,
                "signature": signature,
                "entries": entries,
                "ignored_entries": ignored_entries,
                "risk": "application",
                "weight": int(component.get("weight") or TYPE_WEIGHTS.get(component_type, 5)),
            }
        source = application.get("version_source", "none")
        applications[application["name"]] = {
            "name": application["name"],
            "display_name": application.get("display_name", application["name"]),
            "version": application.get("version", "unknown"),
            "family": application.get("version_family", "default"),
            "version_source": source,
            "version_confidence": _version_confidence(source, application["name"]),
            "components": components,
        }

    for component in manifest.get("host", {}).get("components", []):
        artifacts = component.get("artifacts", [])
        backed_up = bool(artifacts)
        signature = None
        entries = 0
        ignored_entries = 0
        if backed_up:
            try:
                signature, entries, ignored_entries = _tar_signature(archive.read(artifacts[0]["path"]))
            except Exception:
                signature = artifacts[0].get("sha256")
        host_components[component["id"]] = {
            "id": component["id"],
            "display_name": component.get("display_name", component["id"]),
            "sources": component.get("sources", []),
            "present": component.get("present", False),
            "selected": True,
            "backed_up": backed_up,
            "signature": signature,
            "entries": entries,
            "ignored_entries": ignored_entries,
            "risk": component.get("risk", "host-sensitive"),
            "weight": int(component.get("weight") or 10),
        }

    source = manifest.get("source", {})
    archive.close()
    return {
        "kind": "package",
        "path": str(path.resolve()),
        "profile": profile,
        "source": source,
        "applications": applications,
        "host": host_components,
    }


def _current_model() -> dict:
    inventory = scan_system()
    host_data = host_inventory()
    applications: dict[str, dict] = {}
    for application in inventory.get("applications", []):
        components: dict[str, dict] = {}
        for index, component in enumerate(application.get("paths", []), 1):
            component_type = component.get("kind", "data")
            component_id = "".join(ch if ch.isalnum() else "-" for ch in component_type.lower()).strip("-") + f"-{index:02d}"
            signature, entries, ignored_entries = _current_signature([component["path"]]) if component.get("exists") else (None, 0, 0)
            components[component_id] = {
                "id": component_id,
                "type": component_type,
                "sources": [component["path"]],
                "present": component.get("exists", False),
                "selected": True,
                "backed_up": True,
                "signature": signature,
                "entries": entries,
                "ignored_entries": ignored_entries,
                "risk": "application",
                "weight": int(component.get("weight") or TYPE_WEIGHTS.get(component_type, 5)),
            }
        source = application.get("version_source", "none")
        applications[application["name"]] = {
            "name": application["name"],
            "display_name": application.get("display_name", application["name"]),
            "version": application.get("version", "unknown"),
            "family": application.get("version_family", "default"),
            "version_source": source,
            "version_confidence": _version_confidence(source, application["name"]),
            "components": components,
        }

    hosts: dict[str, dict] = {}
    for component in host_data.get("components", []):
        signature, entries, ignored_entries = _current_signature(component.get("existing_paths", [])) if component.get("present") else (None, 0, 0)
        hosts[component["id"]] = {
            "id": component["id"],
            "display_name": component.get("display_name", component["id"]),
            "sources": component.get("paths", []),
            "present": component.get("present", False),
            "selected": True,
            "backed_up": True,
            "signature": signature,
            "entries": entries,
            "ignored_entries": ignored_entries,
            "risk": component.get("risk", "host-sensitive"),
            "weight": int(component.get("weight") or 10),
        }
    return {
        "kind": "current-host",
        "path": "current-host",
        "profile": "production",
        "source": host_data.get("fingerprint", {}),
        "applications": applications,
        "host": hosts,
    }


def _component_status(left: dict | None, right: dict | None, package_scope: bool = True) -> str:
    if left is not None and package_scope and not left.get("backed_up", False):
        return "not-backed-up"
    if left is None and right is not None:
        return "added"
    if left is not None and right is None:
        return "removed"
    if not left.get("present") and not right.get("present"):
        return "identical"
    if left.get("present") != right.get("present"):
        return "changed"
    return "identical" if left.get("signature") == right.get("signature") else "changed"


def _version_result(left: dict, right: dict) -> dict:
    same = left.get("version") == right.get("version") and left.get("family") == right.get("family")
    confidence = min(left.get("version_confidence", 0), right.get("version_confidence", 0))
    reliable = confidence >= 70
    if same:
        status = "identical"
    elif reliable:
        status = "changed"
    else:
        status = "metadata-diff"
    return {
        "status": status,
        "confidence": confidence,
        "reliable": reliable,
        "source_left": left.get("version_source", "none"),
        "source_right": right.get("version_source", "none"),
    }


def _compare_applications(left: dict, right: dict) -> list[dict]:
    rows: list[dict] = []
    for key in sorted(set(left) | set(right)):
        first = left.get(key)
        second = right.get(key)
        if first is None:
            rows.append({"id": key, "display_name": second["display_name"], "status": "added", "version_left": None, "version_right": second["version"], "components": [], "drift_weight": 10})
            continue
        if second is None:
            rows.append({"id": key, "display_name": first["display_name"], "status": "removed", "version_left": first["version"], "version_right": None, "components": [], "drift_weight": 10})
            continue

        components: list[dict] = []
        for component_id in sorted(set(first["components"]) | set(second["components"])):
            left_component = first["components"].get(component_id)
            right_component = second["components"].get(component_id)
            status = _component_status(left_component, right_component)
            model = left_component or right_component
            weight = int(model.get("weight", TYPE_WEIGHTS.get(model.get("type", "data"), 5)))
            if status in {"not-backed-up", "not-applicable"} or model.get("type") == "logs":
                effective_weight = 0
            else:
                effective_weight = weight
            reason = {
                "identical": "content hash matches",
                "changed": "content hash differs",
                "added": "component exists only on right side",
                "removed": "component exists only on left side",
                "not-backed-up": "component was outside backup mode scope",
            }.get(status, status)
            components.append({
                "id": component_id,
                "type": model.get("type"),
                "status": status,
                "reason": reason,
                "sources_left": left_component.get("sources", []) if left_component else [],
                "sources_right": right_component.get("sources", []) if right_component else [],
                "risk": "application",
                "weight": effective_weight,
                "entries_left": left_component.get("entries", 0) if left_component else 0,
                "entries_right": right_component.get("entries", 0) if right_component else 0,
                "runtime_entries_ignored": max(left_component.get("ignored_entries", 0) if left_component else 0, right_component.get("ignored_entries", 0) if right_component else 0),
            })

        version = _version_result(first, second)
        changed_components = [component for component in components if component["status"] in {"changed", "added", "removed"} and component["weight"] > 0]
        if changed_components or version["status"] == "changed":
            status = "changed"
        elif version["status"] == "metadata-diff":
            status = "metadata-diff"
        else:
            status = "identical"
        rows.append({
            "id": key,
            "display_name": first["display_name"],
            "status": status,
            "version_left": first["version"],
            "version_right": second["version"],
            "family_left": first["family"],
            "family_right": second["family"],
            "version_compare": version,
            "components": components,
            "drift_weight": sum(component["weight"] for component in changed_components),
        })
    return rows


def _compare_host(left: dict, right: dict) -> list[dict]:
    rows: list[dict] = []
    for key in sorted(set(left) | set(right)):
        first = left.get(key)
        second = right.get(key)
        status = _component_status(first, second)
        model = first or second
        weight = int(model.get("weight", 10)) if status in {"changed", "added", "removed"} else 0
        rows.append({
            "id": key,
            "display_name": model.get("display_name", key),
            "status": status,
            "risk": model.get("risk"),
            "sources_left": first.get("sources", []) if first else [],
            "sources_right": second.get("sources", []) if second else [],
            "weight": weight,
            "reason": "content hash differs" if status == "changed" else status,
        })
    return rows


def compare_targets(left_path: Path, right_path: Path | None = None) -> dict:
    left = _package_model(left_path.resolve())
    right = _package_model(right_path.resolve()) if right_path else _current_model()

    compare_apps = left["profile"] in {"applications", "production"}
    compare_host = left["profile"] in {"host", "production"}
    applications = _compare_applications(left["applications"], right["applications"]) if compare_apps else []
    host = _compare_host(left["host"], right["host"]) if compare_host else []

    total_weight = 0
    changed_weight = 0
    changed_units = 0
    total_units = 0
    for application in applications:
        if not application.get("components"):
            total_weight += 10
            total_units += 1
            if application["status"] in {"changed", "added", "removed"}:
                changed_weight += 10
                changed_units += 1
            continue
        for component in application["components"]:
            if component["status"] == "not-backed-up":
                continue
            total_units += 1
            total_weight += component["weight"]
            if component["status"] in {"changed", "added", "removed"} and component["weight"] > 0:
                changed_units += 1
                changed_weight += component["weight"]
        if application.get("version_compare", {}).get("status") == "changed":
            total_weight += 2
            changed_weight += 2

    for component in host:
        if component["status"] == "not-backed-up":
            continue
        total_units += 1
        total_weight += int((left["host"].get(component["id"]) or right["host"].get(component["id"]) or {}).get("weight", 10))
        if component["status"] in {"changed", "added", "removed"}:
            changed_units += 1
            changed_weight += component["weight"]

    drift = round(100 * changed_weight / total_weight) if total_weight else 0
    dangerous = [component["id"] for component in host if component["status"] in {"changed", "added", "removed"} and component.get("risk") == "dangerous"]
    confidence_penalties = sum(1 for application in applications if application.get("version_compare", {}).get("status") == "metadata-diff")
    compare_confidence = max(50, 100 - confidence_penalties * 5)
    impact = "high" if dangerous or drift >= 50 else ("medium" if drift >= 15 else "low")

    return {
        "schema_version": 2,
        "comparison": {
            "left": left["path"],
            "right": right["path"],
            "right_kind": right["kind"],
            "profile": left["profile"],
            "applications_scope": "included" if compare_apps else "not-included",
            "host_scope": "included" if compare_host else "not-included",
        },
        "summary": {
            "applications": len(applications),
            "host_components": len(host),
            "units": total_units,
            "changed_units": changed_units,
            "drift_score": drift,
            "drift_weight": changed_weight,
            "total_weight": total_weight,
            "compare_confidence": compare_confidence,
            "dangerous_host_differences": dangerous,
            "recovery_impact": impact,
        },
        "source_comparison": {
            "hostname_left": left["source"].get("hostname"),
            "hostname_right": right["source"].get("hostname"),
            "kernel_left": left["source"].get("kernel"),
            "kernel_right": right["source"].get("kernel"),
            "proxmox_left": left["source"].get("proxmox_version"),
            "proxmox_right": right["source"].get("proxmox_version"),
        },
        "applications": applications,
        "host": host,
        "destructive_actions_performed": False,
    }


def print_compare_report(report: dict) -> None:
    summary = report["summary"]
    scope = report["comparison"]
    print("\nPSB Compare")
    print("=" * 104)
    print(f"Left:  {scope['left']}")
    print(f"Right: {scope['right']}")
    print(f"Profile: {scope['profile']}")
    print(f"Drift score: {summary['drift_score']}%   Impact: {summary['recovery_impact'].upper()}   Confidence: {summary['compare_confidence']}%")
    print(f"Changed weighted units: {summary['changed_units']} / {summary['units']}")
    if summary["dangerous_host_differences"]:
        print("Dangerous host differences: " + ", ".join(summary["dangerous_host_differences"]))

    if scope["applications_scope"] == "included":
        print("\nApplications:")
        print(f"{'Application':28} {'Status':14} {'Version left':18} {'Version right':18} Significant changes")
        print("-" * 104)
        for application in report["applications"]:
            significant = sum(component["status"] in {"changed", "added", "removed"} and component["weight"] > 0 for component in application.get("components", []))
            print(f"{application['display_name'][:28]:28} {application['status']:14} {str(application.get('version_left'))[:18]:18} {str(application.get('version_right'))[:18]:18} {significant}")
            for component in application.get("components", []):
                marker = {"identical": "=", "changed": "!", "added": "+", "removed": "-", "not-backed-up": "o"}.get(component["status"], "?")
                if component["status"] != "identical":
                    suffix = f"; ignored runtime entries: {component['runtime_entries_ignored']}" if component.get("runtime_entries_ignored") else ""
                    print(f"    {marker} {component['type']}: {component['status']} ({component['reason']}){suffix}")
            version_compare = application.get("version_compare", {})
            if version_compare.get("status") == "metadata-diff":
                print(f"    o version metadata differs but is not trusted enough to affect drift ({version_compare.get('confidence')}% confidence)")
    else:
        print("\nApplications: not included by backup profile")

    if scope["host_scope"] == "included":
        print("\nHost configuration:")
        print(f"{'Component':30} {'Risk':16} Status")
        print("-" * 72)
        for component in report["host"]:
            print(f"{component['display_name'][:30]:30} {component.get('risk', ''):16} {component['status']}")
    else:
        print("\nHost configuration: not included by backup profile")
    print("\nAnalysis only: no files were changed.")
