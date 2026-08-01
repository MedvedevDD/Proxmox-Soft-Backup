import json
import zipfile
from pathlib import Path


def read_json_member(package: Path, member: str) -> dict:
    with zipfile.ZipFile(package, "r") as archive:
        try:
            return json.loads(archive.read(member).decode("utf-8"))
        except KeyError as exc:
            raise RuntimeError(f"Missing package member: {member}") from exc


def package_members(package: Path) -> list[str]:
    with zipfile.ZipFile(package, "r") as archive:
        return archive.namelist()


def inspect_package(package: Path) -> dict:
    package = package.resolve()
    if not package.is_file():
        raise RuntimeError(f"Package not found: {package}")
    manifest = read_json_member(package, "manifest.json")
    apps = manifest.get("applications", [])
    components = [c for app in apps for c in app.get("components", [])]
    artifacts = [a for component in components for a in component.get("artifacts", [])]
    host = manifest.get("host", {})
    host_components = host.get("components", [])
    host_artifacts = [a for component in host_components for a in component.get("artifacts", [])]
    total_size = sum(int(a.get("size", 0)) for a in artifacts + host_artifacts)
    return {
        "package": str(package),
        "format": manifest.get("format"),
        "schema_version": manifest.get("schema_version"),
        "tool_version": manifest.get("tool_version"),
        "created_at": manifest.get("created_at"),
        "hostname": manifest.get("source", {}).get("hostname"),
        "backup_mode": manifest.get("backup", {}).get("mode"),
        "backup_profile": manifest.get("backup", {}).get("profile", "production"),
        "applications": len(apps),
        "components": len(components),
        "artifacts": len(artifacts),
        "host_components": len(host_components),
        "host_artifacts": len(host_artifacts),
        "host_backup_completeness": host.get("backup_completeness"),
        "host_recovery_enabled": host.get("recovery_enabled", False),
        "artifact_bytes": total_size,
        "application_details": [
            {
                "name": app.get("name"),
                "display_name": app.get("display_name"),
                "version": app.get("version", "unknown"),
                "version_family": app.get("version_family", "default"),
                "components": len(app.get("components", [])),
                "backup_completeness": app.get("backup_completeness"),
            }
            for app in apps
        ],
        "host_details": [
            {
                "id": component.get("id"),
                "display_name": component.get("display_name"),
                "risk": component.get("risk"),
                "present": component.get("present"),
                "artifacts": len(component.get("artifacts", [])),
            }
            for component in host_components
        ],
    }
