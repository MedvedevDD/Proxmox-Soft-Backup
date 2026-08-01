from pathlib import Path
from psb.modules.common import command_exists, run
from .manifest import load_manifests
from .version import detect_version, component_applies


def package_installed(name: str) -> bool:
    if not command_exists("dpkg-query"):
        return False
    result = run(["dpkg-query", "-W", "-f=${Status}", name])
    return result.returncode == 0 and "install ok installed" in result.stdout


def service_exists(name: str) -> bool:
    if not command_exists("systemctl"):
        return False
    return run(["systemctl", "show", name, "--property=LoadState", "--value"]).stdout.strip() not in {"", "not-found"}


def service_active(name: str) -> bool:
    return command_exists("systemctl") and run(["systemctl", "is-active", name]).stdout.strip() == "active"


def binary_path(name: str) -> str:
    path = Path(name)
    if name.startswith("/") and path.exists():
        return name
    if command_exists("which"):
        result = run(["which", name])
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    for root in (Path("/usr/local/bin"), Path("/usr/local/sbin"), Path("/usr/bin"), Path("/usr/sbin"), Path("/opt")):
        candidate = root / name
        if candidate.exists():
            return str(candidate)
    return ""


def detect_manifest(manifest: dict) -> dict:
    signals = manifest.get("detection", {})
    checks = []
    evidence = []

    def check(kind: str, label: str, weight: int, ok: bool, detail: str) -> None:
        checks.append({"kind": kind, "label": label, "weight": weight, "ok": bool(ok), "detail": detail})
        if ok:
            evidence.append(f"{kind}:{detail}")

    packages = [item for item in signals.get("packages", []) if package_installed(item)]
    services = [item for item in signals.get("services", []) if service_exists(item)]
    binaries = [binary_path(item) for item in signals.get("binaries", [])]
    binaries = [item for item in binaries if item]

    version_info = detect_version(manifest, packages)
    components = []
    skipped_components = []
    for component in manifest.get("components", []):
        if not component_applies(component, version_info):
            skipped_components.append({"path": component["path"], "reason": f"not applicable to {version_info['version_family']}"})
            continue
        path = Path(component["path"])
        components.append({
            "path": component["path"],
            "level": component.get("importance", "critical"),
            "kind": component.get("kind", "data"),
            "exists": path.exists() or path.is_symlink(),
            "required": component.get("required", True),
            "weight": int(component.get("weight", 0)),
        })

    existing = [component for component in components if component["exists"]]
    if signals.get("packages"):
        check("package", "Package installed", 25, bool(packages), ", ".join(packages) or "none")
    if signals.get("services"):
        check("service", "Service definition", 25, bool(services), ", ".join(services) or "none")
    if signals.get("binaries"):
        check("binary", "Executable", 20, bool(binaries), ", ".join(binaries) or "none")
    check("component", "Application data", 30, bool(existing), ", ".join(component["path"] for component in existing) or "none")

    score = sum(item["weight"] for item in checks if item["ok"])
    possible = sum(item["weight"] for item in checks) or 1
    confidence = round(score * 100 / possible)
    detected = bool(evidence) and confidence >= 20
    active = [service for service in services if service_active(service)]

    critical = [component for component in components if component["level"] == "critical" and component.get("required", True)]
    if any(component.get("weight", 0) > 0 for component in critical):
        total_weight = sum(component.get("weight", 0) for component in critical)
        found_weight = sum(component.get("weight", 0) for component in critical if component["exists"])
        readiness = round(found_weight * 100 / total_weight) if total_weight else 100
    else:
        missing = [component for component in critical if not component["exists"]]
        readiness = 100 if not critical else round(100 * (len(critical) - len(missing)) / len(critical))

    missing_critical = [component["path"] for component in critical if not component["exists"]]
    health = "healthy" if active else ("installed" if detected else "not-detected")

    return {
        "name": manifest["id"],
        "display_name": manifest["display_name"],
        "category": manifest.get("category", "Other"),
        "detected": detected,
        "confidence": confidence if detected else 0,
        "confidence_checks": checks,
        "evidence": evidence,
        "missing_signals": [item["label"] for item in checks if not item["ok"]],
        "packages": packages,
        "services": services,
        "active_services": active,
        "paths": components,
        "skipped_version_components": skipped_components,
        "dependencies": manifest.get("dependencies", []),
        "manifest_path": manifest.get("manifest_path", ""),
        "health": health,
        "recovery_readiness": readiness,
        "backup_completeness": readiness,
        "missing_critical_components": missing_critical,
        **version_info,
    }


def detect_applications() -> list[dict]:
    applications = [detect_manifest(manifest) for manifest in load_manifests()]
    return sorted([application for application in applications if application["detected"]], key=lambda item: (item["category"], item["display_name"]))
