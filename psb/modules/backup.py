import datetime as dt
import json
import os
import shutil
import socket
import tarfile
import tempfile
import zipfile
from pathlib import Path

from .common import command_exists, iter_files, run, safe_rel, sha256_file, write_json
from .scanner import scan_system
from .host import host_inventory

HOST_PATHS = [
    "/etc/pve", "/etc/network/interfaces", "/etc/network/interfaces.d",
    "/etc/hosts", "/etc/hostname", "/etc/resolv.conf", "/etc/apt",
    "/etc/default", "/etc/modprobe.d", "/etc/modules", "/etc/modules-load.d",
    "/etc/udev/rules.d", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
    "/etc/cron.monthly", "/etc/cron.weekly", "/etc/systemd/system",
    "/usr/local/bin", "/usr/local/sbin", "/var/lib/vz/snippets",
    "/boot/grub/grub.cfg", "/etc/default/grub",
]

WEIGHTS = {
    "configuration": 35, "database": 35, "credentials": 20, "secrets": 20,
    "quota_state": 15, "application": 15, "binary": 10, "systemd": 3,
    "service": 3, "plugins": 5, "state": 5, "source": 3, "logs": 1,
}


def archive_paths(output: Path, paths: list[str]) -> list[str]:
    included = []
    with tarfile.open(output, "w:gz", dereference=False) as archive:
        for raw in paths:
            path = Path(raw)
            if not path.exists() and not path.is_symlink():
                continue
            archive.add(path, arcname=str(path).lstrip("/"), recursive=True)
            included.append(str(path))
    return included


def collect_reports(report_dir: Path) -> None:
    report_dir.mkdir(parents=True, exist_ok=True)
    commands = {
        "ip-address.txt": ["ip", "address"], "ip-route.txt": ["ip", "route"],
        "lsblk.txt": ["lsblk", "-O"], "blkid.txt": ["blkid"], "df.txt": ["df", "-hT"],
        "mount.txt": ["mount"], "systemctl-failed.txt": ["systemctl", "--failed", "--no-pager"],
        "dpkg-packages.txt": ["dpkg-query", "-W"], "apt-manual.txt": ["apt-mark", "showmanual"],
        "pveversion.txt": ["pveversion", "-v"], "pvesm-status.txt": ["pvesm", "status"],
        "qm-list.txt": ["qm", "list"], "pct-list.txt": ["pct", "list"],
    }
    for filename, command in commands.items():
        if not command_exists(command[0]):
            continue
        result = run(command)
        content = result.stdout + (("\n--- STDERR ---\n" + result.stderr) if result.stderr else "")
        (report_dir / filename).write_text(content, encoding="utf-8", errors="replace")


def component_id(kind: str, index: int) -> str:
    clean = "".join(ch if ch.isalnum() else "-" for ch in kind.lower()).strip("-") or "data"
    return f"{clean}-{index:02d}"


def backup_application(app: dict, output_dir: Path, stop_services: bool, mode: str) -> dict:
    name = app["name"]
    services = app.get("services", [])
    stopped = []
    if stop_services and command_exists("systemctl"):
        for service in services:
            if run(["systemctl", "is-active", service]).stdout.strip() == "active":
                if run(["systemctl", "stop", service]).returncode == 0:
                    stopped.append(service)
    allowed = {"minimal": {"critical"}, "standard": {"critical", "important"}, "full": {"critical", "important", "optional"}}[mode]
    components = []
    try:
        app_dir = output_dir / name / "components"
        app_dir.mkdir(parents=True, exist_ok=True)
        for index, spec in enumerate(app.get("paths", []), start=1):
            kind = spec.get("kind", "data")
            cid = component_id(kind, index)
            selected = spec.get("level") in allowed
            exists = bool(spec.get("exists"))
            weight = int(spec.get("weight") or WEIGHTS.get(kind, 5))
            component = {
                "id": cid, "type": kind, "importance": spec.get("level", "critical"),
                "weight": weight, "strategy": "filesystem-tar", "sources": [spec["path"]],
                "selected": selected, "present": exists, "artifacts": [],
            }
            if selected and exists:
                artifact_path = app_dir / f"{cid}.tar.gz"
                included = archive_paths(artifact_path, [spec["path"]])
                component["artifacts"].append({
                    "id": f"{cid}-artifact", "type": "tar-gzip",
                    "path": safe_rel(artifact_path, output_dir.parent),
                    "size": artifact_path.stat().st_size,
                    "sha256": sha256_file(artifact_path), "portable": True,
                    "generated": True, "compression": "gzip", "included_paths": included,
                })
            components.append(component)
        selected_weight = sum(c["weight"] for c in components if c["selected"])
        present_weight = sum(c["weight"] for c in components if c["selected"] and c["present"])
        completeness = round(100 * present_weight / selected_weight) if selected_weight else 100
        return {
            "name": name, "display_name": app.get("display_name", name),
            "category": app.get("category", "Other"), "version": app.get("version", "unknown"), "version_family": app.get("version_family", "default"), "version_source": app.get("version_source", "none"),
            "detection_confidence": app.get("confidence", 0), "backup_completeness": completeness,
            "runtime_health": app.get("health", "unknown"), "launch_type": app.get("launch_type", "systemd" if services else "manual"),
            "packages": app.get("packages", []), "services": services,
            "dependencies": app.get("dependencies", []), "components": components,
            "services_stopped": stopped,
        }
    finally:
        if stopped and command_exists("systemctl"):
            for service in reversed(stopped):
                run(["systemctl", "start", service])


def backup_host_components(host_data: dict, root: Path) -> dict:
    host_root = root / "host" / "components"
    host_root.mkdir(parents=True, exist_ok=True)
    components = []
    for spec in host_data.get("components", []):
        record = {
            "id": spec["id"],
            "display_name": spec["display_name"],
            "type": "host-configuration",
            "importance": spec["importance"],
            "risk": spec["risk"],
            "weight": spec["weight"],
            "strategy": "filesystem-tar",
            "sources": spec.get("paths", []),
            "present": spec.get("present", False),
            "artifacts": [],
            "recovery_enabled": False,
        }
        if spec.get("existing_paths"):
            artifact_path = host_root / f"{spec['id']}.tar.gz"
            included = archive_paths(artifact_path, spec["existing_paths"])
            record["artifacts"].append({
                "id": f"host-{spec['id']}-artifact",
                "type": "tar-gzip",
                "path": safe_rel(artifact_path, root),
                "size": artifact_path.stat().st_size,
                "sha256": sha256_file(artifact_path),
                "portable": spec["risk"] == "safe",
                "generated": True,
                "compression": "gzip",
                "included_paths": included,
            })
        components.append(record)
    fingerprint_path = root / "host" / "fingerprint.json"
    write_json(fingerprint_path, host_data.get("fingerprint", {}))
    return {
        "display_name": host_data.get("display_name"),
        "backup_completeness": host_data.get("backup_completeness"),
        "recovery_enabled": False,
        "fingerprint_path": "host/fingerprint.json",
        "components": components,
    }


def create_backup(destination: Path, name: str | None, include_root: bool, stop_services: bool, mode: str = "standard", profile: str = "production") -> Path:
    destination = destination.resolve(); destination.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    base_name = name or f"psb-{socket.gethostname()}-{profile}-{stamp}"
    if not base_name.endswith(".psb"):
        base_name += ".psb"
    package_path = destination / base_name
    if package_path.exists():
        raise RuntimeError(f"Backup package already exists: {package_path}")
    if profile not in {"production", "host", "applications"}:
        raise RuntimeError(f"Unsupported backup profile: {profile}")
    with tempfile.TemporaryDirectory(prefix="psb-build-") as temp:
        root = Path(temp)
        for child in ("reports", "host", "applications"):
            (root / child).mkdir(parents=True)
        inventory = scan_system()
        host_data = host_inventory()
        user_inventory = {k: v for k, v in inventory.items() if k not in {"intelligent_services", "dependency_graph"}}
        user_inventory["host_configuration"] = host_data
        write_json(root / "inventory.json", user_inventory)
        collect_reports(root / "reports")
        host_manifest = backup_host_components(host_data, root) if profile in {"production", "host"} else {"components": [], "recovery_enabled": False}
        applications = []
        if profile in {"production", "applications"}:
            applications = [backup_application(app, root / "applications", stop_services, mode) for app in inventory["applications"]]
        if include_root and profile != "host":
            root_artifact = root / "host" / "root-extra.tar.gz"
            included = archive_paths(root_artifact, ["/root"])
            host_manifest.setdefault("components", []).append({
                "id": "root-extra", "display_name": "Root Home Extra", "type": "host-extra",
                "importance": "optional", "risk": "dangerous", "weight": 0,
                "strategy": "filesystem-tar", "sources": ["/root"], "present": bool(included),
                "recovery_enabled": False,
                "artifacts": [{"id": "root-extra-artifact", "type": "tar-gzip", "path": "host/root-extra.tar.gz", "size": root_artifact.stat().st_size, "sha256": sha256_file(root_artifact), "portable": False, "generated": True, "compression": "gzip", "included_paths": included}] if included else [],
            })
        restore_order = [a["name"] for a in applications]
        manifest = {
            "format": "Proxmox Soft Backup Package", "schema_version": 4, "tool_version": "0.9.2",
            "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "source": {"hostname": socket.gethostname(), "architecture": inventory.get("architecture"), "kernel": inventory.get("kernel"), "proxmox_version": inventory.get("proxmox_version")},
            "backup": {"mode": mode, "profile": profile, "include_root": include_root, "service_stop_enabled": stop_services},
            "host": host_manifest,
            "applications": applications,
        }
        write_json(root / "manifest.json", manifest)
        write_json(root / "restore-plan.json", {
            "schema_version": 2,
            "application_order": restore_order,
            "host_components": [{"id": c["id"], "risk": c["risk"], "recovery_enabled": False} for c in host_manifest.get("components", [])],
            "destructive_restore_enabled": False,
            "host_restore_enabled": False,
            "requires_dry_run": True,
            "confirmation_count_required": 3,
        })
        write_json(root / "doctor.json", {"created_at": manifest["created_at"], "host": {"backup": host_manifest.get("backup_completeness"), "recovery_enabled": False}, "applications": [{"name": a["name"], "detection": a["detection_confidence"], "backup": a["backup_completeness"], "runtime": a["runtime_health"]} for a in applications]})
        checksum_lines = []
        for path in iter_files(root):
            if path.name == "checksums.sha256": continue
            checksum_lines.append(f"{sha256_file(path)}  {safe_rel(path, root)}")
        (root / "checksums.sha256").write_text("\n".join(checksum_lines) + "\n", encoding="ascii")
        with zipfile.ZipFile(package_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            for path in iter_files(root):
                archive.write(path, safe_rel(path, root))
    return package_path
