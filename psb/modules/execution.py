import datetime as dt
import json
import os
import hashlib
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.request
import uuid
import zipfile
from pathlib import Path, PurePosixPath

from .compare import _hash_parts, _ignored, _tar_signature
from .recovery import build_recovery_preview
from .rollback import RECOVERY_LOCK, ROLLBACK_STATE_DIR, create_rollback_package
from .verify import verify_backup

GRAFANA_APPLICATION = "grafana"
GRAFANA_COMPONENT = "database"
GRAFANA_SOURCE = Path("/var/lib/grafana")
GRAFANA_SERVICE = "grafana-server.service"

INFLUXDB_APPLICATION = "influxdb"
INFLUXDB_COMPONENT = "database"
INFLUXDB_SOURCE = Path("/var/lib/influxdb")
INFLUXDB_SERVICES = ("influxdb.service", "influxd.service")


def _run(command: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(command, text=True, capture_output=True, check=False)


def _write_lock(data: dict) -> None:
    ROLLBACK_STATE_DIR.mkdir(parents=True, exist_ok=True)
    RECOVERY_LOCK.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    os.chmod(RECOVERY_LOCK, 0o600)


def read_recovery_lock() -> dict | None:
    if not RECOVERY_LOCK.is_file():
        return None
    try:
        return json.loads(RECOVERY_LOCK.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"state": "invalid", "error": str(exc), "lock_path": str(RECOVERY_LOCK)}


def abort_recovery_lock() -> bool:
    if not RECOVERY_LOCK.exists():
        return False
    RECOVERY_LOCK.unlink()
    return True


def _selected_action(preview: dict, application: str, component_type: str) -> dict:
    matches = [
        item for item in preview.get("actions", [])
        if item.get("scope") == "application"
        and item.get("application") == application
        and item.get("component_type") == component_type
        and item.get("action") == "restore"
    ]
    if len(matches) != 1:
        raise RuntimeError(
            f"Expected exactly one writable action for {application}/{component_type}; found {len(matches)}"
        )
    return matches[0]


def _filtered_preview(preview: dict, selected: dict) -> dict:
    result = json.loads(json.dumps(preview))
    for action in result.get("actions", []):
        same = (
            action.get("scope") == selected.get("scope")
            and action.get("application") == selected.get("application")
            and action.get("component") == selected.get("component")
        )
        if not same:
            action["action"] = "skip"
            action["rollback_required"] = False
    result["summary"]["restore_components"] = 1
    result["summary"]["review_components"] = 0
    result["summary"]["blocked_components"] = 0
    result["summary"]["restore_bytes"] = int(selected.get("artifact_bytes", 0))
    result["summary"]["rollback_estimate_bytes"] = int(selected.get("artifact_bytes", 0))
    return result


def _find_artifact(package: Path, action: dict) -> tuple[str, bytes]:
    with zipfile.ZipFile(package, "r") as archive:
        manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
        app = next((x for x in manifest.get("applications", []) if x.get("name") == action.get("application")), None)
        if not app:
            raise RuntimeError("Application is missing from backup manifest")
        component = next((x for x in app.get("components", []) if x.get("id") == action.get("component")), None)
        if not component:
            raise RuntimeError("Component is missing from backup manifest")
        artifacts = component.get("artifacts", [])
        if len(artifacts) != 1:
            raise RuntimeError("Recovery requires exactly one component artifact")
        member = artifacts[0].get("path")
        if not member:
            raise RuntimeError("Artifact path is missing")
        return member, archive.read(member)


def _validate_tar_member(member: tarfile.TarInfo) -> None:
    path = PurePosixPath(member.name)
    if path.is_absolute() or ".." in path.parts:
        raise RuntimeError(f"Unsafe archive member: {member.name}")
    if member.ischr() or member.isblk() or member.isfifo():
        raise RuntimeError(f"Unsupported special archive member: {member.name}")
    if member.issym() or member.islnk():
        link = PurePosixPath(member.linkname)
        if link.is_absolute() or ".." in link.parts:
            raise RuntimeError(f"Unsafe archive link: {member.name} -> {member.linkname}")


def _safe_extract_tar(data: bytes, destination: Path, canonical_source: Path) -> Path:
    artifact_file = destination / "component.tar.gz"
    artifact_file.write_bytes(data)
    with tarfile.open(artifact_file, "r:gz") as archive:
        members = archive.getmembers()
        for member in members:
            _validate_tar_member(member)
        archive.extractall(destination, members=members)
    restored = destination / str(canonical_source).lstrip("/")
    if not restored.is_dir():
        raise RuntimeError(f"Restored directory is missing from artifact: {canonical_source}")
    return restored



def _directory_signature_as_source(root: Path, canonical: Path) -> str | None:
    parts: list[str] = []
    items = [root] + sorted(root.rglob("*"))
    for item in items:
        suffix = item.relative_to(root)
        relative = str(canonical.joinpath(suffix)).lstrip("/")
        if _ignored(relative):
            continue
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
    return _hash_parts(parts) if parts else None

def _confirm(application: str, component: str) -> None:
    if not os.isatty(0):
        raise RuntimeError("Safe Recovery requires an interactive terminal")
    phrase = f"RESTORE {application.upper()} {component.upper()}"
    print("\nConfirmation 1/3: Type YES to continue.")
    if input("> ").strip() != "YES":
        raise RuntimeError("Recovery cancelled at confirmation 1")
    print("\nConfirmation 2/3: Type RESTORE to confirm system modification.")
    if input("> ").strip() != "RESTORE":
        raise RuntimeError("Recovery cancelled at confirmation 2")
    print(f"\nConfirmation 3/3: Type {phrase} exactly.")
    if input("> ").strip() != phrase:
        raise RuntimeError("Recovery cancelled at confirmation 3")


def _service_active(service: str) -> bool:
    return _run(["systemctl", "is-active", "--quiet", service]).returncode == 0


def _service_stop(service: str) -> None:
    result = _run(["systemctl", "stop", service])
    if result.returncode != 0:
        raise RuntimeError(f"Failed to stop {service}: {result.stderr.strip() or result.stdout.strip()}")


def _service_start(service: str) -> None:
    result = _run(["systemctl", "start", service])
    if result.returncode != 0:
        raise RuntimeError(f"Failed to start {service}: {result.stderr.strip() or result.stdout.strip()}")
    if not _service_active(service):
        raise RuntimeError(f"Service did not become active: {service}")


def _grafana_http_health(timeout_seconds: float = 30.0, interval_seconds: float = 2.0) -> dict:
    started = time.monotonic()
    attempts = 0
    last_error = None
    while True:
        attempts += 1
        try:
            request = urllib.request.Request(
                "http://127.0.0.1:3000/api/health",
                headers={"User-Agent": "Proxmox-Soft-Backup/0.9.4"},
            )
            with urllib.request.urlopen(request, timeout=min(5.0, timeout_seconds)) as response:
                body = response.read(4096).decode("utf-8", "replace")
                elapsed = round(time.monotonic() - started, 3)
                return {
                    "checked": True,
                    "ok": 200 <= response.status < 300,
                    "status": response.status,
                    "body": body,
                    "attempts": attempts,
                    "wait_seconds": elapsed,
                    "implementation": "python-urllib",
                }
        except Exception as exc:
            last_error = str(exc)
        elapsed = time.monotonic() - started
        if elapsed >= timeout_seconds:
            return {
                "checked": True,
                "ok": False,
                "error": last_error or "health check timed out",
                "advisory": True,
                "attempts": attempts,
                "wait_seconds": round(elapsed, 3),
                "timeout_seconds": timeout_seconds,
                "implementation": "python-urllib",
            }
        time.sleep(min(interval_seconds, max(0.0, timeout_seconds - elapsed)))


def execute_grafana_database_recovery(
    package: Path,
    rollback_destination: Path,
    rollback_name: str | None = None,
    interactive: bool = True,
    target_override: Path | None = None,
    manage_service: bool = True,
) -> dict:
    package = package.resolve()
    existing_lock = read_recovery_lock()
    if existing_lock is not None:
        raise RuntimeError(
            f"Recovery lock already exists with state {existing_lock.get('state', 'unknown')}. "
            "Run psb recovery-status and psb recovery-abort before starting a new recovery."
        )
    ok, messages = verify_backup(package)
    if not ok:
        raise RuntimeError("Source backup verification failed: " + "; ".join(messages))

    preview = build_recovery_preview(package)
    selected = _selected_action(preview, GRAFANA_APPLICATION, GRAFANA_COMPONENT)
    sources = [Path(item) for item in selected.get("sources", [])]
    if sources != [GRAFANA_SOURCE]:
        raise RuntimeError(f"Unexpected Grafana database source paths: {sources}")

    target = target_override.resolve() if target_override else GRAFANA_SOURCE
    if target_override is None and target != GRAFANA_SOURCE:
        raise RuntimeError("Grafana database target validation failed")
    if not target.exists():
        raise RuntimeError(f"Current Grafana database directory does not exist: {target}")

    selected_for_rollback = json.loads(json.dumps(selected))
    if target_override is not None:
        selected_for_rollback["sources"] = [str(target)]
    filtered = _filtered_preview(preview, selected_for_rollback)
    rollback_package, rollback_result = create_rollback_package(
        filtered, rollback_destination, rollback_name, create_lock=True
    )
    rollback_ok, rollback_messages = verify_backup(rollback_package)
    if not rollback_ok:
        raise RuntimeError("Rollback verification failed: " + "; ".join(rollback_messages))

    # Re-check after rollback creation so execution never uses a stale preview.
    fresh_preview = build_recovery_preview(package)
    fresh_selected = _selected_action(fresh_preview, GRAFANA_APPLICATION, GRAFANA_COMPONENT)
    if fresh_selected.get("reason") != selected.get("reason"):
        raise RuntimeError("System state changed after preview; rerun recovery")

    if interactive:
        _confirm(GRAFANA_APPLICATION, GRAFANA_COMPONENT)

    member, artifact_data = _find_artifact(package, selected)
    expected_signature, _, _ = _tar_signature(artifact_data)
    operation_id = str(uuid.uuid4())
    operation_started_monotonic = time.monotonic()
    started_at = dt.datetime.now(dt.timezone.utc).isoformat()
    lock = read_recovery_lock() or {}
    lock.update({
        "schema_version": 2,
        "state": "executing",
        "execution_enabled": True,
        "operation_id": operation_id,
        "application": GRAFANA_APPLICATION,
        "component": GRAFANA_COMPONENT,
        "source_backup": str(package),
        "rollback_package": str(rollback_package),
        "artifact_member": member,
        "target": str(target),
        "started_at": started_at,
        "pid": os.getpid(),
    })
    _write_lock(lock)

    service_was_active = _service_active(GRAFANA_SERVICE) if manage_service else False
    parent = target.parent
    staging = Path(tempfile.mkdtemp(prefix=".psb-grafana-stage-", dir=parent))
    old_path = parent / f".psb-grafana-old-{operation_id}"
    restored_installed = False
    current_moved = False
    try:
        restored = _safe_extract_tar(artifact_data, staging, GRAFANA_SOURCE)
        if expected_signature is None:
            raise RuntimeError("Unable to calculate backup component signature")

        if manage_service and service_was_active:
            _service_stop(GRAFANA_SERVICE)

        target.rename(old_path)
        current_moved = True
        restored.rename(target)
        restored_installed = True

        installed_signature = _directory_signature_as_source(target, GRAFANA_SOURCE)
        if installed_signature != expected_signature:
            raise RuntimeError("Installed Grafana database checksum does not match backup artifact")

        if manage_service and service_was_active:
            _service_start(GRAFANA_SERVICE)
        health = _grafana_http_health() if manage_service and service_was_active else {"checked": False, "ok": True}

        shutil.rmtree(old_path)
        current_moved = False
        lock.update({
            "state": "completed",
            "execution_enabled": False,
            "completed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "service_active": _service_active(GRAFANA_SERVICE) if manage_service else None,
            "http_health": health,
            "duration_seconds": round(time.monotonic() - operation_started_monotonic, 3),
        })
        _write_lock(lock)
        return {
            "status": "completed",
            "operation_id": operation_id,
            "application": GRAFANA_APPLICATION,
            "component": GRAFANA_COMPONENT,
            "backup": str(package),
            "rollback_package": str(rollback_package),
            "rollback_verified": True,
            "target": str(target),
            "service_was_active": service_was_active,
            "service_active_after": _service_active(GRAFANA_SERVICE) if manage_service else None,
            "http_health": health,
            "duration_seconds": round(time.monotonic() - operation_started_monotonic, 3),
            "lock_path": str(RECOVERY_LOCK),
        }
    except Exception as exc:
        rollback_error = None
        try:
            if manage_service and _service_active(GRAFANA_SERVICE):
                _service_stop(GRAFANA_SERVICE)
            if restored_installed and target.exists():
                shutil.rmtree(target)
            if current_moved and old_path.exists():
                old_path.rename(target)
                current_moved = False
            if manage_service and service_was_active:
                _service_start(GRAFANA_SERVICE)
        except Exception as rollback_exc:
            rollback_error = str(rollback_exc)
        lock.update({
            "state": "rolled-back" if rollback_error is None else "rollback-failed",
            "execution_enabled": False,
            "failed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "error": str(exc),
            "rollback_error": rollback_error,
            "duration_seconds": round(time.monotonic() - operation_started_monotonic, 3),
        })
        _write_lock(lock)
        if rollback_error:
            raise RuntimeError(f"Recovery failed: {exc}; automatic rollback also failed: {rollback_error}") from exc
        raise RuntimeError(f"Recovery failed and previous state was restored: {exc}") from exc
    finally:
        shutil.rmtree(staging, ignore_errors=True)



def _active_services(services: tuple[str, ...]) -> list[str]:
    return [service for service in services if _service_active(service)]


def _stop_services(services: list[str]) -> None:
    stopped: list[str] = []
    try:
        for service in services:
            _service_stop(service)
            stopped.append(service)
    except Exception:
        for service in reversed(stopped):
            try:
                _service_start(service)
            except Exception:
                pass
        raise


def _start_services(services: list[str]) -> None:
    errors: list[str] = []
    for service in services:
        try:
            _service_start(service)
        except Exception as exc:
            errors.append(f"{service}: {exc}")
    if errors:
        raise RuntimeError("Failed to restore service state: " + "; ".join(errors))


def _influxdb_http_health(timeout_seconds: float = 30.0, interval_seconds: float = 2.0) -> dict:
    started = time.monotonic()
    attempts = 0
    last_error = None
    while True:
        attempts += 1
        try:
            request = urllib.request.Request(
                "http://127.0.0.1:8086/ping",
                headers={"User-Agent": "Proxmox-Soft-Backup/0.9.4"},
            )
            with urllib.request.urlopen(request, timeout=min(5.0, timeout_seconds)) as response:
                elapsed = round(time.monotonic() - started, 3)
                return {
                    "checked": True,
                    "ok": response.status in {200, 204},
                    "status": response.status,
                    "attempts": attempts,
                    "wait_seconds": elapsed,
                    "implementation": "python-urllib",
                }
        except Exception as exc:
            last_error = str(exc)
        elapsed = time.monotonic() - started
        if elapsed >= timeout_seconds:
            return {
                "checked": True,
                "ok": False,
                "error": last_error or "health check timed out",
                "advisory": True,
                "attempts": attempts,
                "wait_seconds": round(elapsed, 3),
                "timeout_seconds": timeout_seconds,
                "implementation": "python-urllib",
            }
        time.sleep(min(interval_seconds, max(0.0, timeout_seconds - elapsed)))


def execute_influxdb_database_recovery(
    package: Path,
    rollback_destination: Path,
    rollback_name: str | None = None,
    interactive: bool = True,
    target_override: Path | None = None,
    manage_service: bool = True,
) -> dict:
    package = package.resolve()
    existing_lock = read_recovery_lock()
    if existing_lock is not None:
        raise RuntimeError(
            f"Recovery lock already exists with state {existing_lock.get('state', 'unknown')}. "
            "Run psb recovery-status and psb recovery-abort before starting a new recovery."
        )
    ok, messages = verify_backup(package)
    if not ok:
        raise RuntimeError("Source backup verification failed: " + "; ".join(messages))

    preview = build_recovery_preview(package)
    selected = _selected_action(preview, INFLUXDB_APPLICATION, INFLUXDB_COMPONENT)
    sources = [Path(item) for item in selected.get("sources", [])]
    if sources != [INFLUXDB_SOURCE]:
        raise RuntimeError(f"Unexpected InfluxDB database source paths: {sources}")

    target = target_override.resolve() if target_override else INFLUXDB_SOURCE
    if target_override is None and target != INFLUXDB_SOURCE:
        raise RuntimeError("InfluxDB database target validation failed")
    if not target.is_dir():
        raise RuntimeError(f"Current InfluxDB database directory does not exist: {target}")

    member, artifact_data = _find_artifact(package, selected)
    expected_signature, _, _ = _tar_signature(artifact_data)
    if expected_signature is None:
        raise RuntimeError("Unable to calculate backup component signature")

    if interactive:
        _confirm(INFLUXDB_APPLICATION, INFLUXDB_COMPONENT)

    operation_id = str(uuid.uuid4())
    operation_started_monotonic = time.monotonic()
    started_at = dt.datetime.now(dt.timezone.utc).isoformat()
    active_services = _active_services(INFLUXDB_SERVICES) if manage_service else []
    parent = target.parent
    staging = Path(tempfile.mkdtemp(prefix=".psb-influxdb-stage-", dir=parent))
    old_path = parent / f".psb-influxdb-old-{operation_id}"
    restored_installed = False
    current_moved = False
    rollback_package: Path | None = None
    lock: dict = {
        "schema_version": 3,
        "state": "preparing",
        "execution_enabled": False,
        "operation_id": operation_id,
        "application": INFLUXDB_APPLICATION,
        "component": INFLUXDB_COMPONENT,
        "source_backup": str(package),
        "artifact_member": member,
        "target": str(target),
        "started_at": started_at,
        "pid": os.getpid(),
        "services_active_before": active_services,
    }
    _write_lock(lock)

    try:
        # InfluxDB must be stopped before the rollback snapshot to make both the
        # rollback and restored database consistent on disk.
        if manage_service and active_services:
            _stop_services(active_services)

        selected_for_rollback = json.loads(json.dumps(selected))
        if target_override is not None:
            selected_for_rollback["sources"] = [str(target)]
        filtered = _filtered_preview(preview, selected_for_rollback)
        rollback_package, rollback_result = create_rollback_package(
            filtered, rollback_destination, rollback_name, create_lock=False
        )
        rollback_ok, rollback_messages = verify_backup(rollback_package)
        if not rollback_ok:
            raise RuntimeError("Rollback verification failed: " + "; ".join(rollback_messages))

        lock.update({
            "state": "executing",
            "execution_enabled": True,
            "rollback_id": rollback_result.get("rollback_id"),
            "rollback_package": str(rollback_package),
            "rollback_verified": True,
        })
        _write_lock(lock)

        restored = _safe_extract_tar(artifact_data, staging, INFLUXDB_SOURCE)
        target.rename(old_path)
        current_moved = True
        restored.rename(target)
        restored_installed = True

        installed_signature = _directory_signature_as_source(target, INFLUXDB_SOURCE)
        if installed_signature != expected_signature:
            raise RuntimeError("Installed InfluxDB database checksum does not match backup artifact")

        if manage_service and active_services:
            _start_services(active_services)
        health = _influxdb_http_health() if manage_service and active_services else {"checked": False, "ok": True}
        if health.get("checked") and not health.get("ok"):
            raise RuntimeError(f"InfluxDB HTTP health check failed: {health.get('error', health.get('status'))}")

        shutil.rmtree(old_path)
        current_moved = False
        duration = round(time.monotonic() - operation_started_monotonic, 3)
        lock.update({
            "state": "completed",
            "execution_enabled": False,
            "completed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "services_active_after": _active_services(INFLUXDB_SERVICES) if manage_service else [],
            "http_health": health,
            "duration_seconds": duration,
        })
        _write_lock(lock)
        return {
            "status": "completed",
            "operation_id": operation_id,
            "application": INFLUXDB_APPLICATION,
            "component": INFLUXDB_COMPONENT,
            "backup": str(package),
            "rollback_package": str(rollback_package),
            "rollback_verified": True,
            "target": str(target),
            "services_active_before": active_services,
            "services_active_after": _active_services(INFLUXDB_SERVICES) if manage_service else [],
            "http_health": health,
            "duration_seconds": duration,
            "lock_path": str(RECOVERY_LOCK),
        }
    except Exception as exc:
        rollback_error = None
        try:
            for service in _active_services(INFLUXDB_SERVICES):
                _service_stop(service)
            if restored_installed and target.exists():
                shutil.rmtree(target)
            if current_moved and old_path.exists():
                old_path.rename(target)
                current_moved = False
            if manage_service and active_services:
                _start_services(active_services)
        except Exception as rollback_exc:
            rollback_error = str(rollback_exc)
        lock.update({
            "state": "rolled-back" if rollback_error is None else "rollback-failed",
            "execution_enabled": False,
            "failed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "error": str(exc),
            "rollback_error": rollback_error,
            "duration_seconds": round(time.monotonic() - operation_started_monotonic, 3),
            "rollback_package": str(rollback_package) if rollback_package else None,
        })
        _write_lock(lock)
        if rollback_error:
            raise RuntimeError(f"Recovery failed: {exc}; automatic rollback also failed: {rollback_error}") from exc
        raise RuntimeError(f"Recovery failed and previous state was restored: {exc}") from exc
    finally:
        shutil.rmtree(staging, ignore_errors=True)
