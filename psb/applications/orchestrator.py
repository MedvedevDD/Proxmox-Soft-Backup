import datetime as dt
import json
import os
import shutil
import tempfile
import time
import uuid
from pathlib import Path

from .recovery_plan import application_recovery_order
from ..modules.compare import _tar_signature
from ..modules.execution import (
    GRAFANA_CONFIGURATION_SOURCE,
    GRAFANA_PLUGINS_SOURCE,
    GRAFANA_SERVICE,
    GRAFANA_SOURCE,
    INFLUXDB_CONFIGURATION_SOURCE,
    INFLUXDB_SERVICES,
    INFLUXDB_SOURCE,
    NUT_SERVICES,
    NUT_SOURCE,
    NUT_STATE_SOURCE,
    NUT_SYSTEMD_SOURCE,
    RECOVERY_LOCK,
    TELEGRAF_SERVICE,
    TELEGRAF_SOURCE,
    TELEGRAF_STATE_SOURCE,
    _active_services,
    _directory_signature_as_source,
    _find_artifact,
    _run,
    _safe_extract_tar,
    _start_services,
    _stop_services,
    _write_lock,
    read_recovery_lock,
)
from ..modules.recovery import build_recovery_preview
from ..modules.rollback import create_rollback_package
from ..modules.verify import verify_backup


WRITABLE_ACTIONS = {"restore", "review"}

APPLICATION_TARGETS = {
    "grafana": {
        "configuration": GRAFANA_CONFIGURATION_SOURCE,
        "plugins": GRAFANA_PLUGINS_SOURCE,
        "database": GRAFANA_SOURCE,
    },
    "influxdb": {
        "configuration": INFLUXDB_CONFIGURATION_SOURCE,
        "database": INFLUXDB_SOURCE,
    },
    "telegraf": {
        "configuration": TELEGRAF_SOURCE,
        "state": TELEGRAF_STATE_SOURCE,
    },
    "nut": {
        "configuration": NUT_SOURCE,
        "systemd": NUT_SYSTEMD_SOURCE,
        "state": NUT_STATE_SOURCE,
    },
}

APPLICATION_SERVICES = {
    "grafana": (GRAFANA_SERVICE,),
    "influxdb": INFLUXDB_SERVICES,
    "telegraf": (TELEGRAF_SERVICE,),
    "nut": NUT_SERVICES,
}

DAEMON_RELOAD_COMPONENTS = {
    ("nut", "systemd"),
}


def _application_actions(preview: dict, application: str) -> list[dict]:
    return [
        action
        for action in preview.get("actions", [])
        if action.get("scope") == "application"
        and action.get("application") == application
    ]


def _ordered_actions(preview: dict, application: str) -> list[dict]:
    actions = _application_actions(preview, application)
    by_type = {
        action.get("component_type"): action
        for action in actions
        if action.get("component_type")
    }
    return [
        by_type[component_type]
        for component_type in application_recovery_order(application)
        if component_type in by_type
    ]


def _normalized_sources(action: dict) -> list[Path]:
    return [Path(source).resolve() for source in action.get("sources", [])]


def _path_relation(left: Path, right: Path) -> str | None:
    if left == right:
        return "equal"
    try:
        left.relative_to(right)
        return "left-inside-right"
    except ValueError:
        pass
    try:
        right.relative_to(left)
        return "right-inside-left"
    except ValueError:
        return None


def _component_depth(action: dict) -> int:
    sources = _normalized_sources(action)
    if not sources:
        return 0
    return min(len(source.parts) for source in sources)


def _nested_component_dependencies(actions: list[dict]) -> list[dict]:
    dependencies = []
    for left_index, left_action in enumerate(actions):
        for right_action in actions[left_index + 1:]:
            for left_source in _normalized_sources(left_action):
                for right_source in _normalized_sources(right_action):
                    relation = _path_relation(left_source, right_source)
                    if relation == "left-inside-right":
                        dependencies.append({
                            "parent_component": right_action.get("component_type"),
                            "parent_source": str(right_source),
                            "child_component": left_action.get("component_type"),
                            "child_source": str(left_source),
                        })
                    elif relation == "right-inside-left":
                        dependencies.append({
                            "parent_component": left_action.get("component_type"),
                            "parent_source": str(left_source),
                            "child_component": right_action.get("component_type"),
                            "child_source": str(right_source),
                        })
    return dependencies


def _ambiguous_overlap_conflicts(actions: list[dict]) -> list[dict]:
    conflicts = []
    for left_index, left_action in enumerate(actions):
        for right_action in actions[left_index + 1:]:
            for left_source in _normalized_sources(left_action):
                for right_source in _normalized_sources(right_action):
                    if _path_relation(left_source, right_source) == "equal":
                        conflicts.append({
                            "left_component": left_action.get("component_type"),
                            "left_source": str(left_source),
                            "right_component": right_action.get("component_type"),
                            "right_source": str(right_source),
                            "reason": "components use the same target path",
                        })
    return conflicts


def _physical_execution_order(actions: list[dict]) -> list[dict]:
    logical_position = {
        action.get("component_type"): index
        for index, action in enumerate(actions)
    }
    return sorted(
        actions,
        key=lambda action: (
            _component_depth(action),
            logical_position.get(action.get("component_type"), 0),
        ),
    )


def _rollback_root_components(actions: list[dict]) -> list[str]:
    roots = []
    for action in actions:
        covered = False
        for other in actions:
            if other is action:
                continue
            for source in _normalized_sources(action):
                for other_source in _normalized_sources(other):
                    if _path_relation(source, other_source) == "left-inside-right":
                        covered = True
                        break
                if covered:
                    break
            if covered:
                break
        if not covered:
            roots.append(action.get("component_type"))
    return roots


def build_application_transaction_plan(package: Path, application: str) -> dict:
    package = package.resolve()
    ok, verification_messages = verify_backup(package)
    if not ok:
        raise RuntimeError(
            "Source backup verification failed: "
            + "; ".join(verification_messages)
        )
    if application not in APPLICATION_TARGETS:
        raise ValueError(f"Unsupported application transaction: {application}")

    preview = build_recovery_preview(package)
    ordered = _ordered_actions(preview, application)
    if not ordered:
        raise ValueError(
            f"Application is missing from recovery preview: {application}"
        )

    writable = [
        action
        for action in ordered
        if action.get("action") in WRITABLE_ACTIONS
        and action.get("rollback_required")
    ]
    dependencies = _nested_component_dependencies(writable)
    conflicts = _ambiguous_overlap_conflicts(writable)
    physical_order = _physical_execution_order(writable)

    return {
        "schema_version": 3,
        "application": application,
        "package": str(package),
        "package_valid": True,
        "verification_messages": verification_messages,
        "components": [
            {
                "component": action.get("component"),
                "component_type": action.get("component_type"),
                "action": action.get("action"),
                "reason": action.get("reason"),
                "sources": action.get("sources", []),
                "artifact_bytes": int(action.get("artifact_bytes", 0)),
                "rollback_required": bool(action.get("rollback_required")),
            }
            for action in ordered
        ],
        "writable_components": [
            action.get("component_type") for action in writable
        ],
        "physical_execution_order": [
            action.get("component_type") for action in physical_order
        ],
        "nested_dependencies": dependencies,
        "rollback_root_components": _rollback_root_components(writable),
        "overlap_conflicts": conflicts,
        "blocked": bool(conflicts),
        "block_reason": (
            "Ambiguous component targets require an explicit transaction strategy"
            if conflicts else None
        ),
    }


def _transaction_preview(
    preview: dict,
    application: str,
    writable_components: list[str],
) -> dict:
    selected_types = set(writable_components)
    result = json.loads(json.dumps(preview))
    selected_actions = []

    for action in result.get("actions", []):
        selected = (
            action.get("scope") == "application"
            and action.get("application") == application
            and action.get("component_type") in selected_types
            and action.get("action") in WRITABLE_ACTIONS
        )
        if selected:
            selected_actions.append(action)
        else:
            action["action"] = "skip"
            action["rollback_required"] = False

    result["summary"]["restore_components"] = len(selected_actions)
    result["summary"]["review_components"] = 0
    result["summary"]["blocked_components"] = 0
    restore_bytes = sum(
        int(action.get("artifact_bytes", 0))
        for action in selected_actions
    )
    result["summary"]["restore_bytes"] = restore_bytes
    result["summary"]["rollback_estimate_bytes"] = restore_bytes
    return result


def prepare_application_rollback(
    package: Path,
    application: str,
    rollback_destination: Path,
    rollback_name: str | None = None,
) -> dict:
    plan = build_application_transaction_plan(package, application)
    if plan["blocked"]:
        conflict_text = "; ".join(
            f"{item['left_component']}:{item['left_source']} overlaps "
            f"{item['right_component']}:{item['right_source']}"
            for item in plan["overlap_conflicts"]
        )
        raise RuntimeError(
            "Application transaction is blocked by overlapping targets: "
            + conflict_text
        )
    if not plan["writable_components"]:
        raise RuntimeError(
            f"Application has no writable recovery actions: {application}"
        )

    preview = build_recovery_preview(package.resolve())
    filtered = _transaction_preview(
        preview,
        application,
        plan["writable_components"],
    )
    rollback_package, rollback_result = create_rollback_package(
        filtered,
        rollback_destination,
        rollback_name,
        create_lock=False,
    )
    return {
        "plan": plan,
        "rollback_package": str(rollback_package),
        "rollback": rollback_result,
    }


def _confirm_application(application: str, components: list[str]) -> None:
    if not os.isatty(0):
        raise RuntimeError("Application recovery requires an interactive terminal")
    phrase = f"RESTORE {application.upper()} ALL"
    print("\nApplication transaction components:")
    for index, component in enumerate(components, start=1):
        print(f"  {index}. {component}")
    print("\nConfirmation 1/3: Type YES to continue.")
    if input("> ").strip() != "YES":
        raise RuntimeError("Recovery cancelled at confirmation 1")
    print("\nConfirmation 2/3: Type RESTORE to confirm system modification.")
    if input("> ").strip() != "RESTORE":
        raise RuntimeError("Recovery cancelled at confirmation 2")
    print(f"\nConfirmation 3/3: Type {phrase} exactly.")
    if input("> ").strip() != phrase:
        raise RuntimeError("Recovery cancelled at confirmation 3")


def _daemon_reload() -> None:
    result = _run(["systemctl", "daemon-reload"])
    if result.returncode != 0:
        raise RuntimeError(
            "systemctl daemon-reload failed: "
            + (result.stderr.strip() or result.stdout.strip())
        )


def execute_application_transaction(
    package: Path,
    application: str,
    rollback_destination: Path,
    rollback_name: str | None = None,
    interactive: bool = True,
    manage_services: bool = True,
) -> dict:
    package = package.resolve()
    if read_recovery_lock() is not None:
        raise RuntimeError(
            "Recovery lock already exists. Run psb recovery-status and "
            "psb recovery-abort before starting a new transaction."
        )

    prepared = prepare_application_rollback(
        package,
        application,
        rollback_destination,
        rollback_name,
    )
    plan = prepared["plan"]
    component_types = plan["writable_components"]
    if interactive:
        _confirm_application(application, component_types)

    preview = build_recovery_preview(package)
    ordered_actions = [
        action
        for action in _ordered_actions(preview, application)
        if action.get("component_type") in component_types
        and action.get("action") in WRITABLE_ACTIONS
    ]

    services = APPLICATION_SERVICES[application]
    active_services = _active_services(services) if manage_services else []
    operation_id = str(uuid.uuid4())
    started_monotonic = time.monotonic()
    started_at = dt.datetime.now(dt.timezone.utc).isoformat()
    stage_directories = []
    staged = []
    installed = []
    needs_daemon_reload = any(
        (application, component) in DAEMON_RELOAD_COMPONENTS
        for component in component_types
    )

    lock = {
        "schema_version": 12,
        "state": "preparing",
        "execution_enabled": False,
        "operation_id": operation_id,
        "application": application,
        "components": component_types,
        "completed_components": [],
        "source_backup": str(package),
        "rollback_package": prepared["rollback_package"],
        "rollback_id": prepared["rollback"].get("rollback_id"),
        "rollback_verified": True,
        "started_at": started_at,
        "pid": os.getpid(),
        "services_active_before": active_services,
    }
    _write_lock(lock)

    try:
        for index, action in enumerate(ordered_actions, start=1):
            component_type = action["component_type"]
            target = APPLICATION_TARGETS[application][component_type]
            sources = [Path(item) for item in action.get("sources", [])]
            if sources != [target]:
                raise RuntimeError(
                    f"Unexpected source paths for {application}/{component_type}: "
                    f"{sources}"
                )
            if not target.exists():
                raise RuntimeError(f"Recovery target does not exist: {target}")

            member, artifact_data = _find_artifact(package, action)
            expected_signature, _, _ = _tar_signature(artifact_data)
            if expected_signature is None:
                raise RuntimeError(
                    f"Unable to calculate signature for {application}/{component_type}"
                )

            component_stage = Path(
                tempfile.mkdtemp(
                    prefix=f".psb-{application}-{component_type}-stage-",
                    dir=target.parent,
                )
            )
            stage_directories.append(component_stage)
            restored = _safe_extract_tar(
                artifact_data,
                component_stage,
                target,
            )
            staged.append({
                "component": component_type,
                "target": target,
                "restored": restored,
                "expected_signature": expected_signature,
                "artifact_member": member,
            })

        if manage_services and active_services:
            _stop_services(active_services)

        lock.update({"state": "executing", "execution_enabled": True})
        _write_lock(lock)

        for item in staged:
            component_type = item["component"]
            target = item["target"]
            old_path = target.parent / (
                f".psb-{application}-{component_type}-old-{operation_id}"
            )
            target.rename(old_path)
            item["restored"].rename(target)
            installed.append({
                "component": component_type,
                "target": target,
                "old_path": old_path,
            })

            installed_signature = _directory_signature_as_source(target, target)
            if installed_signature != item["expected_signature"]:
                raise RuntimeError(
                    f"Installed {application}/{component_type} checksum "
                    "does not match backup artifact"
                )

            lock["completed_components"].append(component_type)
            _write_lock(lock)

        if needs_daemon_reload:
            _daemon_reload()
        if manage_services and active_services:
            _start_services(list(reversed(active_services)))

        for item in installed:
            shutil.rmtree(item["old_path"])

        duration = round(time.monotonic() - started_monotonic, 3)
        active_after = _active_services(services) if manage_services else []
        lock.update({
            "state": "completed",
            "execution_enabled": False,
            "completed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "services_active_after": active_after,
            "duration_seconds": duration,
        })
        _write_lock(lock)
        return {
            "status": "completed",
            "operation_id": operation_id,
            "application": application,
            "components": component_types,
            "rollback_package": prepared["rollback_package"],
            "rollback_verified": True,
            "services_active_before": active_services,
            "services_active_after": active_after,
            "duration_seconds": duration,
            "lock_path": str(RECOVERY_LOCK),
        }
    except Exception as exc:
        rollback_error = None
        try:
            if manage_services:
                for service in _active_services(services):
                    _run(["systemctl", "stop", service])

            for item in reversed(installed):
                if item["target"].exists():
                    shutil.rmtree(item["target"])
                if item["old_path"].exists():
                    item["old_path"].rename(item["target"])

            if needs_daemon_reload:
                _daemon_reload()
            if manage_services and active_services:
                _start_services(list(reversed(active_services)))
        except Exception as rollback_exc:
            rollback_error = str(rollback_exc)

        lock.update({
            "state": (
                "rolled-back" if rollback_error is None else "rollback-failed"
            ),
            "execution_enabled": False,
            "failed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "error": str(exc),
            "rollback_error": rollback_error,
            "duration_seconds": round(
                time.monotonic() - started_monotonic,
                3,
            ),
        })
        _write_lock(lock)

        if rollback_error:
            raise RuntimeError(
                f"Application recovery failed: {exc}; automatic rollback "
                f"also failed: {rollback_error}"
            ) from exc
        raise RuntimeError(
            f"Application recovery failed and previous state was restored: {exc}"
        ) from exc
    finally:
        for stage_directory in stage_directories:
            shutil.rmtree(stage_directory, ignore_errors=True)
