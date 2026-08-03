import datetime as dt
import json
import os
import shutil
import tempfile
import time
import uuid
from pathlib import Path

from .multi_recovery_plan import build_multi_application_plan
from .orchestrator import (
    APPLICATION_SERVICES,
    APPLICATION_TARGETS,
    DAEMON_RELOAD_COMPONENTS,
    WRITABLE_ACTIONS,
    _component_staging_parent,
    _daemon_reload,
    _ordered_actions,
)
from ..modules.compare import _tar_signature
from ..modules.execution import (
    RECOVERY_LOCK,
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


def _multi_transaction_preview(
    preview: dict,
    application_plans: list[dict],
) -> dict:
    selected = {
        (plan["application"], component)
        for plan in application_plans
        for component in plan["rollback_root_components"]
    }
    result = json.loads(json.dumps(preview))
    selected_actions = []

    for action in result.get("actions", []):
        key = (
            action.get("application"),
            action.get("component_type"),
        )
        use_action = (
            action.get("scope") == "application"
            and key in selected
            and action.get("action") in WRITABLE_ACTIONS
        )
        if use_action:
            selected_actions.append(action)
        else:
            action["action"] = "skip"
            action["rollback_required"] = False

    restore_bytes = sum(
        int(action.get("artifact_bytes", 0))
        for action in selected_actions
    )
    result["summary"]["restore_components"] = len(selected_actions)
    result["summary"]["review_components"] = 0
    result["summary"]["blocked_components"] = 0
    result["summary"]["restore_bytes"] = restore_bytes
    result["summary"]["rollback_estimate_bytes"] = restore_bytes
    return result


def prepare_multi_application_rollback(
    package: Path,
    applications: list[str] | None,
    rollback_destination: Path,
    rollback_name: str | None = None,
) -> dict:
    package = package.resolve()
    plan = build_multi_application_plan(package, applications)

    if plan["blocked"]:
        raise RuntimeError(
            "Multi-application recovery is blocked for: "
            + ", ".join(plan["blocked_applications"])
        )
    if not plan["writable_applications"]:
        raise RuntimeError(
            "Multi-application recovery has no writable actions"
        )

    preview = build_recovery_preview(package)
    filtered = _multi_transaction_preview(
        preview,
        plan["application_plans"],
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


def _confirm_multi_application(
    application_order: list[str],
    component_order: list[dict],
) -> None:
    if not os.isatty(0):
        raise RuntimeError(
            "Multi-application recovery requires an interactive terminal"
        )

    print("\nMulti-application transaction order:")
    for index, application in enumerate(application_order, start=1):
        print(f"  {index}. {application}")

    print("\nComponent execution order:")
    for index, item in enumerate(component_order, start=1):
        print(
            f"  {index}. {item['application']}/"
            f"{item['component']}"
        )

    print("\nConfirmation 1/3: Type YES to continue.")
    if input("> ").strip() != "YES":
        raise RuntimeError("Recovery cancelled at confirmation 1")

    print("\nConfirmation 2/3: Type RESTORE to confirm system modification.")
    if input("> ").strip() != "RESTORE":
        raise RuntimeError("Recovery cancelled at confirmation 2")

    phrase = "RESTORE MULTI APPLICATIONS"
    print(f"\nConfirmation 3/3: Type {phrase} exactly.")
    if input("> ").strip() != phrase:
        raise RuntimeError("Recovery cancelled at confirmation 3")


def _ordered_writable_actions(
    package: Path,
    plan: dict,
) -> list[dict]:
    preview = build_recovery_preview(package)
    plans_by_application = {
        item["application"]: item
        for item in plan["application_plans"]
    }
    result = []

    for application in plan["physical_application_order"]:
        application_plan = plans_by_application[application]
        writable = set(application_plan["writable_components"])
        actions_by_type = {
            action.get("component_type"): action
            for action in _ordered_actions(preview, application)
            if action.get("component_type") in writable
            and action.get("action") in WRITABLE_ACTIONS
        }

        for component in application_plan["physical_execution_order"]:
            result.append({
                "application": application,
                "component": component,
                "action": actions_by_type[component],
            })

    return result


def _active_services_by_application(
    application_order: list[str],
) -> dict[str, list[str]]:
    return {
        application: _active_services(
            APPLICATION_SERVICES[application]
        )
        for application in application_order
    }


def _stop_multi_application_services(
    application_order: list[str],
    active_services: dict[str, list[str]],
) -> None:
    for application in reversed(application_order):
        services = active_services[application]
        if services:
            _stop_services(services)


def _start_multi_application_services(
    application_order: list[str],
    active_services: dict[str, list[str]],
) -> None:
    for application in application_order:
        services = active_services[application]
        if services:
            _start_services(list(reversed(services)))


def execute_multi_application_transaction(
    package: Path,
    applications: list[str] | None,
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

    prepared = prepare_multi_application_rollback(
        package,
        applications,
        rollback_destination,
        rollback_name,
    )
    plan = prepared["plan"]
    application_order = plan["physical_application_order"]
    writable_actions = _ordered_writable_actions(package, plan)
    component_order = [
        {
            "application": item["application"],
            "component": item["component"],
        }
        for item in writable_actions
    ]

    if interactive:
        _confirm_multi_application(
            application_order,
            component_order,
        )

    transaction_targets = [
        APPLICATION_TARGETS[item["application"]][item["component"]]
        for item in writable_actions
    ]
    active_services = (
        _active_services_by_application(application_order)
        if manage_services
        else {
            application: []
            for application in application_order
        }
    )

    operation_id = str(uuid.uuid4())
    started_monotonic = time.monotonic()
    started_at = dt.datetime.now(dt.timezone.utc).isoformat()
    stage_directories = []
    staged = []
    installed = []

    needs_daemon_reload = any(
        (
            item["application"],
            item["component"],
        ) in DAEMON_RELOAD_COMPONENTS
        for item in writable_actions
    )

    completed_components = {
        application: []
        for application in application_order
    }
    completed_applications = []

    lock = {
        "schema_version": 13,
        "state": "preparing",
        "execution_enabled": False,
        "operation_id": operation_id,
        "applications": application_order,
        "requested_applications": plan["requested_applications"],
        "writable_applications": plan["writable_applications"],
        "physical_application_order": application_order,
        "component_execution_order": component_order,
        "completed_applications": completed_applications,
        "completed_components": completed_components,
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
        for index, item in enumerate(writable_actions, start=1):
            application = item["application"]
            component = item["component"]
            action = item["action"]
            target = APPLICATION_TARGETS[application][component]
            sources = [
                Path(source)
                for source in action.get("sources", [])
            ]

            if sources != [target]:
                raise RuntimeError(
                    f"Unexpected source paths for "
                    f"{application}/{component}: {sources}"
                )
            if not target.exists():
                raise RuntimeError(
                    f"Recovery target does not exist: {target}"
                )

            member, artifact_data = _find_artifact(
                package,
                action,
            )
            expected_signature, _, _ = _tar_signature(
                artifact_data
            )
            if expected_signature is None:
                raise RuntimeError(
                    f"Unable to calculate signature for "
                    f"{application}/{component}"
                )

            component_stage = Path(
                tempfile.mkdtemp(
                    prefix=(
                        f".psb-{application}-{component}-stage-"
                    ),
                    dir=_component_staging_parent(
                        target,
                        transaction_targets,
                    ),
                )
            )
            stage_directories.append(component_stage)
            restored = _safe_extract_tar(
                artifact_data,
                component_stage,
                target,
            )
            staged.append({
                "application": application,
                "component": component,
                "target": target,
                "restored": restored,
                "expected_signature": expected_signature,
                "artifact_member": member,
                "index": index,
            })

        if manage_services:
            _stop_multi_application_services(
                application_order,
                active_services,
            )

        lock.update({
            "state": "executing",
            "execution_enabled": True,
        })
        _write_lock(lock)

        application_remaining = {
            application: sum(
                1
                for item in staged
                if item["application"] == application
            )
            for application in application_order
        }

        for item in staged:
            application = item["application"]
            component = item["component"]
            target = item["target"]
            old_path = target.parent / (
                f".psb-{application}-{component}-old-"
                f"{operation_id}"
            )

            target.rename(old_path)
            item["restored"].rename(target)
            installed.append({
                "application": application,
                "component": component,
                "target": target,
                "old_path": old_path,
            })

            installed_signature = _directory_signature_as_source(
                target,
                target,
            )
            if installed_signature != item["expected_signature"]:
                raise RuntimeError(
                    f"Installed {application}/{component} checksum "
                    "does not match backup artifact"
                )

            completed_components[application].append(component)
            application_remaining[application] -= 1
            if (
                application_remaining[application] == 0
                and application not in completed_applications
            ):
                completed_applications.append(application)

            _write_lock(lock)

        if needs_daemon_reload:
            _daemon_reload()

        if manage_services:
            _start_multi_application_services(
                application_order,
                active_services,
            )

        for item in installed:
            shutil.rmtree(item["old_path"])

        duration = round(
            time.monotonic() - started_monotonic,
            3,
        )
        active_after = (
            _active_services_by_application(application_order)
            if manage_services
            else {
                application: []
                for application in application_order
            }
        )

        lock.update({
            "state": "completed",
            "execution_enabled": False,
            "completed_at": dt.datetime.now(
                dt.timezone.utc
            ).isoformat(),
            "services_active_after": active_after,
            "duration_seconds": duration,
        })
        _write_lock(lock)

        return {
            "status": "completed",
            "operation_id": operation_id,
            "applications": application_order,
            "requested_applications": plan["requested_applications"],
            "writable_applications": plan["writable_applications"],
            "physical_application_order": application_order,
            "component_execution_order": component_order,
            "completed_applications": completed_applications,
            "completed_components": completed_components,
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
                for application in reversed(application_order):
                    for service in _active_services(
                        APPLICATION_SERVICES[application]
                    ):
                        _run(["systemctl", "stop", service])

            for item in reversed(installed):
                if item["target"].exists():
                    shutil.rmtree(item["target"])
                if item["old_path"].exists():
                    item["old_path"].rename(item["target"])

            if needs_daemon_reload:
                _daemon_reload()

            if manage_services:
                _start_multi_application_services(
                    application_order,
                    active_services,
                )
        except Exception as rollback_exc:
            rollback_error = str(rollback_exc)

        lock.update({
            "state": (
                "rolled-back"
                if rollback_error is None
                else "rollback-failed"
            ),
            "execution_enabled": False,
            "failed_at": dt.datetime.now(
                dt.timezone.utc
            ).isoformat(),
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
                f"Multi-application recovery failed: {exc}; "
                f"automatic rollback also failed: "
                f"{rollback_error}"
            ) from exc

        raise RuntimeError(
            "Multi-application recovery failed and previous "
            f"state was restored: {exc}"
        ) from exc
    finally:
        for stage_directory in stage_directories:
            shutil.rmtree(
                stage_directory,
                ignore_errors=True,
            )
