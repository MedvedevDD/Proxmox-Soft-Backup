import json
from pathlib import Path

from .recovery_plan import application_recovery_order
from ..modules.recovery import build_recovery_preview
from ..modules.rollback import create_rollback_package
from ..modules.verify import verify_backup


WRITABLE_ACTIONS = {"restore", "review"}


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

    result = []
    for component_type in application_recovery_order(application):
        action = by_type.get(component_type)
        if action is not None:
            result.append(action)
    return result


def _normalized_sources(action: dict) -> list[Path]:
    return [
        Path(source).resolve()
        for source in action.get("sources", [])
    ]


def _paths_overlap(left: Path, right: Path) -> bool:
    if left == right:
        return True
    try:
        left.relative_to(right)
        return True
    except ValueError:
        pass
    try:
        right.relative_to(left)
        return True
    except ValueError:
        return False


def _overlap_conflicts(actions: list[dict]) -> list[dict]:
    conflicts = []
    for left_index, left_action in enumerate(actions):
        for right_action in actions[left_index + 1:]:
            for left_source in _normalized_sources(left_action):
                for right_source in _normalized_sources(right_action):
                    if _paths_overlap(left_source, right_source):
                        conflicts.append({
                            "left_component": left_action.get("component_type"),
                            "left_source": str(left_source),
                            "right_component": right_action.get("component_type"),
                            "right_source": str(right_source),
                        })
    return conflicts


def build_application_transaction_plan(
    package: Path,
    application: str,
) -> dict:
    package = package.resolve()

    ok, verification_messages = verify_backup(package)
    if not ok:
        raise RuntimeError(
            "Source backup verification failed: "
            + "; ".join(verification_messages)
        )

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
    conflicts = _overlap_conflicts(writable)

    components = []
    for action in ordered:
        components.append({
            "component": action.get("component"),
            "component_type": action.get("component_type"),
            "action": action.get("action"),
            "reason": action.get("reason"),
            "sources": action.get("sources", []),
            "artifact_bytes": int(action.get("artifact_bytes", 0)),
            "rollback_required": bool(action.get("rollback_required")),
        })

    return {
        "schema_version": 1,
        "application": application,
        "package": str(package),
        "package_valid": True,
        "verification_messages": verification_messages,
        "components": components,
        "writable_components": [
            action.get("component_type")
            for action in writable
        ],
        "overlap_conflicts": conflicts,
        "blocked": bool(conflicts),
        "block_reason": (
            "Overlapping component targets require an explicit transaction strategy"
            if conflicts
            else None
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
    result["summary"]["restore_bytes"] = sum(
        int(action.get("artifact_bytes", 0))
        for action in selected_actions
    )
    result["summary"]["rollback_estimate_bytes"] = result["summary"][
        "restore_bytes"
    ]
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
            (
                f"{item['left_component']}:{item['left_source']} overlaps "
                f"{item['right_component']}:{item['right_source']}"
            )
            for item in plan["overlap_conflicts"]
        )
        raise RuntimeError(
            "Application transaction is blocked by overlapping targets: "
            + conflict_text
        )

    writable_components = plan["writable_components"]
    if not writable_components:
        raise RuntimeError(
            f"Application has no writable recovery actions: {application}"
        )

    preview = build_recovery_preview(package.resolve())
    filtered = _transaction_preview(
        preview,
        application,
        writable_components,
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
