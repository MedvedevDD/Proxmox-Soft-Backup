import json
import zipfile
from pathlib import Path

from .compare import compare_targets
from .package import read_json_member
from .verify import verify_backup


def _artifact_index(package: Path) -> dict[tuple[str, str, str], dict]:
    manifest = read_json_member(package, "manifest.json")
    index: dict[tuple[str, str, str], dict] = {}
    for app in manifest.get("applications", []):
        app_id = app.get("name", "")
        for component in app.get("components", []):
            artifacts = component.get("artifacts", [])
            index[("application", app_id, component.get("id", ""))] = {
                "artifacts": artifacts,
                "size": sum(int(item.get("size", 0)) for item in artifacts),
                "sources": component.get("sources", []),
                "type": component.get("type", "data"),
            }
    for component in manifest.get("host", {}).get("components", []):
        artifacts = component.get("artifacts", [])
        index[("host", "host", component.get("id", ""))] = {
            "artifacts": artifacts,
            "size": sum(int(item.get("size", 0)) for item in artifacts),
            "sources": component.get("sources", []),
            "type": "host-configuration",
        }
    return index


def build_recovery_preview(package: Path) -> dict:
    package = package.resolve()
    ok, verification_messages = verify_backup(package)
    if not ok:
        return {
            "schema_version": 1,
            "package": str(package),
            "package_valid": False,
            "verification_messages": verification_messages,
            "preview_only": True,
            "destructive_actions_enabled": False,
            "blocked": True,
            "block_reason": "Package verification failed",
        }

    comparison = compare_targets(package)
    artifact_index = _artifact_index(package)
    actions: list[dict] = []

    for app in comparison.get("applications", []):
        for component in app.get("components", []):
            status = component.get("status")
            action = "restore" if status in {"changed", "removed"} and component.get("weight", 0) > 0 else "skip"
            reason = component.get("reason", status)
            key = ("application", app.get("id", ""), component.get("id", ""))
            artifact = artifact_index.get(key, {})
            actions.append({
                "scope": "application",
                "application": app.get("id"),
                "display_name": app.get("display_name"),
                "component": component.get("id"),
                "component_type": component.get("type"),
                "status": status,
                "action": action,
                "reason": reason,
                "risk": "application",
                "weight": component.get("weight", 0),
                "artifact_bytes": artifact.get("size", 0),
                "sources": artifact.get("sources", component.get("sources_left", [])),
                "rollback_required": action == "restore",
            })

    for component in comparison.get("host", []):
        status = component.get("status")
        risk = component.get("risk", "host-sensitive")
        if status in {"changed", "removed"}:
            action = "blocked" if risk == "dangerous" else "review"
        else:
            action = "skip"
        key = ("host", "host", component.get("id", ""))
        artifact = artifact_index.get(key, {})
        actions.append({
            "scope": "host",
            "application": None,
            "display_name": component.get("display_name"),
            "component": component.get("id"),
            "component_type": "host-configuration",
            "status": status,
            "action": action,
            "reason": component.get("reason", status),
            "risk": risk,
            "weight": component.get("weight", 0),
            "artifact_bytes": artifact.get("size", 0),
            "sources": artifact.get("sources", component.get("sources_left", [])),
            "rollback_required": action in {"review", "restore"},
        })

    restore_actions = [item for item in actions if item["action"] == "restore"]
    review_actions = [item for item in actions if item["action"] == "review"]
    blocked_actions = [item for item in actions if item["action"] == "blocked"]
    skipped_actions = [item for item in actions if item["action"] == "skip"]
    rollback_bytes = sum(item["artifact_bytes"] for item in restore_actions + review_actions)
    restore_bytes = sum(item["artifact_bytes"] for item in restore_actions)

    return {
        "schema_version": 1,
        "package": str(package),
        "package_valid": True,
        "verification_messages": verification_messages,
        "preview_only": True,
        "destructive_actions_enabled": False,
        "comparison": comparison,
        "summary": {
            "restore_components": len(restore_actions),
            "review_components": len(review_actions),
            "blocked_components": len(blocked_actions),
            "skipped_components": len(skipped_actions),
            "restore_bytes": restore_bytes,
            "rollback_estimate_bytes": rollback_bytes,
            "recovery_required": bool(restore_actions or review_actions or blocked_actions),
            "recovery_impact": comparison.get("summary", {}).get("recovery_impact", "unknown"),
            "drift_score": comparison.get("summary", {}).get("drift_score", 0),
            "compare_confidence": comparison.get("summary", {}).get("compare_confidence", 0),
        },
        "actions": actions,
        "safety": {
            "current_state_backup_required": True,
            "rollback_required": True,
            "confirmations_required_for_future_recovery": 3,
            "identical_components_will_be_skipped": True,
            "dangerous_host_components_blocked": True,
        },
    }


def write_recovery_plan(preview: dict, output: Path) -> Path:
    target = output.resolve()
    target.write_text(json.dumps(preview, indent=2, sort_keys=True), encoding="utf-8")
    return target


def print_recovery_preview(preview: dict) -> None:
    print("\nPSB Recovery Preview")
    print("=" * 104)
    print(f"Package: {preview.get('package')}")
    if not preview.get("package_valid"):
        print("Package verification: FAILED")
        print(f"Recovery blocked: {preview.get('block_reason')}")
        print("\nPreview only: no files were changed.")
        return

    summary = preview["summary"]
    print("Package verification: PASS")
    print(f"Drift score: {summary['drift_score']}%   Impact: {summary['recovery_impact'].upper()}   Confidence: {summary['compare_confidence']}%")
    print(f"Restore: {summary['restore_components']}   Review: {summary['review_components']}   Blocked: {summary['blocked_components']}   Skip: {summary['skipped_components']}")
    print(f"Estimated restore data: {summary['restore_bytes']} bytes")
    print(f"Estimated rollback data: {summary['rollback_estimate_bytes']} bytes")

    print("\nPlanned application actions:")
    app_actions = [item for item in preview["actions"] if item["scope"] == "application" and item["action"] != "skip"]
    if not app_actions:
        print("  Nothing to restore.")
    for item in app_actions:
        print(f"  {item['display_name']} / {item['component_type']}: {item['action'].upper()} ({item['reason']})")

    print("\nHost configuration actions:")
    host_actions = [item for item in preview["actions"] if item["scope"] == "host" and item["action"] != "skip"]
    if not host_actions:
        print("  Nothing to restore or review.")
    for item in host_actions:
        print(f"  {item['display_name']}: {item['action'].upper()} [{item['risk']}] ({item['reason']})")

    if not summary["recovery_required"]:
        print("\nNo recovery is required: all backed-up components are identical.")
    else:
        print("\nA recovery plan was generated. Safe execution is available only for an explicitly selected supported component.")
    print("Preview only: no files were changed.")
