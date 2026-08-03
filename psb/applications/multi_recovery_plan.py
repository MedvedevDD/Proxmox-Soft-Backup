from pathlib import Path

from .manifest import load_manifests
from .orchestrator import build_application_transaction_plan


SUPPORTED_TRANSACTION_APPLICATIONS = {
    "grafana",
    "influxdb",
    "telegraf",
    "nut",
}


def _manifest_map() -> dict[str, dict]:
    return {
        manifest["id"]: manifest
        for manifest in load_manifests()
    }


def _expand_dependencies(
    selected: list[str],
    manifests: dict[str, dict],
) -> list[str]:
    expanded = []
    visiting = set()
    visited = set()

    def visit(application: str) -> None:
        if application in visited:
            return
        if application in visiting:
            raise RuntimeError(
                "Application dependency graph contains a cycle"
            )
        if application not in manifests:
            raise ValueError(
                f"Unknown application: {application}"
            )
        if application not in SUPPORTED_TRANSACTION_APPLICATIONS:
            raise ValueError(
                f"Unsupported transaction application: {application}"
            )

        visiting.add(application)
        for dependency in manifests[application].get(
            "dependencies",
            [],
        ):
            visit(dependency)
        visiting.remove(application)
        visited.add(application)
        expanded.append(application)

    for application in selected:
        visit(application)

    return expanded


def supported_transaction_applications() -> list[str]:
    manifests = _manifest_map()
    return [
        application
        for application in manifests
        if application in SUPPORTED_TRANSACTION_APPLICATIONS
    ]


def build_multi_application_plan(
    package: Path,
    applications: list[str] | None = None,
) -> dict:
    manifests = _manifest_map()
    selected = (
        applications
        if applications is not None
        else supported_transaction_applications()
    )

    if not selected:
        raise ValueError("At least one application is required")
    if len(selected) != len(set(selected)):
        raise ValueError(
            "Duplicate application in recovery selection"
        )

    execution_order = _expand_dependencies(
        selected,
        manifests,
    )
    plans = [
        build_application_transaction_plan(
            package,
            application,
        )
        for application in execution_order
    ]
    blocked = [
        plan["application"]
        for plan in plans
        if plan["blocked"]
    ]

    return {
        "schema_version": 1,
        "package": str(package.resolve()),
        "requested_applications": list(selected),
        "included_applications": execution_order,
        "physical_application_order": execution_order,
        "application_plans": plans,
        "blocked": bool(blocked),
        "blocked_applications": blocked,
        "writable_applications": [
            plan["application"]
            for plan in plans
            if plan["writable_components"]
        ],
    }
