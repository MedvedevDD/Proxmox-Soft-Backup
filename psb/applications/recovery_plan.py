from .manifest import load_manifests


def application_recovery_order(application: str) -> list[str]:
    manifests = load_manifests()
    manifest = next(
        (item for item in manifests if item.get("id") == application),
        None,
    )
    if manifest is None:
        raise ValueError(f"Unknown application: {application}")

    recovery_order = manifest.get("recovery_order")
    if not recovery_order:
        raise ValueError(
            f"Application does not define a recovery order: {application}"
        )
    return list(recovery_order)


def build_application_recovery_plan(
    application: str,
    available_components: list[str],
) -> dict:
    ordered_components = application_recovery_order(application)
    available = set(available_components)

    selected = [
        component
        for component in ordered_components
        if component in available
    ]
    missing = [
        component
        for component in ordered_components
        if component not in available
    ]

    return {
        "application": application,
        "components": selected,
        "missing_components": missing,
        "complete": not missing,
    }
