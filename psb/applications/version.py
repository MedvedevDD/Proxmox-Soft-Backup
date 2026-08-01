import re
from pathlib import Path
from psb.modules.common import command_exists, run


def _first_version(text: str) -> str:
    if not text:
        return "unknown"
    match = re.search(r"(?<!\d)(\d+(?:\.\d+){1,3}(?:[-+~._a-zA-Z0-9]*)?)", text)
    return match.group(1) if match else "unknown"


def package_version(packages: list[str]) -> tuple[str, str]:
    if not command_exists("dpkg-query"):
        return "unknown", ""
    for package in packages:
        result = run(["dpkg-query", "-W", "-f=${Version}", package])
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip(), package
    return "unknown", ""


def command_version(commands: list[list[str]]) -> str:
    for command in commands:
        executable = command[0]
        if executable.startswith("/"):
            if not Path(executable).exists():
                continue
        elif not command_exists(executable):
            continue
        result = run(command)
        text = (result.stdout + "\n" + result.stderr).strip()
        version = _first_version(text)
        if version != "unknown":
            return version
    return "unknown"


def major_version(version: str) -> int | None:
    match = re.match(r"^(\d+)", version or "")
    return int(match.group(1)) if match else None


def detect_version(manifest: dict, installed_packages: list[str]) -> dict:
    spec = manifest.get("version_detection", {})
    version = "unknown"
    source = "none"

    for item in spec.get("path_patterns", []):
        import glob
        pattern=item.get("glob","")
        regex=item.get("regex","")
        for value in sorted(glob.glob(pattern), reverse=True):
            match=re.search(regex, value)
            if match:
                version=match.group(1)
                source="path"
                break
        if version != "unknown": break

    commands = spec.get("commands", [])
    if commands and version == "unknown":
        version = command_version(commands)
        if version != "unknown":
            source = "command"

    package_name = ""
    if version == "unknown":
        version, package_name = package_version(installed_packages or manifest.get("detection", {}).get("packages", []))
        if version != "unknown":
            source = f"package:{package_name}"

    major = major_version(version)
    family = "default"
    families = spec.get("families", [])
    for item in families:
        min_major = item.get("min_major")
        max_major = item.get("max_major")
        if major is None:
            continue
        if min_major is not None and major < int(min_major):
            continue
        if max_major is not None and major > int(max_major):
            continue
        family = item.get("id", "default")
        break

    return {
        "version": version,
        "version_major": major,
        "version_family": family,
        "version_source": source,
    }


def component_applies(component: dict, version_info: dict) -> bool:
    families = component.get("version_families")
    if not families:
        return True
    return version_info.get("version_family") in families
