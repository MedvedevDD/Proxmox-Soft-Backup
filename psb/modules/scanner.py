import os
import platform
import re
import shlex
import socket
from pathlib import Path

from .common import command_exists, read_text, run
from .profiles import load_profiles
from psb.applications import detect_applications

SYSTEM_UNIT_PREFIXES = (
    "apt-", "ceph", "corosync", "cron", "dbus", "getty", "lvm", "lxc", "pve", "proxmox",
    "qemu", "rpc", "ssh", "systemd", "zfs", "zed", "networking", "remote-fs", "sockets",
)
UNIT_SUFFIXES = (".service", ".timer", ".mount", ".path", ".socket", ".target")
CONFIG_ARG_NAMES = {"-c", "--config", "--config-file", "--config.path", "--config.file"}


def package_installed(package: str) -> bool:
    if not command_exists("dpkg-query"):
        return False
    result = run(["dpkg-query", "-W", "-f=${Status}", package])
    return result.returncode == 0 and "install ok installed" in result.stdout


def package_for_path(path: str) -> str:
    if not path or not command_exists("dpkg-query"):
        return ""
    result = run(["dpkg-query", "-S", path])
    if result.returncode != 0 or ":" not in result.stdout:
        return ""
    return result.stdout.split(":", 1)[0].strip()


def unit_fragment_path(unit: str) -> Path | None:
    if command_exists("systemctl"):
        result = run(["systemctl", "show", unit, "--property=FragmentPath", "--value"])
        value = result.stdout.strip()
        if value:
            return Path(value)
    for root in (Path("/etc/systemd/system"), Path("/lib/systemd/system"), Path("/usr/lib/systemd/system")):
        candidate = root / unit
        if candidate.exists():
            return candidate
    return None


def unit_exists(unit: str) -> bool:
    return unit_fragment_path(unit) is not None


def list_service_units() -> list[str]:
    units = set()
    if command_exists("systemctl"):
        result = run(["systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager"])
        for line in result.stdout.splitlines():
            name = line.split(maxsplit=1)[0].strip() if line.strip() else ""
            if name.endswith(".service") and "@" not in name:
                units.add(name)
    for root in (Path("/etc/systemd/system"), Path("/lib/systemd/system"), Path("/usr/lib/systemd/system")):
        if root.exists():
            for path in root.glob("*.service"):
                if "@" not in path.name:
                    units.add(path.name)
    return sorted(units)


def systemctl_property(unit: str, prop: str) -> str:
    if not command_exists("systemctl"):
        return ""
    return run(["systemctl", "show", unit, f"--property={prop}", "--value"]).stdout.strip()


def parse_execstart(raw: str) -> tuple[str, list[str]]:
    if not raw:
        return "", []
    match = re.search(r"path=([^ ;}]+)", raw)
    if match:
        binary = match.group(1)
        argv_match = re.search(r"argv\[\]=([^;}]*)", raw)
        argv = shlex.split(argv_match.group(1).strip()) if argv_match else []
        return binary, argv
    try:
        argv = shlex.split(raw)
    except ValueError:
        argv = raw.split()
    binary = argv[0].lstrip("-+!:@") if argv else ""
    return binary, argv


def split_paths(value: str) -> list[str]:
    paths = []
    for token in shlex.split(value or ""):
        token = token.lstrip("-+")
        if token.startswith("/"):
            paths.append(token)
    return paths


def infer_config_paths(argv: list[str]) -> list[str]:
    found = []
    for index, token in enumerate(argv):
        if token in CONFIG_ARG_NAMES and index + 1 < len(argv):
            value = argv[index + 1]
            if value.startswith("/"):
                found.append(value)
        elif "=" in token:
            key, value = token.split("=", 1)
            if key in CONFIG_ARG_NAMES and value.startswith("/"):
                found.append(value)
        elif token.startswith("/") and token.endswith((".conf", ".ini", ".toml", ".yaml", ".yml", ".json")):
            found.append(token)
    return found


def analyze_service(unit: str) -> dict:
    fragment = unit_fragment_path(unit)
    raw_exec = systemctl_property(unit, "ExecStart")
    binary, argv = parse_execstart(raw_exec)
    package = package_for_path(binary)
    environment_files = split_paths(systemctl_property(unit, "EnvironmentFiles"))
    read_write_paths = split_paths(systemctl_property(unit, "ReadWritePaths"))
    working_directory = systemctl_property(unit, "WorkingDirectory")
    state_directory = systemctl_property(unit, "StateDirectory")
    config_paths = infer_config_paths(argv)
    dropins = []
    for root in (Path("/etc/systemd/system"), Path("/lib/systemd/system"), Path("/usr/lib/systemd/system")):
        directory = root / f"{unit}.d"
        if directory.exists():
            dropins.extend(str(p) for p in sorted(directory.glob("*.conf")))
    candidate_paths = []
    for value in environment_files + read_write_paths + config_paths:
        if value not in candidate_paths:
            candidate_paths.append(value)
    if working_directory.startswith("/"):
        candidate_paths.append(working_directory)
    if state_directory:
        for item in state_directory.split():
            candidate_paths.append(item if item.startswith("/") else f"/var/lib/{item}")
    if fragment:
        candidate_paths.append(str(fragment))
    candidate_paths.extend(dropins)
    candidate_paths = list(dict.fromkeys(candidate_paths))
    is_custom = bool(fragment and str(fragment).startswith("/etc/systemd/system"))
    is_third_party_package = bool(package and not package.startswith(("proxmox", "pve-", "libpve", "systemd", "debian")))
    is_interesting = is_custom or is_third_party_package or any(Path(p).exists() for p in candidate_paths)
    if unit.startswith(SYSTEM_UNIT_PREFIXES) and not is_custom and not is_third_party_package:
        is_interesting = False
    return {
        "unit": unit,
        "fragment_path": str(fragment) if fragment else "",
        "binary": binary,
        "argv": argv,
        "package": package,
        "environment_files": environment_files,
        "read_write_paths": read_write_paths,
        "working_directory": working_directory,
        "state_directory": state_directory,
        "dropins": dropins,
        "candidate_paths": candidate_paths,
        "enabled_state": systemctl_property(unit, "UnitFileState"),
        "active_state": systemctl_property(unit, "ActiveState"),
        "is_custom": is_custom,
        "is_interesting": is_interesting,
    }


def recovery_score(item: dict) -> dict:
    checks = []
    def add(name: str, weight: int, ok: bool, detail: str):
        checks.append({"name": name, "weight": weight, "ok": bool(ok), "detail": detail})
    add("service definition", 20, bool(item.get("fragment_path")), item.get("fragment_path", "not found"))
    add("executable", 20, bool(item.get("binary") and Path(item["binary"]).exists()), item.get("binary", "not found"))
    add("package identity", 15, bool(item.get("package")), item.get("package", "manual or unknown"))
    existing = [p for p in item.get("candidate_paths", []) if Path(p).exists()]
    add("configuration and data", 25, bool(existing), ", ".join(existing) if existing else "no paths inferred")
    add("startup state", 10, item.get("enabled_state") in {"enabled", "static", "indirect", "generated"}, item.get("enabled_state", "unknown"))
    add("runtime visibility", 10, item.get("active_state") in {"active", "inactive", "failed"}, item.get("active_state", "unknown"))
    score = sum(c["weight"] for c in checks if c["ok"])
    missing = [c["name"] for c in checks if not c["ok"]]
    return {"score": score, "checks": checks, "missing": missing}


def detect_profiles() -> list[dict]:
    detected = []
    for profile in load_profiles():
        evidence = []
        for package in profile.get("packages", []):
            if package_installed(package):
                evidence.append(f"package:{package}")
        for unit in profile.get("services", []):
            if unit_exists(unit):
                evidence.append(f"service:{unit}")
        for item in profile.get("paths", []):
            if Path(item).exists():
                evidence.append(f"path:{item}")
        if evidence:
            record = dict(profile)
            record["source"] = "profile"
            record["evidence"] = evidence
            record["existing_paths"] = [p for p in profile.get("paths", []) if Path(p).exists()]
            detected.append(record)
    return detected


def intelligent_services() -> list[dict]:
    services = []
    for unit in list_service_units():
        item = analyze_service(unit)
        if item["is_interesting"]:
            item["recovery"] = recovery_score(item)
            services.append(item)
    return services


def dependency_graph(services: list[dict]) -> list[dict]:
    names = {s["unit"] for s in services}
    graph = []
    for service in services:
        after = set(systemctl_property(service["unit"], "After").split())
        requires = set(systemctl_property(service["unit"], "Requires").split())
        dependencies = sorted((after | requires) & names)
        graph.append({"service": service["unit"], "depends_on": dependencies})
    return graph


def custom_systemd_units() -> list[str]:
    output = []
    root = Path("/etc/systemd/system")
    if not root.exists():
        return output
    for path in sorted(root.glob("*")):
        if path.name.endswith(UNIT_SUFFIXES) and (path.is_file() or (path.is_symlink() and not path.parent.name.endswith(".wants"))):
            output.append(str(path))
        if path.is_dir() and path.name.endswith(".d"):
            output.extend(str(p) for p in sorted(path.glob("*.conf")))
    return output


def manual_packages() -> list[str]:
    if not command_exists("apt-mark"):
        return []
    result = run(["apt-mark", "showmanual"])
    return sorted(line.strip() for line in result.stdout.splitlines() if line.strip())


def pve_version() -> str:
    return run(["pveversion", "-v"]).stdout.strip() if command_exists("pveversion") else ""


def guest_inventory() -> dict:
    guests = {"qemu": [], "lxc": []}
    if command_exists("qm"):
        guests["qemu"] = run(["qm", "list"]).stdout.splitlines()
    if command_exists("pct"):
        guests["lxc"] = run(["pct", "list"]).stdout.splitlines()
    return guests


def scan_system() -> dict:
    services = intelligent_services()
    products = detect_applications()
    return {
        "schema_version": 4,
        "tool": {"name": "Proxmox Soft Backup", "short_name": "PSB", "version": "0.6.0"},
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "architecture": platform.machine(),
        "kernel": platform.release(),
        "proxmox_version": pve_version(),
        "os_release": read_text(Path("/etc/os-release")),
        "applications": products,
        "legacy_profile_applications": detect_profiles(),
        "intelligent_services": services,
        "application_dependency_graph": [{"application": a["name"], "depends_on": a.get("dependencies", [])} for a in products],
        "dependency_graph": dependency_graph(services),
        "custom_systemd_units": custom_systemd_units(),
        "manual_packages": manual_packages(),
        "guests": guest_inventory(),
        "environment": {"python": platform.python_version(), "uid": os.geteuid()},
    }
