import json
import os
import platform
import re
import socket
from pathlib import Path

from .common import command_exists, read_text, run


def existing(paths: list[str]) -> list[str]:
    return [p for p in paths if Path(p).exists() or Path(p).is_symlink()]


def command_output(command: list[str]) -> str:
    if not command or not command_exists(command[0]):
        return ""
    result = run(command)
    return result.stdout.strip()


def detect_boot_mode() -> str:
    return "uefi" if Path("/sys/firmware/efi").exists() else "legacy-bios"


def parse_mem_total() -> str:
    text = read_text(Path("/proc/meminfo"))
    match = re.search(r"^MemTotal:\s+(\d+)\s+kB", text, re.MULTILINE)
    if not match:
        return "unknown"
    gib = int(match.group(1)) / 1024 / 1024
    return f"{gib:.1f} GiB"


def cpu_summary() -> str:
    if command_exists("lscpu"):
        model = command_output(["lscpu"]) 
        for line in model.splitlines():
            if line.lower().startswith("model name:"):
                return line.split(":", 1)[1].strip()
    return platform.processor() or "unknown"


def network_names() -> list[str]:
    names = []
    if command_exists("ip"):
        result = run(["ip", "-o", "link", "show"])
        for line in result.stdout.splitlines():
            parts = line.split(":", 2)
            if len(parts) >= 2:
                name = parts[1].strip().split("@")[0]
                transient_prefixes = ("tap", "fwpr", "fwln", "fwbr", "veth")
                if name and name != "lo" and not name.startswith(transient_prefixes):
                    names.append(name)
    return sorted(set(names))


def storage_names() -> list[str]:
    names = []
    if command_exists("pvesm"):
        result = run(["pvesm", "status"])
        for index, line in enumerate(result.stdout.splitlines()):
            if index == 0 or not line.strip():
                continue
            names.append(line.split()[0])
    return sorted(set(names))


def find_hook_scripts() -> list[str]:
    found = set()
    config_roots = [Path("/etc/pve/qemu-server"), Path("/etc/pve/lxc")]
    pattern = re.compile(r"^hookscript:\s*(.+)$", re.MULTILINE)
    for root in config_roots:
        if not root.exists():
            continue
        for config in root.glob("*.conf"):
            text = read_text(config)
            for match in pattern.finditer(text):
                value = match.group(1).strip()
                # Proxmox volume syntax: storage:snippets/file
                if ":" in value and not value.startswith("/"):
                    storage, relative = value.split(":", 1)
                    if relative.startswith("snippets/"):
                        candidates = [
                            Path("/var/lib/vz") / relative,
                            Path("/mnt/pve") / storage / relative,
                        ]
                        for candidate in candidates:
                            if candidate.exists():
                                found.add(str(candidate))
                elif Path(value).exists():
                    found.add(value)
    snippets = Path("/var/lib/vz/snippets")
    if snippets.exists():
        for path in snippets.iterdir():
            if path.is_file():
                found.add(str(path))
    return sorted(found)


def host_components() -> list[dict]:
    specs = [
        {
            "id": "proxmox-datacenter", "display_name": "Proxmox Datacenter",
            "risk": "host-sensitive", "importance": "critical", "weight": 15,
            "paths": [
                "/etc/pve/datacenter.cfg", "/etc/pve/user.cfg", "/etc/pve/domains.cfg",
                "/etc/pve/authkey.pub", "/etc/pve/priv" ,
            ],
        },
        {
            "id": "storage", "display_name": "Storage Configuration",
            "risk": "host-sensitive", "importance": "critical", "weight": 15,
            "paths": ["/etc/pve/storage.cfg", "/etc/lvm", "/etc/zfs", "/etc/fstab"],
        },
        {
            "id": "network", "display_name": "Network Configuration",
            "risk": "dangerous", "importance": "critical", "weight": 15,
            "paths": [
                "/etc/network/interfaces", "/etc/network/interfaces.d", "/etc/hosts",
                "/etc/hostname", "/etc/resolv.conf", "/etc/iproute2",
            ],
        },
        {
            "id": "firewall", "display_name": "Firewall Configuration",
            "risk": "host-sensitive", "importance": "critical", "weight": 10,
            "paths": ["/etc/pve/firewall", "/etc/iptables", "/etc/nftables.conf"],
        },
        {
            "id": "apt", "display_name": "APT and Repositories",
            "risk": "safe", "importance": "critical", "weight": 10,
            "paths": ["/etc/apt"],
        },
        {
            "id": "certificates", "display_name": "Proxmox Certificates",
            "risk": "dangerous", "importance": "critical", "weight": 8,
            "paths": [
                "/etc/pve/local/pve-ssl.pem", "/etc/pve/local/pve-ssl.key",
                "/etc/pve/pve-root-ca.pem", "/etc/pve/priv/pve-root-ca.key",
                "/etc/pve/local/pveproxy-ssl.pem", "/etc/pve/local/pveproxy-ssl.key",
            ],
        },
        {
            "id": "kernel-boot", "display_name": "Kernel and Boot Configuration",
            "risk": "dangerous", "importance": "important", "weight": 8,
            "paths": [
                "/etc/default/grub", "/etc/kernel", "/etc/initramfs-tools",
                "/boot/grub/grub.cfg", "/etc/default/pve-kernel-helper",
            ],
        },
        {
            "id": "modules", "display_name": "Kernel Modules",
            "risk": "host-sensitive", "importance": "critical", "weight": 7,
            "paths": ["/etc/modules", "/etc/modules-load.d", "/etc/modprobe.d", "/etc/udev/rules.d"],
        },
        {
            "id": "cron", "display_name": "Scheduled Tasks",
            "risk": "safe", "importance": "important", "weight": 5,
            "paths": [
                "/etc/crontab", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
                "/etc/cron.monthly", "/etc/cron.weekly", "/var/spool/cron/crontabs/root",
            ],
        },
        {
            "id": "hooks", "display_name": "Proxmox Hooks and Snippets",
            "risk": "safe", "importance": "important", "weight": 4,
            "paths": find_hook_scripts() + ["/var/lib/vz/snippets"],
        },
        {
            "id": "custom-scripts", "display_name": "Custom Administrative Scripts",
            "risk": "safe", "importance": "important", "weight": 3,
            "paths": ["/usr/local/bin", "/usr/local/sbin"],
        },
    ]
    output = []
    for spec in specs:
        record = dict(spec)
        record["existing_paths"] = existing(spec["paths"])
        record["present"] = bool(record["existing_paths"])
        output.append(record)
    return output


def host_fingerprint() -> dict:
    pve = command_output(["pveversion"]) if command_exists("pveversion") else ""
    fingerprint = {
        "hostname": socket.gethostname(),
        "architecture": platform.machine(),
        "kernel": platform.release(),
        "proxmox_version": pve,
        "boot_mode": detect_boot_mode(),
        "cpu": cpu_summary(),
        "memory": parse_mem_total(),
        "network_interfaces": network_names(),
        "storages": storage_names(),
        "machine_id_hash_source_present": Path("/etc/machine-id").exists(),
        "cluster_config_present": Path("/etc/pve/corosync.conf").exists(),
    }
    return fingerprint


def host_inventory() -> dict:
    components = host_components()
    total = sum(c["weight"] for c in components)
    present = sum(c["weight"] for c in components if c["present"])
    return {
        "schema_version": 1,
        "display_name": "Proxmox Host Configuration",
        "fingerprint": host_fingerprint(),
        "components": components,
        "backup_completeness": round(100 * present / total) if total else 100,
        "recovery_enabled": False,
    }
