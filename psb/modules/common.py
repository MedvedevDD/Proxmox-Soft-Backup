import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Iterable, Optional

from .checksums import sha256_file


def run(command: list[str], check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=check,
    )


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")



def iter_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            yield path


def safe_rel(path: Path, base: Path) -> str:
    return str(path.relative_to(base))


def first_existing(paths: Iterable[str]) -> Optional[str]:
    for item in paths:
        if Path(item).exists():
            return item
    return None


def is_root() -> bool:
    return os.geteuid() == 0
