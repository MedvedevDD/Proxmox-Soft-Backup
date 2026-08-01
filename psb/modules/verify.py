import zipfile
from pathlib import Path

from .checksums import sha256_bytes


def verify_backup(package: Path) -> tuple[bool, list[str]]:
    package = package.resolve()
    if not package.is_file():
        return False, [f"FAIL: Package not found: {package}"]

    messages: list[str] = []
    ok = True

    try:
        with zipfile.ZipFile(package, "r") as archive:
            bad_member = archive.testzip()
            if bad_member:
                return False, [f"FAIL: ZIP integrity error: {bad_member}"]

            try:
                checksum_lines = archive.read("checksums.sha256").decode("ascii").splitlines()
            except KeyError:
                return False, ["FAIL: checksums.sha256 is missing"]

            member_names = set(archive.namelist())
            for line in checksum_lines:
                if not line.strip():
                    continue

                try:
                    expected, member = line.split("  ", 1)
                except ValueError:
                    messages.append(f"FAIL: Invalid checksum line: {line}")
                    ok = False
                    continue

                if member not in member_names:
                    messages.append(f"FAIL: Missing member: {member}")
                    ok = False
                    continue

                actual = sha256_bytes(archive.read(member))
                if actual != expected:
                    messages.append(f"FAIL: Checksum mismatch: {member}")
                    ok = False
                else:
                    messages.append(f"PASS: {member}")
    except zipfile.BadZipFile:
        return False, ["FAIL: Invalid PSB package"]

    if ok:
        messages.append("PASS: PSB package verification completed successfully")
    return ok, messages
