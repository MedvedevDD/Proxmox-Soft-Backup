import hashlib
import zipfile
from pathlib import Path


def verify_backup(package: Path) -> tuple[bool, list[str]]:
    package = package.resolve()
    if not package.is_file():
        return False, [f"FAIL: Package not found: {package}"]
    messages=[]; ok=True
    try:
        with zipfile.ZipFile(package, "r") as archive:
            bad=archive.testzip()
            if bad:
                return False,[f"FAIL: ZIP integrity error: {bad}"]
            try: lines=archive.read("checksums.sha256").decode("ascii").splitlines()
            except KeyError: return False,["FAIL: checksums.sha256 is missing"]
            names=set(archive.namelist())
            for line in lines:
                if not line.strip(): continue
                try: expected,rel=line.split("  ",1)
                except ValueError:
                    messages.append(f"FAIL: Invalid checksum line: {line}"); ok=False; continue
                if rel not in names:
                    messages.append(f"FAIL: Missing member: {rel}"); ok=False; continue
                actual=hashlib.sha256(archive.read(rel)).hexdigest()
                if actual!=expected:
                    messages.append(f"FAIL: Checksum mismatch: {rel}"); ok=False
                else: messages.append(f"PASS: {rel}")
    except zipfile.BadZipFile:
        return False,["FAIL: Invalid PSB package"]
    if ok: messages.append("PASS: PSB package verification completed successfully")
    return ok,messages
