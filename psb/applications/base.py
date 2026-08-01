from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from psb.modules.common import command_exists, run


@dataclass
class PathSpec:
    path: str
    level: str = "critical"
    kind: str = "data"


@dataclass
class ApplicationResult:
    name: str
    display_name: str
    category: str
    confidence: int
    detected: bool
    evidence: list[str] = field(default_factory=list)
    missing_signals: list[str] = field(default_factory=list)
    packages: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    paths: list[dict] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    health_checks: list[dict] = field(default_factory=list)

    def existing_paths(self, mode: str = "standard") -> list[str]:
        allowed = {
            "minimal": {"critical"},
            "standard": {"critical", "important"},
            "full": {"critical", "important", "optional"},
        }[mode]
        return [p["path"] for p in self.paths if p["level"] in allowed and (Path(p["path"]).exists() or Path(p["path"]).is_symlink())]


class ApplicationDetector:
    name = "unknown"
    display_name = "Unknown"
    category = "Other"
    package_names: tuple[str, ...] = ()
    service_names: tuple[str, ...] = ()
    binary_names: tuple[str, ...] = ()
    path_specs: tuple[PathSpec, ...] = ()
    dependencies: tuple[str, ...] = ()

    def package_installed(self, package: str) -> bool:
        if not command_exists("dpkg-query"):
            return False
        result = run(["dpkg-query", "-W", "-f=${Status}", package])
        return result.returncode == 0 and "install ok installed" in result.stdout

    def service_exists(self, service: str) -> bool:
        if not command_exists("systemctl"):
            return False
        result = run(["systemctl", "show", service, "--property=LoadState", "--value"])
        return result.stdout.strip() not in {"", "not-found"}

    def binary_path(self, binary: str) -> str:
        if binary.startswith("/") and Path(binary).exists():
            return binary
        if command_exists("which"):
            result = run(["which", binary])
            if result.returncode == 0:
                return result.stdout.strip()
        for root in (Path("/usr/local/bin"), Path("/usr/local/sbin"), Path("/opt"), Path("/usr/bin"), Path("/usr/sbin")):
            candidate = root / binary
            if candidate.exists():
                return str(candidate)
        return ""

    def extra_signals(self) -> list[tuple[str, bool, int]]:
        return []

    def detect(self) -> ApplicationResult:
        evidence: list[str] = []
        missing: list[str] = []
        packages = [p for p in self.package_names if self.package_installed(p)]
        services = [s for s in self.service_names if self.service_exists(s)]
        binaries = [(b, self.binary_path(b)) for b in self.binary_names]
        existing_paths = [p for p in self.path_specs if Path(p.path).exists() or Path(p.path).is_symlink()]

        score = 0
        if packages:
            score += 25
            evidence.extend(f"package:{p}" for p in packages)
        elif self.package_names:
            missing.append("package")
        if services:
            score += 25
            evidence.extend(f"service:{s}" for s in services)
        elif self.service_names:
            missing.append("service")
        found_bins = [path for _, path in binaries if path]
        if found_bins:
            score += 20
            evidence.extend(f"binary:{p}" for p in found_bins)
        elif self.binary_names:
            missing.append("binary")
        if existing_paths:
            score += 20
            evidence.extend(f"path:{p.path}" for p in existing_paths)
        elif self.path_specs:
            missing.append("configuration or data")
        extras = self.extra_signals()
        for label, ok, weight in extras:
            if ok:
                score += weight
                evidence.append(label)
            else:
                missing.append(label.split(":", 1)[0])
        score = min(score, 100)
        detected = score >= 20 and bool(evidence)
        return ApplicationResult(
            name=self.name,
            display_name=self.display_name,
            category=self.category,
            confidence=score if detected else 0,
            detected=detected,
            evidence=evidence,
            missing_signals=list(dict.fromkeys(missing)),
            packages=packages,
            services=services,
            paths=[{"path": p.path, "level": p.level, "kind": p.kind, "exists": Path(p.path).exists() or Path(p.path).is_symlink()} for p in self.path_specs],
            dependencies=list(self.dependencies),
        )
