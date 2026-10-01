import os
import re
from pathlib import Path

from security_runner.models import Project

IGNORED_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "node_modules", "vendor",
    "bin", "obj", "dist", "build", "artifacts", "coverage", "target", "__pycache__", ".terraform",
    ".next", ".nuxt", "security-results",
}
LOCKFILE_NAMES = {
    "packages.lock.json", "packages.config", "package-lock.json", "pnpm-lock.yaml",
    "yarn.lock", "requirements.txt", "poetry.lock", "go.mod", "cargo.lock",
    "cargo.toml", "pom.xml", "build.gradle", "build.gradle.kts",
}
SOURCE_EXTENSIONS = {
    ".cs", ".fs", ".vb", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
    ".py", ".java", ".kt", ".go", ".rs", ".php", ".rb", ".swift", ".c",
    ".h", ".cc", ".cpp", ".hpp", ".scala", ".ex", ".exs",
}
TECH_ORDER = [
    ".NET", "Node.js", "npm", "pnpm", "yarn", "Python", "Java", "Go", "Rust",
    "Docker", "Terraform", "Kubernetes",
]


def detect_project(root: Path, exclude_paths: set[str] | None = None) -> Project:
    excluded_paths = {path.strip("/") for path in (exclude_paths or set()) if path.strip("/")}
    files: list[Path] = []
    for current, dirs, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        relative_current = current_path.relative_to(root).as_posix() if current_path != root else ""
        dirs[:] = sorted(
            name for name in dirs
            if name not in IGNORED_DIRS
            and not _is_excluded_path(f"{relative_current}/{name}".strip("/"), excluded_paths)
        )
        for filename in filenames:
            path = Path(current, filename)
            try:
                if path.is_file():
                    files.append(path)
            except OSError:
                continue

    technologies: set[str] = set()
    artifacts: set[str] = set()
    lockfiles: list[str] = []
    has_source = False

    for path in files:
        name = path.name.lower()
        suffix = path.suffix.lower()
        relative = path.relative_to(root).as_posix()
        if suffix in SOURCE_EXTENSIONS:
            has_source = True
        if name.endswith((".csproj", ".fsproj", ".vbproj", ".sln")) or name in {
            "packages.lock.json", "packages.config",
        } or name.endswith(".deps.json"):
            technologies.add(".NET")
            if name.endswith((".csproj", ".fsproj", ".vbproj", ".sln")) or name in LOCKFILE_NAMES or name.endswith(".deps.json"):
                artifacts.add(relative)
        if name == "package.json" or name in {"package-lock.json", "pnpm-lock.yaml", "yarn.lock"}:
            technologies.add("Node.js")
            artifacts.add(relative)
            if name in LOCKFILE_NAMES:
                lockfiles.append(relative)
        if name == "package-lock.json":
            technologies.add("npm")
        elif name == "pnpm-lock.yaml":
            technologies.add("pnpm")
        elif name == "yarn.lock":
            technologies.add("yarn")
        if name in {"requirements.txt", "pyproject.toml", "poetry.lock", "setup.py", "setup.cfg"}:
            technologies.add("Python")
            artifacts.add(relative)
            if name in LOCKFILE_NAMES:
                lockfiles.append(relative)
        if name in {"pom.xml", "build.gradle", "build.gradle.kts"} or suffix == ".jar":
            technologies.add("Java")
            artifacts.add(relative)
            if name in LOCKFILE_NAMES:
                lockfiles.append(relative)
        if name == "go.mod":
            technologies.add("Go")
            artifacts.add(relative)
            lockfiles.append(relative)
        if name in {"cargo.toml", "cargo.lock"}:
            technologies.add("Rust")
            artifacts.add(relative)
            lockfiles.append(relative)
        if name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile"):
            technologies.add("Docker")
            artifacts.add(relative)
        if suffix in {".tf", ".tfvars"}:
            technologies.add("Terraform")
            artifacts.add(relative)
        if suffix in {".yaml", ".yml", ".json"} and _is_kubernetes_manifest(path):
            technologies.add("Kubernetes")
            artifacts.add(relative)

    return Project(
        technologies=[technology for technology in TECH_ORDER if technology in technologies],
        artifacts=sorted(artifacts),
        lockfiles=sorted(set(lockfiles)),
        has_source=has_source,
        has_files=bool(files),
    )


def _is_kubernetes_manifest(path: Path) -> bool:
    try:
        if path.stat().st_size > 1_000_000:
            return False
        content = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    return bool(
        re.search(r"(?m)^\s*apiVersion\s*:", content)
        and re.search(r"(?m)^\s*kind\s*:", content)
    )


def _is_excluded_path(path: str, excluded_paths: set[str]) -> bool:
    return any(path == excluded or path.startswith(f"{excluded}/") for excluded in excluded_paths)