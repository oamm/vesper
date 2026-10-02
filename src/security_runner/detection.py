import os
import re
from pathlib import Path

from security_runner.models import Project

IGNORED_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", ".tmp", "tmp", "node_modules", "vendor",
    "bin", "obj", "dist", "build", "artifacts", "coverage", "target", "__pycache__", ".terraform",
    ".next", ".nuxt", "security-results",
}
LOCKFILE_NAMES = {
    "packages.lock.json", "packages.config", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock",
    "requirements.txt", "poetry.lock", "pipfile.lock", "pdm.lock", "pylock.toml", "uv.lock",
    "go.mod", "cargo.lock", "conan.lock", "pom.xml", "gradle.lockfile", "buildscript-gradle.lockfile",
    "verification-metadata.xml", "pubspec.lock", "mix.lock", "cabal.project.freeze", "stack.yaml.lock",
    "composer.lock", "gemfile.lock", "gems.locked",
}
DEPENDENCY_CANDIDATE_NAMES = LOCKFILE_NAMES | {
    "package.json", "pyproject.toml", "setup.py", "setup.cfg", "pipfile", "cargo.toml",
    "build.gradle", "build.gradle.kts", "composer.json", "gemfile",
}
SOURCE_EXTENSIONS = {
    ".cs", ".fs", ".vb", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
    ".py", ".java", ".kt", ".go", ".rs", ".php", ".rb", ".swift", ".c",
    ".h", ".cc", ".cpp", ".hpp", ".scala", ".ex", ".exs",
}
TECH_ORDER = [
    ".NET", "Node.js", "npm", "pnpm", "yarn", "bun", "Python", "Java", "Go", "Rust", "C/C++",
    "Dart", "Elixir", "Haskell", "PHP", "Ruby", "Docker", "Terraform", "Kubernetes",
]


def detect_project(
    root: Path,
    exclude_paths: set[str] | None = None,
    exclude_files: set[str] | None = None,
) -> Project:
    excluded_paths = {path.strip("/") for path in (exclude_paths or set()) if path.strip("/")}
    excluded_files = {path.replace("\\", "/").strip("/") for path in (exclude_files or set()) if path.strip("/\\")}
    files: list[Path] = []
    exclusions: dict[str, str] = {}
    for current, dirs, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        relative_current = current_path.relative_to(root).as_posix() if current_path != root else ""
        kept_directories = []
        for name in dirs:
            relative_directory = f"{relative_current}/{name}".strip("/")
            if name in IGNORED_DIRS:
                exclusions[relative_directory] = "generated_or_transient_directory"
            elif _is_excluded_path(relative_directory, excluded_paths):
                exclusions[relative_directory] = "scan_output_or_user_exclusion"
            else:
                kept_directories.append(name)
        dirs[:] = sorted(kept_directories)
        for filename in filenames:
            path = Path(current, filename)
            relative_file = f"{relative_current}/{filename}".strip("/")
            if relative_file in excluded_files:
                exclusions[relative_file] = "baseline_input"
                continue
            try:
                if path.is_file():
                    files.append(path)
            except OSError:
                continue

    technologies: set[str] = set()
    artifacts: set[str] = set()
    project_descriptors: list[str] = []
    lockfiles: list[str] = []
    dependency_manifests: set[str] = set()
    source_files: list[str] = []
    has_source = False

    for path in files:
        name = path.name.lower()
        suffix = path.suffix.lower()
        relative = path.relative_to(root).as_posix()
        if suffix in SOURCE_EXTENSIONS:
            has_source = True
            source_files.append(relative)
        is_dotnet_project = name.endswith((".csproj", ".fsproj", ".vbproj"))
        is_dotnet_solution = name.endswith(".sln")
        if is_dotnet_project or is_dotnet_solution:
            project_descriptors.append(relative)
            artifacts.add(relative)
        if name in DEPENDENCY_CANDIDATE_NAMES or name.endswith(".deps.json"):
            dependency_manifests.add(relative)
            artifacts.add(relative)
        if name in LOCKFILE_NAMES or name.endswith(".deps.json"):
            lockfiles.append(relative)

        if is_dotnet_project or is_dotnet_solution or name in {"packages.lock.json", "packages.config"} or name.endswith(".deps.json"):
            technologies.add(".NET")
        if is_dotnet_solution:
            artifacts.add(relative)
        if name in {"package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock"}:
            technologies.add("Node.js")
        if name == "package-lock.json":
            technologies.add("npm")
        elif name == "pnpm-lock.yaml":
            technologies.add("pnpm")
        elif name == "yarn.lock":
            technologies.add("yarn")
        elif name == "bun.lock":
            technologies.add("bun")
        if name in {"requirements.txt", "pyproject.toml", "poetry.lock", "setup.py", "setup.cfg", "pipfile", "pipfile.lock", "pdm.lock", "pylock.toml", "uv.lock"}:
            technologies.add("Python")
        if name in {"pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile", "buildscript-gradle.lockfile", "verification-metadata.xml"} or suffix == ".jar":
            technologies.add("Java")
        if name == "go.mod":
            technologies.add("Go")
        if name in {"cargo.toml", "cargo.lock"}:
            technologies.add("Rust")
        if name == "conan.lock":
            technologies.add("C/C++")
        if name in {"pubspec.yaml", "pubspec.lock"}:
            technologies.add("Dart")
        if name in {"mix.exs", "mix.lock"}:
            technologies.add("Elixir")
        if name in {"cabal.project", "cabal.project.freeze", "stack.yaml", "stack.yaml.lock"}:
            technologies.add("Haskell")
        if name in {"composer.json", "composer.lock"}:
            technologies.add("PHP")
        if name in {"gemfile", "gemfile.lock", "gems.locked"}:
            technologies.add("Ruby")
        if name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile"):
            technologies.add("Docker")
            artifacts.add(relative)
        if suffix in {".tf", ".tfvars"}:
            technologies.add("Terraform")
            artifacts.add(relative)
        if suffix in {".yaml", ".yml", ".json"} and _is_kubernetes_manifest(path):
            technologies.add("Kubernetes")
            artifacts.add(relative)

    artifact_summary: dict[str, int] = {}
    for artifact in artifacts:
        kind = _artifact_kind(Path(artifact).name.lower(), Path(artifact).suffix.lower())
        if kind:
            artifact_summary[kind] = artifact_summary.get(kind, 0) + 1

    covered_manifests = sorted(
        manifest for manifest in dependency_manifests
        if manifest not in lockfiles and _is_covered_by_sibling_lock(manifest, lockfiles)
    )
    unsupported_manifests = sorted(dependency_manifests - set(lockfiles) - set(covered_manifests))
    dotnet_projects = []
    unsupported_dotnet_projects = []
    for descriptor in sorted(path for path in project_descriptors if Path(path).suffix.casefold() in {".csproj", ".fsproj", ".vbproj"}):
        inputs = _dotnet_project_inputs(descriptor, lockfiles)
        if not inputs:
            unsupported_dotnet_projects.append(descriptor)
        dotnet_projects.append({
            "name": Path(descriptor).stem,
            "projectDescriptor": descriptor,
            "scannerInputs": inputs,
            "coverage": "supported" if inputs else "unsupported",
            "scope": _classify_project_scope(descriptor),
        })

    return Project(
        technologies=[technology for technology in TECH_ORDER if technology in technologies],
        artifacts=sorted(artifacts),
        project_descriptors=sorted(project_descriptors),
        dotnet_projects=dotnet_projects,
        lockfiles=sorted(set(lockfiles)),
        dependency_manifests=sorted(dependency_manifests),
        covered_dependency_manifests=covered_manifests,
        unsupported_dependency_manifests=unsupported_manifests,
        unsupported_dependency_projects=unsupported_dotnet_projects,
        source_files=sorted(source_files),
        artifact_summary=dict(sorted(artifact_summary.items())),
        exclusions=[{"path": path, "reason": reason} for path, reason in sorted(exclusions.items())],
        file_count=len(files),
        has_source=has_source,
        has_files=bool(files),
    )


def _is_covered_by_sibling_lock(manifest: str, lockfiles: list[str]) -> bool:
    name = Path(manifest).name.casefold()
    sibling_locks = {
        "package.json": {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock"},
        "pyproject.toml": {"poetry.lock", "pipfile.lock", "pdm.lock", "pylock.toml", "uv.lock", "requirements.txt"},
        "setup.py": {"requirements.txt"},
        "setup.cfg": {"requirements.txt"},
        "pipfile": {"pipfile.lock"},
        "cargo.toml": {"cargo.lock"},
        "gemfile": {"gemfile.lock", "gems.locked"},
        "composer.json": {"composer.lock"},
        "build.gradle": {"gradle.lockfile", "buildscript-gradle.lockfile", "verification-metadata.xml"},
        "build.gradle.kts": {"gradle.lockfile", "buildscript-gradle.lockfile", "verification-metadata.xml"},
        ".csproj": {"packages.lock.json", "packages.config"},
        ".fsproj": {"packages.lock.json", "packages.config"},
        ".vbproj": {"packages.lock.json", "packages.config"},
    }.get(name, set())
    parent = Path(manifest).parent.as_posix()
    return any(
        Path(lockfile).parent.as_posix() == parent and Path(lockfile).name.casefold() in sibling_locks
        for lockfile in lockfiles
    )


def _dotnet_project_inputs(project_descriptor: str, lockfiles: list[str]) -> list[str]:
    project_path = Path(project_descriptor)
    project_parent = project_path.parent.as_posix()
    project_stem = project_path.stem.casefold()
    inputs = []
    for lockfile in lockfiles:
        lock_path = Path(lockfile)
        lock_name = lock_path.name.casefold()
        same_directory = lock_path.parent.as_posix() == project_parent
        if same_directory and lock_name in {"packages.lock.json", "packages.config"}:
            inputs.append(lockfile)
            continue
        is_descendant = project_parent == "." or lock_path.parent.as_posix().startswith(f"{project_parent}/")
        if is_descendant and lock_name.endswith(".deps.json") and lock_path.name[:-len(".deps.json")].casefold() == project_stem:
            inputs.append(lockfile)
    return sorted(inputs)


def _classify_project_scope(project_descriptor: str) -> str:
    path = Path(project_descriptor)
    parts = [part.casefold() for part in path.parts]
    name = path.stem.casefold()
    if any(part in {"test", "tests", "unittest", "__tests__"} for part in parts) or name.endswith((".test", ".tests")):
        return "test"
    if any(part in {"benchmark", "benchmarks"} for part in parts) or "benchmark" in name:
        return "benchmark"
    if any(part in {"migration", "migrations"} for part in parts) or "migration" in name:
        return "migration"
    if any(part in {"tool", "tools", "tooling", "scripts"} for part in parts) or name.endswith((".tool", ".tools")):
        return "tooling"
    return "unknown"


def _artifact_kind(name: str, suffix: str) -> str | None:
    fixed_kinds = {
        "packages.lock.json": "packagesLock",
        "packages.config": "packagesConfig",
        "package-lock.json": "packageLock",
        "package.json": "packageManifest",
        "pnpm-lock.yaml": "pnpmLock",
        "yarn.lock": "yarnLock",
        "bun.lock": "bunLock",
        "conan.lock": "conanLock",
        "requirements.txt": "requirements",
        "pom.xml": "pom",
        "dockerfile": "dockerfile",
    }
    if name in fixed_kinds:
        return fixed_kinds[name]
    if name.endswith(".deps.json"):
        return "dotnetDeps"
    if suffix in {".csproj", ".fsproj", ".vbproj"}:
        return suffix[1:]
    if suffix in {".tf", ".tfvars"}:
        return "terraform"
    if suffix in {".yaml", ".yml"} and name in {"pubspec.yaml", "stack.yaml"}:
        return name.rsplit(".", maxsplit=1)[0]
    return suffix[1:] if suffix else None


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