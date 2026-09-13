#!/usr/bin/env python3
"""Phase 3 architecture and dependency-boundary guard.

This checker combines conservative source-pattern analysis with both the
default and all-features graphs from ``cargo metadata --locked``. Manifest
declarations are checked independently of resolved edges so inactive optional,
development, build, target-specific, and renamed dependencies cannot bypass the
policy.

It is NOT a Rust parser, macro expander, compiler visibility proof, runtime
sandbox, or formal verification system.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, fields
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "crates" / "core"
PORTS = ROOT / "crates" / "ports"
CRYPTO = ROOT / "crates" / "crypto"
CRYPTO_API = CRYPTO / "icc-crypto-api"
PLATFORM = ROOT / "crates" / "platform"
APPS = ROOT / "apps"
LOCKFILE = ROOT / "Cargo.lock"
CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"

SECRET_WRAPPERS = {
    "Ed25519SigningSeed",
    "X25519Secret",
    "SharedSecret32",
    "AeadKey32",
    "DerivedKey32",
}

FORBIDDEN_SECRET_TRAITS = {
    "Copy",
    "Clone",
    "Debug",
    "Serialize",
    "Deserialize",
}

FORBIDDEN_CORE_TOKENS = {
    "std::fs": "filesystem access belongs in an adapter",
    "std::net": "network access belongs in an adapter",
    "std::env": "environment access belongs in the composition layer",
    "std::process": "process creation belongs in runtime/platform code",
    "std::os": "OS-specific APIs cannot enter Domain Core",
    "SystemTime": "wall-clock implementation belongs behind a Clock port",
    "Instant": "monotonic-clock implementation belongs behind a Clock port",
    "UnixStream": "concrete IPC/network transport cannot enter Domain Core",
    "TcpStream": "concrete network transport cannot enter Domain Core",
    "PathBuf": "physical filesystem paths cannot become Domain Core authority",
    "tokio::": "async runtime types cannot enter Domain Core",
    "rusqlite": "database implementation cannot enter Domain Core",
    "reqwest": "HTTP implementation cannot enter Domain Core",
    "libc::": "raw platform FFI cannot enter Domain Core",
}

FORBIDDEN_PORT_TOKENS = {
    "std::fs": "Port definitions must describe semantics, not a filesystem implementation",
    "std::net": "Port definitions must not bind to a concrete network stack",
    "tokio::": "Port definitions must not bind to a concrete async runtime",
    "std::os": "Port definitions must remain platform-neutral",
}

FORBIDDEN_CRYPTO_API_TOKENS = {
    "use ed25519_dalek": "provider implementation must not leak into crypto API",
    "use x25519_dalek": "provider implementation must not leak into crypto API",
    "use chacha20poly1305": "provider implementation must not leak into crypto API",
    "use sha2::": "provider implementation must not leak into crypto API",
    "use hkdf::": "provider implementation must not leak into crypto API",
    "std::": "crypto API must remain no_std",
}


@dataclass(frozen=True)
class DependencyDeclaration:
    """One exact direct-dependency declaration allowed for a workspace package."""

    actual_package: str
    alias: str
    kind: str
    target: str | None
    optional: bool
    source: str | None
    path_target: str | None
    version_requirement: str
    uses_default_features: bool
    requested_features: tuple[str, ...]
    registry: str | None


def path_dependency(name: str) -> DependencyDeclaration:
    return DependencyDeclaration(
        actual_package=name,
        alias=name,
        kind="normal",
        target=None,
        optional=False,
        source=None,
        path_target=name,
        version_requirement="*",
        uses_default_features=True,
        requested_features=(),
        registry=None,
    )


def registry_dependency(
    name: str,
    version: str,
    *,
    uses_default_features: bool,
    features: tuple[str, ...] = (),
) -> DependencyDeclaration:
    return DependencyDeclaration(
        actual_package=name,
        alias=name,
        kind="normal",
        target=None,
        optional=False,
        source=CRATES_IO_SOURCE,
        path_target=None,
        version_requirement=f"={version}",
        uses_default_features=uses_default_features,
        requested_features=tuple(sorted(features)),
        registry=None,
    )


# Phase 0.3 dependency matrix represented as a complete declaration allowlist.
# Every workspace package must appear. Each entry fixes package identity, local
# alias, dependency kind, target condition, optional flag, source/path target,
# version requirement, default-feature semantics, and requested feature set.
# Anything else fails closed.
#
# ``icc-identity-core -> icc-platform-api`` is the reviewed Phase 1 Port
# dependency-inversion exception. Phase 3 adds the reviewed dependency on the
# provider-neutral crypto API for signature verification; Domain Core still
# cannot depend on a concrete crypto provider.
PACKAGE_DECLARATION_POLICY: dict[str, frozenset[DependencyDeclaration]] = {
    "icc-types": frozenset(),
    "icc-error": frozenset(),
    "icc-rights": frozenset(),
    "icc-capability-core": frozenset(
        {
            path_dependency("icc-error"),
            path_dependency("icc-rights"),
            path_dependency("icc-types"),
        }
    ),
    "icc-identity-core": frozenset(
        {
            path_dependency("icc-crypto-api"),
            path_dependency("icc-error"),
            path_dependency("icc-platform-api"),
            path_dependency("icc-types"),
        }
    ),
    "icc-platform-api": frozenset(
        {path_dependency("icc-error"), path_dependency("icc-types")}
    ),
    "icc-crypto-api": frozenset(
        {registry_dependency("zeroize", "1.9.0", uses_default_features=False)}
    ),
    "icc-crypto-rust": frozenset(
        {
            registry_dependency(
                "chacha20poly1305",
                "0.11.0",
                uses_default_features=False,
                features=("alloc", "zeroize"),
            ),
            registry_dependency(
                "ed25519-dalek",
                "3.0.0",
                uses_default_features=False,
                features=("zeroize",),
            ),
            registry_dependency("hkdf", "0.13.0", uses_default_features=False),
            path_dependency("icc-crypto-api"),
            registry_dependency("sha2", "0.11.0", uses_default_features=False),
            registry_dependency(
                "x25519-dalek",
                "3.0.0",
                uses_default_features=False,
                features=("static_secrets", "zeroize"),
            ),
        }
    ),
    "icc-test-support": frozenset(
        {
            path_dependency("icc-error"),
            path_dependency("icc-platform-api"),
            path_dependency("icc-types"),
        }
    ),
    "icc-platform-linux": frozenset(
        {
            registry_dependency("getrandom", "0.4.3", uses_default_features=True),
            path_dependency("icc-error"),
            path_dependency("icc-platform-api"),
            path_dependency("icc-types"),
        }
    ),
    "indie-cli": frozenset(
        {
            path_dependency("icc-capability-core"),
            path_dependency("icc-platform-api"),
            path_dependency("icc-platform-linux"),
            path_dependency("icc-rights"),
            path_dependency("icc-types"),
        }
    ),
    "icc-architecture-tests": frozenset(
        {
            path_dependency("icc-capability-core"),
            path_dependency("icc-crypto-api"),
            path_dependency("icc-crypto-rust"),
            path_dependency("icc-error"),
            path_dependency("icc-identity-core"),
            path_dependency("icc-platform-api"),
            path_dependency("icc-rights"),
            path_dependency("icc-test-support"),
            path_dependency("icc-types"),
        }
    ),
}

# Backward-compatible name for review tooling importing the old symbol.
PACKAGE_POLICY = PACKAGE_DECLARATION_POLICY

# Exact feature unions permitted on reviewed direct external identities. The
# all-features graph is the security-relevant union; checking the default graph
# also protects the existing inventory evidence from silent drift.
RESOLVED_FEATURE_POLICY: dict[tuple[str, str, str], frozenset[str]] = {
    ("zeroize", "1.9.0", CRATES_IO_SOURCE): frozenset(),
    ("chacha20poly1305", "0.11.0", CRATES_IO_SOURCE): frozenset(
        {"alloc", "zeroize"}
    ),
    ("ed25519-dalek", "3.0.0", CRATES_IO_SOURCE): frozenset({"zeroize"}),
    ("hkdf", "0.13.0", CRATES_IO_SOURCE): frozenset(),
    ("sha2", "0.11.0", CRATES_IO_SOURCE): frozenset(),
    ("x25519-dalek", "3.0.0", CRATES_IO_SOURCE): frozenset(
        {"static_secrets", "zeroize"}
    ),
    ("getrandom", "0.4.3", CRATES_IO_SOURCE): frozenset(),
}

MANIFEST_FEATURE_POLICY: dict[str, tuple[bool, frozenset[str]]] = {
    "zeroize": (False, frozenset()),
    "chacha20poly1305": (False, frozenset({"alloc", "zeroize"})),
    "ed25519-dalek": (False, frozenset({"zeroize"})),
    "hkdf": (False, frozenset()),
    "sha2": (False, frozenset()),
    "x25519-dalek": (False, frozenset({"static_secrets", "zeroize"})),
    # Preserve the reviewed string-declaration semantics in the Linux adapter.
    "getrandom": (True, frozenset()),
}

ED25519_FORBIDDEN_FEATURES = {"serde", "hazmat", "legacy_compatibility"}

UNSAFE_RE = re.compile(r"\bunsafe\s*(?:\{|fn\b|impl\b|trait\b|extern\b)")
DERIVE_RE = re.compile(r"#\s*\[\s*derive\s*\((?P<traits>[^)]*)\)\s*\]", re.DOTALL)
SECRET_MACRO_RE = re.compile(
    r"macro_rules!\s+secret32_type\b(?P<body>.*?)(?=secret32_type!\s*\()",
    re.DOTALL,
)
TYPE_ALIAS_RE = re.compile(
    r"\btype\s+(?P<alias>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?P<target>(?:(?:[A-Za-z_][A-Za-z0-9_]*)::)*[A-Za-z_][A-Za-z0-9_]*)\s*;"
)
TRAIT_IMPORT_ALIAS_RE = re.compile(
    r"\buse\s+(?P<trait>(?:(?:[A-Za-z_][A-Za-z0-9_]*)::)*"
    r"(?:Copy|Clone|Debug|Serialize|Deserialize))\s+as\s+"
    r"(?P<alias>[A-Za-z_][A-Za-z0-9_]*)\s*;"
)
IMPL_RE = re.compile(
    r"\bimpl(?:\s*<[^{};]*>)?\s+"
    r"(?P<trait>(?:(?:[A-Za-z_][A-Za-z0-9_]*)::)*[A-Za-z_][A-Za-z0-9_]*)"
    r"\s+for\s+"
    r"(?P<target>(?:(?:[A-Za-z_][A-Za-z0-9_]*)::)*[A-Za-z_][A-Za-z0-9_]*)\b"
)


def check_tree(base: Path, rules: dict[str, str]) -> list[str]:
    failures: list[str] = []
    if not base.exists():
        return failures
    for path in base.rglob("*.rs"):
        text = path.read_text(encoding="utf-8")
        for token, reason in rules.items():
            if token in text:
                failures.append(f"{path.relative_to(ROOT)}: found {token!r} — {reason}")
    return failures


def _read_metadata_file(path: Path, label: str) -> tuple[list[str], dict | None]:
    try:
        return [], json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        return [f"cannot read {label} Cargo metadata {path}: {error}"], None
    except json.JSONDecodeError as error:
        return [f"{label} Cargo metadata is invalid JSON: {error}"], None


def _run_locked_metadata(*, all_features: bool) -> tuple[list[str], dict | None]:
    command = ["cargo", "metadata", "--locked"]
    label = "all-features" if all_features else "default"
    if all_features:
        command.append("--all-features")
    command.extend(["--format-version", "1"])

    try:
        proc = subprocess.run(
            command,
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        return ["cargo is required to validate the locked dependency graphs"], None

    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or "unknown cargo metadata failure"
        return [f"{' '.join(command)} failed: {detail}"], None

    try:
        return [], json.loads(proc.stdout)
    except json.JSONDecodeError as error:
        return [f"{label} cargo metadata returned invalid JSON: {error}"], None


def require_lockfile_and_locked_metadata(
    default_path: Path | None = None,
    all_features_path: Path | None = None,
) -> tuple[list[str], dict | None, dict | None]:
    if not LOCKFILE.is_file():
        return ["Cargo.lock is required for reproducible Phase 2 dependency resolution"], None, None

    if default_path is None:
        default_failures, default_metadata = _run_locked_metadata(all_features=False)
    else:
        default_failures, default_metadata = _read_metadata_file(default_path, "default")

    if all_features_path is None:
        all_failures, all_metadata = _run_locked_metadata(all_features=True)
    else:
        all_failures, all_metadata = _read_metadata_file(
            all_features_path, "all-features"
        )

    return default_failures + all_failures, default_metadata, all_metadata


def require_no_std() -> list[str]:
    failures: list[str] = []
    bases = [CORE, PORTS, CRYPTO]
    for base in bases:
        if not base.exists():
            continue
        for crate in base.iterdir():
            if not crate.is_dir():
                continue
            lib = crate / "src" / "lib.rs"
            if lib.exists() and "#![no_std]" not in lib.read_text(encoding="utf-8"):
                failures.append(f"{lib.relative_to(ROOT)}: portable library must declare #![no_std]")
    return failures


def _normalise_path(value: str | Path) -> str:
    return str(Path(value).resolve(strict=False))


def _workspace_package_indexes(
    metadata: dict,
) -> tuple[list[str], dict[str, dict], dict[str, str], dict[str, str]]:
    failures: list[str] = []
    packages = {str(package.get("id")): package for package in metadata.get("packages", [])}
    workspace_ids = {str(package_id) for package_id in metadata.get("workspace_members", [])}
    workspace_by_name: dict[str, str] = {}
    workspace_by_directory: dict[str, str] = {}

    for package_id in sorted(workspace_ids):
        package = packages.get(package_id)
        if package is None:
            failures.append(
                f"workspace member {package_id!r} is missing from Cargo metadata packages"
            )
            continue

        name = str(package.get("name", ""))
        if not name:
            failures.append(f"workspace member {package_id!r} has no package name")
            continue
        if name in workspace_by_name:
            failures.append(f"duplicate workspace package name is not supported by policy: {name}")
        workspace_by_name[name] = package_id

        manifest_path = package.get("manifest_path")
        if not isinstance(manifest_path, str):
            failures.append(f"{name}: Cargo metadata has no manifest_path")
            continue
        directory = _normalise_path(Path(manifest_path).parent)
        if directory in workspace_by_directory:
            failures.append(f"multiple workspace packages use manifest directory {directory}")
        workspace_by_directory[directory] = name

        if package.get("source") is not None:
            failures.append(f"{name}: workspace package unexpectedly has external source")

    return failures, packages, workspace_by_name, workspace_by_directory


def validate_workspace_package_policy(metadata: dict) -> list[str]:
    failures, _, workspace_by_name, _ = _workspace_package_indexes(metadata)

    for name in sorted(set(workspace_by_name) - set(PACKAGE_DECLARATION_POLICY)):
        failures.append(f"{name}: unknown workspace package has no reviewed dependency policy")

    for name in sorted(set(PACKAGE_DECLARATION_POLICY) - set(workspace_by_name)):
        failures.append(f"{name}: policy expects workspace package but Cargo metadata does not contain it")

    return failures


def repository_package_manifests() -> tuple[list[str], dict[str, str]]:
    failures: list[str] = []
    manifests: dict[str, str] = {}
    for path in sorted(ROOT.rglob("Cargo.toml")):
        relative = path.relative_to(ROOT)
        if path == ROOT / "Cargo.toml" or relative.parts[0] in {".git", "target"}:
            continue
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as error:
            failures.append(f"{relative}: cannot parse Cargo package manifest: {error}")
            continue
        package = data.get("package")
        if not isinstance(package, dict):
            failures.append(
                f"{relative}: non-root Cargo.toml must be an explicit workspace package manifest"
            )
            continue
        name = package.get("name")
        if not isinstance(name, str) or not name:
            failures.append(f"{relative}: Cargo package manifest has no package.name")
            continue
        manifests[_normalise_path(path)] = name
    return failures, manifests


def validate_repository_manifest_membership(
    metadata: dict, repository_manifests: dict[str, str]
) -> list[str]:
    failures, packages, workspace_by_name, _ = _workspace_package_indexes(metadata)
    workspace_manifests: dict[str, str] = {}
    for name, package_id in workspace_by_name.items():
        manifest_path = packages[package_id].get("manifest_path")
        if isinstance(manifest_path, str):
            workspace_manifests[_normalise_path(manifest_path)] = name

    normalised_repository_manifests = {
        _normalise_path(path): name for path, name in repository_manifests.items()
    }

    for manifest_path, name in sorted(normalised_repository_manifests.items()):
        workspace_name = workspace_manifests.get(manifest_path)
        if workspace_name is None:
            failures.append(
                f"{manifest_path}: repository Cargo package {name} is not a workspace member"
            )
        elif workspace_name != name:
            failures.append(
                f"{manifest_path}: manifest package name {name!r} does not match "
                f"Cargo metadata workspace identity {workspace_name!r}"
            )

    for manifest_path, name in sorted(workspace_manifests.items()):
        if manifest_path not in normalised_repository_manifests:
            failures.append(
                f"{name}: workspace package manifest {manifest_path} is not present in repository scan"
            )

    return failures


def _metadata_declaration(
    dependency: dict, workspace_by_directory: dict[str, str]
) -> DependencyDeclaration:
    actual_package = str(dependency.get("name", ""))
    alias = dependency.get("rename") or actual_package
    path = dependency.get("path")
    path_target = None
    if isinstance(path, str):
        normalised_path = _normalise_path(path)
        path_target = workspace_by_directory.get(
            normalised_path, f"<non-workspace-path:{normalised_path}>"
        )

    kind = dependency.get("kind") or "normal"
    target = dependency.get("target")
    features_value = dependency.get("features", [])
    requested_features = tuple(sorted(str(feature) for feature in features_value))

    return DependencyDeclaration(
        actual_package=actual_package,
        alias=str(alias),
        kind=str(kind),
        target=str(target) if target is not None else None,
        optional=bool(dependency.get("optional", False)),
        source=dependency.get("source"),
        path_target=path_target,
        version_requirement=str(dependency.get("req", "")),
        uses_default_features=bool(dependency.get("uses_default_features", True)),
        requested_features=requested_features,
        registry=dependency.get("registry"),
    )


DECLARATION_FIELD_LABELS = {
    "alias": "local alias/rename",
    "kind": "dependency kind",
    "target": "target condition",
    "optional": "optional",
    "source": "source",
    "path_target": "path target",
    "version_requirement": "version requirement",
    "uses_default_features": "uses_default_features",
    "requested_features": "requested features",
    "registry": "registry",
}


def _declaration_mismatches(
    actual: DependencyDeclaration, expected: DependencyDeclaration
) -> list[str]:
    mismatches: list[str] = []
    for field in fields(DependencyDeclaration):
        if field.name == "actual_package":
            continue
        actual_value = getattr(actual, field.name)
        expected_value = getattr(expected, field.name)
        if actual_value != expected_value:
            label = DECLARATION_FIELD_LABELS[field.name]
            mismatches.append(f"{label} expected {expected_value!r}, got {actual_value!r}")
    return mismatches


def _format_declaration(declaration: DependencyDeclaration) -> str:
    return (
        f"{declaration.alias} (package {declaration.actual_package}, "
        f"kind={declaration.kind}, target={declaration.target!r}, "
        f"optional={declaration.optional})"
    )


def validate_dependency_declarations(metadata: dict) -> list[str]:
    failures, packages, workspace_by_name, workspace_by_directory = (
        _workspace_package_indexes(metadata)
    )

    for package_name, package_id in sorted(workspace_by_name.items()):
        policy = PACKAGE_DECLARATION_POLICY.get(package_name)
        if policy is None:
            continue
        dependencies = packages[package_id].get("dependencies", [])
        if not isinstance(dependencies, list):
            failures.append(f"{package_name}: packages[].dependencies is not a list")
            continue

        for raw_dependency in dependencies:
            if not isinstance(raw_dependency, dict):
                failures.append(f"{package_name}: malformed dependency declaration metadata")
                continue
            actual = _metadata_declaration(raw_dependency, workspace_by_directory)
            if actual in policy:
                continue

            candidates = [
                expected
                for expected in policy
                if expected.actual_package == actual.actual_package
            ]
            if not candidates:
                failures.append(
                    f"{package_name}: unreviewed dependency declaration "
                    f"{_format_declaration(actual)}"
                )
                continue

            best = min(candidates, key=lambda expected: len(_declaration_mismatches(actual, expected)))
            mismatches = "; ".join(_declaration_mismatches(actual, best))
            failures.append(
                f"{package_name}: dependency declaration {_format_declaration(actual)} "
                f"violates allowlist: {mismatches}"
            )

        actual_declarations = {
            _metadata_declaration(dependency, workspace_by_directory)
            for dependency in dependencies
            if isinstance(dependency, dict)
        }
        for missing in sorted(policy - actual_declarations, key=repr):
            failures.append(
                f"{package_name}: reviewed dependency declaration is missing: "
                f"{_format_declaration(missing)}"
            )

    return failures


def _version_from_exact_requirement(requirement: str) -> str | None:
    if requirement.startswith("=") and requirement.count("=") == 1:
        version = requirement[1:]
        if version:
            return version
    return None


def validate_resolved_direct_dependencies(metadata: dict, graph_name: str) -> list[str]:
    failures, packages, workspace_by_name, _ = _workspace_package_indexes(metadata)
    workspace_ids = set(workspace_by_name.values())
    nodes = {
        str(node.get("id")): node
        for node in (metadata.get("resolve") or {}).get("nodes", [])
    }

    for package_name, package_id in sorted(workspace_by_name.items()):
        policy = PACKAGE_DECLARATION_POLICY.get(package_name)
        if policy is None:
            continue
        node = nodes.get(package_id)
        if node is None:
            failures.append(f"{graph_name}: {package_name}: missing resolved dependency node")
            continue

        allowed_workspace = {
            declaration.path_target
            for declaration in policy
            if declaration.path_target is not None
        }
        allowed_external = {
            (
                declaration.actual_package,
                _version_from_exact_requirement(declaration.version_requirement),
                declaration.source,
            )
            for declaration in policy
            if declaration.path_target is None
        }

        for dependency in node.get("deps", []):
            target_id = str(dependency.get("pkg"))
            target = packages.get(target_id)
            if target is None:
                failures.append(
                    f"{graph_name}: {package_name}: resolved dependency {target_id!r} "
                    "is missing from packages"
                )
                continue

            target_name = str(target.get("name", ""))
            if target_id in workspace_ids:
                if target_name not in allowed_workspace:
                    failures.append(
                        f"{graph_name}: {package_name}: forbidden workspace dependency "
                        f"on {target_name}"
                    )
                continue

            identity = (
                target_name,
                str(target.get("version", "")),
                target.get("source"),
            )
            if identity not in allowed_external:
                failures.append(
                    f"{graph_name}: {package_name}: unreviewed external direct dependency "
                    f"{identity[0]} {identity[1]} from {identity[2]!r}"
                )

    return failures


def validate_dependency_policy(metadata: dict, graph_name: str = "fixture") -> list[str]:
    """Run production declaration and resolved-edge policy against fixture-shaped data."""

    failures: list[str] = []
    failures.extend(validate_workspace_package_policy(metadata))
    failures.extend(validate_dependency_declarations(metadata))
    failures.extend(validate_resolved_direct_dependencies(metadata, graph_name))
    return failures


def validate_metadata_declaration_consistency(
    default_metadata: dict, all_features_metadata: dict
) -> list[str]:
    failures: list[str] = []

    def snapshot(metadata: dict) -> dict[str, tuple[DependencyDeclaration, ...]]:
        _, packages, workspace_by_name, workspace_by_directory = (
            _workspace_package_indexes(metadata)
        )
        return {
            name: tuple(
                sorted(
                    (
                        _metadata_declaration(dependency, workspace_by_directory)
                        for dependency in packages[package_id].get("dependencies", [])
                    ),
                    key=repr,
                )
            )
            for name, package_id in workspace_by_name.items()
        }

    if snapshot(default_metadata) != snapshot(all_features_metadata):
        failures.append(
            "default and all-features Cargo metadata disagree on workspace dependency declarations"
        )
    return failures


def validate_resolved_feature_policy(metadata: dict, graph_name: str) -> list[str]:
    failures: list[str] = []
    packages = {str(package.get("id")): package for package in metadata.get("packages", [])}
    nodes = {
        str(node.get("id")): node
        for node in (metadata.get("resolve") or {}).get("nodes", [])
    }

    feature_unions: dict[tuple[str, str, str | None], set[str]] = {}
    for package_id, node in nodes.items():
        package = packages.get(package_id)
        if package is None:
            failures.append(
                f"{graph_name}: resolved feature node {package_id!r} is missing from packages"
            )
            continue
        identity = (
            str(package.get("name", "")),
            str(package.get("version", "")),
            package.get("source"),
        )
        feature_unions.setdefault(identity, set()).update(
            str(feature) for feature in node.get("features", [])
        )

    for identity, expected in RESOLVED_FEATURE_POLICY.items():
        if identity not in feature_unions:
            continue
        actual = frozenset(feature_unions[identity])
        if actual != expected:
            failures.append(
                f"{graph_name}: resolved feature union for {identity[0]} {identity[1]} "
                f"expected {sorted(expected)!r}, got {sorted(actual)!r}"
            )

    for (name, version, source), enabled in feature_unions.items():
        if _canonical_package_name(name) != "ed25519-dalek":
            continue
        forbidden = sorted(enabled & ED25519_FORBIDDEN_FEATURES)
        if forbidden:
            failures.append(
                f"{graph_name}: ed25519-dalek {version} from {source!r} resolved "
                f"forbidden features {forbidden}"
            )

    return failures


def _canonical_package_name(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def _iter_manifest_dependency_specs(data: dict):
    tables = (
        ("dependencies", "normal"),
        ("dev-dependencies", "dev"),
        ("build-dependencies", "build"),
    )
    for table_name, kind in tables:
        table = data.get(table_name, {})
        if isinstance(table, dict):
            for dependency_key, spec in table.items():
                yield kind, None, str(dependency_key), spec

    targets = data.get("target", {})
    if not isinstance(targets, dict):
        return
    for target_condition, target_data in targets.items():
        if not isinstance(target_data, dict):
            continue
        for table_name, kind in tables:
            table = target_data.get(table_name, {})
            if isinstance(table, dict):
                for dependency_key, spec in table.items():
                    yield kind, str(target_condition), str(dependency_key), spec


def forbidden_crypto_features_in_manifest_texts(
    manifest_texts: dict[str, str]
) -> list[str]:
    failures: list[str] = []
    for manifest_name, text in manifest_texts.items():
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError as error:
            failures.append(f"{manifest_name}: cannot parse Cargo manifest: {error}")
            continue

        for kind, target, dependency_key, spec in _iter_manifest_dependency_specs(data):
            if isinstance(spec, str):
                actual_package = dependency_key
                uses_default_features = True
                requested_features: set[str] = set()
            elif isinstance(spec, dict):
                actual_package = str(spec.get("package", dependency_key))
                uses_default_features = bool(spec.get("default-features", True))
                requested_features = {
                    str(feature) for feature in spec.get("features", [])
                }
            else:
                continue

            canonical_name = _canonical_package_name(actual_package)
            policy = MANIFEST_FEATURE_POLICY.get(canonical_name)
            if policy is None:
                continue
            expected_default_features, allowed_features = policy
            context = (
                f"{manifest_name}: {kind} dependency {dependency_key!r} "
                f"(package {actual_package!r}, target={target!r})"
            )
            extra = sorted(requested_features - allowed_features)
            if extra:
                failures.append(f"{context} requests forbidden/unreviewed features {extra}")
            if uses_default_features != expected_default_features:
                failures.append(
                    f"{context} uses_default_features expected "
                    f"{expected_default_features}, got {uses_default_features}"
                )

    return failures


def _repository_cargo_manifest_paths() -> list[Path]:
    paths: list[Path] = []
    for path in sorted(ROOT.rglob("Cargo.toml")):
        relative = path.relative_to(ROOT)
        if relative.parts[0] in {".git", "target"}:
            continue
        paths.append(path)
    return paths


def forbidden_crypto_features() -> list[str]:
    manifest_texts = {
        str(path.relative_to(ROOT)): path.read_text(encoding="utf-8")
        for path in _repository_cargo_manifest_paths()
    }
    return forbidden_crypto_features_in_manifest_texts(manifest_texts)


def forbid_secret_wrappers_outside_crypto_boundary() -> list[str]:
    failures: list[str] = []
    roots = [APPS, CORE, PORTS, PLATFORM, ROOT / "crates" / "protocol"]
    for base in roots:
        if not base.exists():
            continue
        for path in base.rglob("*.rs"):
            text = path.read_text(encoding="utf-8")
            for secret_name in SECRET_WRAPPERS:
                if secret_name in text:
                    failures.append(
                        f"{path.relative_to(ROOT)}: secret wrapper {secret_name} must stay inside "
                        "the crypto/keystore boundary"
                    )
    return failures


def _trait_leaf(path: str) -> str:
    return path.strip().split("::")[-1].strip()


def _secret_type_names(text: str) -> set[str]:
    names = set(SECRET_WRAPPERS)
    changed = True
    while changed:
        changed = False
        for match in TYPE_ALIAS_RE.finditer(text):
            target = _trait_leaf(match.group("target"))
            alias = match.group("alias")
            if target in names and alias not in names:
                names.add(alias)
                changed = True
    return names


def secret_wrapper_trait_check_sources(source_files: dict[str, str]) -> list[str]:
    """Conservatively reject textual forbidden traits for secret wrappers.

    The scan covers the current declaration macro, direct derives (including
    intervening attributes), qualified/aliased explicit trait impls, and type
    aliases. It does not expand arbitrary declarative or procedural macros.
    Independent compile-fail doctests therefore provide compiler-level evidence
    for the resulting Clone, Copy, and Debug trait bounds.
    """

    failures: list[str] = []
    combined = "\n".join(source_files.values())

    for name in sorted(SECRET_WRAPPERS):
        declared = bool(
            re.search(rf"\bsecret32_type!\s*\(\s*{re.escape(name)}\s*\)\s*;", combined)
            or re.search(rf"\bstruct\s+{re.escape(name)}\b", combined)
        )
        if not declared:
            failures.append(f"icc-crypto-api: expected secret wrapper declaration missing: {name}")

    for path, text in source_files.items():
        macro_match = SECRET_MACRO_RE.search(text)
        if macro_match:
            for derive in DERIVE_RE.finditer(macro_match.group("body")):
                traits = {_trait_leaf(item) for item in derive.group("traits").split(",")}
                for trait in sorted(traits & FORBIDDEN_SECRET_TRAITS):
                    failures.append(f"{path}: secret32_type macro derives forbidden trait {trait}")

        secret_names = _secret_type_names(text)
        trait_aliases = {
            match.group("alias"): _trait_leaf(match.group("trait"))
            for match in TRAIT_IMPORT_ALIAS_RE.finditer(text)
        }

        for name in sorted(SECRET_WRAPPERS):
            declaration_re = re.compile(
                rf"#\s*\[\s*derive\s*\((?P<traits>[^)]*)\)\s*\]\s*"
                rf"(?:#\s*\[[^\]]*\]\s*)*"
                rf"(?:pub(?:\([^)]*\))?\s+)?struct\s+{re.escape(name)}\b",
                re.DOTALL,
            )
            for derive in declaration_re.finditer(text):
                traits = {_trait_leaf(item) for item in derive.group("traits").split(",")}
                for trait in sorted(traits & FORBIDDEN_SECRET_TRAITS):
                    failures.append(f"{path}: {name} derives forbidden trait {trait}")

        for impl in IMPL_RE.finditer(text):
            target = _trait_leaf(impl.group("target"))
            if target not in secret_names:
                continue
            trait_token = _trait_leaf(impl.group("trait"))
            trait = trait_aliases.get(trait_token, trait_token)
            if trait in FORBIDDEN_SECRET_TRAITS:
                failures.append(f"{path}: {target} explicitly implements forbidden trait {trait}")

    return failures


def secret_wrapper_trait_check() -> list[str]:
    source_files: dict[str, str] = {}
    src = CRYPTO_API / "src"
    if not src.exists():
        return ["icc-crypto-api: src directory missing"]
    for path in sorted(src.rglob("*.rs")):
        source_files[str(path.relative_to(ROOT))] = path.read_text(encoding="utf-8")
    return secret_wrapper_trait_check_sources(source_files)


def first_party_unsafe_check() -> list[str]:
    failures: list[str] = []
    roots = [CORE, PORTS, CRYPTO, PLATFORM, APPS]
    for base in roots:
        if not base.exists():
            continue
        for path in base.rglob("*.rs"):
            text = path.read_text(encoding="utf-8")
            if UNSAFE_RE.search(text):
                failures.append(
                    f"{path.relative_to(ROOT)}: first-party production unsafe requires an explicit ADR"
                )
    return failures


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--default-metadata", type=Path)
    parser.add_argument("--all-features-metadata", type=Path)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    failures: list[str] = []
    metadata_failures, default_metadata, all_features_metadata = (
        require_lockfile_and_locked_metadata(
            args.default_metadata, args.all_features_metadata
        )
    )
    failures.extend(metadata_failures)

    failures.extend(check_tree(CORE, FORBIDDEN_CORE_TOKENS))
    failures.extend(check_tree(PORTS, FORBIDDEN_PORT_TOKENS))
    failures.extend(check_tree(CRYPTO_API, FORBIDDEN_CRYPTO_API_TOKENS))
    failures.extend(require_no_std())
    failures.extend(forbidden_crypto_features())
    failures.extend(forbid_secret_wrappers_outside_crypto_boundary())
    failures.extend(secret_wrapper_trait_check())
    failures.extend(first_party_unsafe_check())

    manifest_scan_failures, repository_manifests = repository_package_manifests()
    failures.extend(manifest_scan_failures)

    if default_metadata is not None:
        failures.extend(validate_workspace_package_policy(default_metadata))
        failures.extend(validate_dependency_declarations(default_metadata))
        failures.extend(
            validate_resolved_direct_dependencies(default_metadata, "default")
        )
        failures.extend(validate_resolved_feature_policy(default_metadata, "default"))
        failures.extend(
            validate_repository_manifest_membership(default_metadata, repository_manifests)
        )

    if all_features_metadata is not None:
        failures.extend(
            validate_resolved_direct_dependencies(all_features_metadata, "all-features")
        )
        failures.extend(
            validate_resolved_feature_policy(all_features_metadata, "all-features")
        )

    if default_metadata is not None and all_features_metadata is not None:
        failures.extend(
            validate_metadata_declaration_consistency(default_metadata, all_features_metadata)
        )

    if failures:
        print("Architecture boundary violations:")
        for item in failures:
            print(f"  - {item}")
        return 1

    print("Architecture boundary check: PASS")
    print("Manifest dependency declaration allowlist check: PASS")
    print("Repository Cargo package workspace-membership check: PASS")
    print("Default locked dependency graph and feature check: PASS")
    print("All-features locked dependency graph and feature-union check: PASS")
    print("Secret material boundary check: PASS")
    print("Secret forbidden-trait source-pattern scan: PASS")
    print("First-party production unsafe scan: PASS")
    print(
        "NOTE: source-pattern checks are conservative text analysis and do not "
        "expand arbitrary macros; they are not Rust AST, compiler, visibility, "
        "runtime-sandbox, or formal proofs."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
