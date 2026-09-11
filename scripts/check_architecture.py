#!/usr/bin/env python3
"""Phase 2 architecture/dependency boundary guard.

This checker combines conservative source analysis with Cargo's resolved
dependency graph from `cargo metadata --locked`. It is deliberately fail-closed
for workspace package classification and direct dependency review.

It is NOT a Rust parser, compiler visibility proof, runtime sandbox, or formal
verification system.
"""

from __future__ import annotations

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

# Phase 0.3 dependency matrix implemented as exact current-package policy.
# Every workspace package must appear here. Adding a package without a reviewed
# rule fails closed.
#
# `icc-identity-core -> icc-platform-api` is an explicit reviewed Phase 1 Port
# dependency-inversion exception. It does not widen the policy of other L2 crates.
PACKAGE_POLICY: dict[str, dict[str, set]] = {
    "icc-types": {"workspace": set(), "external": set()},
    "icc-error": {"workspace": set(), "external": set()},
    "icc-rights": {"workspace": set(), "external": set()},
    "icc-capability-core": {
        "workspace": {"icc-error", "icc-rights", "icc-types"},
        "external": set(),
    },
    "icc-identity-core": {
        "workspace": {"icc-error", "icc-platform-api", "icc-types"},
        "external": set(),
    },
    "icc-platform-api": {
        "workspace": {"icc-error", "icc-types"},
        "external": set(),
    },
    "icc-crypto-api": {
        "workspace": set(),
        "external": {("zeroize", "1.9.0", CRATES_IO_SOURCE)},
    },
    "icc-crypto-rust": {
        "workspace": {"icc-crypto-api"},
        "external": {
            ("chacha20poly1305", "0.11.0", CRATES_IO_SOURCE),
            ("ed25519-dalek", "3.0.0", CRATES_IO_SOURCE),
            ("hkdf", "0.13.0", CRATES_IO_SOURCE),
            ("sha2", "0.11.0", CRATES_IO_SOURCE),
            ("x25519-dalek", "3.0.0", CRATES_IO_SOURCE),
        },
    },
    "icc-test-support": {
        "workspace": {"icc-error", "icc-platform-api", "icc-types"},
        "external": set(),
    },
    "icc-platform-linux": {
        "workspace": {"icc-error", "icc-platform-api", "icc-types"},
        "external": {("getrandom", "0.4.3", CRATES_IO_SOURCE)},
    },
    "indie-cli": {
        "workspace": {
            "icc-capability-core",
            "icc-identity-core",
            "icc-platform-api",
            "icc-platform-linux",
            "icc-rights",
            "icc-types",
        },
        "external": set(),
    },
    "icc-architecture-tests": {
        "workspace": {
            "icc-capability-core",
            "icc-identity-core",
            "icc-platform-api",
            "icc-rights",
            "icc-test-support",
            "icc-types",
        },
        "external": set(),
    },
}

UNSAFE_RE = re.compile(r"\bunsafe\s*(?:\{|fn\b|impl\b|trait\b|extern\b)")
DERIVE_RE = re.compile(r"#\s*\[\s*derive\s*\((?P<traits>[^)]*)\)\s*\]", re.DOTALL)
SECRET_MACRO_RE = re.compile(
    r"macro_rules!\s+secret32_type\b(?P<body>.*?)(?=secret32_type!\s*\()",
    re.DOTALL,
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


def require_lockfile_and_locked_metadata() -> tuple[list[str], dict | None]:
    if not LOCKFILE.is_file():
        return ["Cargo.lock is required for reproducible Phase 2 dependency resolution"], None

    try:
        proc = subprocess.run(
            ["cargo", "metadata", "--locked", "--format-version", "1"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        return ["cargo is required to validate the locked dependency graph"], None

    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or "unknown cargo metadata failure"
        return [f"cargo metadata --locked failed: {detail}"], None

    try:
        return [], json.loads(proc.stdout)
    except json.JSONDecodeError as error:
        return [f"cargo metadata returned invalid JSON: {error}"], None


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


def validate_dependency_policy(metadata: dict) -> list[str]:
    """Validate resolved direct edges against the exact package policy.

    This consumes Cargo metadata-shaped data and is pure so negative fixtures can
    exercise policy behavior without editing real manifests.
    """
    failures: list[str] = []
    packages = {pkg["id"]: pkg for pkg in metadata.get("packages", [])}
    workspace_ids = set(metadata.get("workspace_members", []))
    workspace_by_name: dict[str, str] = {}

    for package_id in workspace_ids:
        package = packages.get(package_id)
        if package is None:
            failures.append(f"workspace member {package_id!r} is missing from Cargo metadata packages")
            continue
        name = package["name"]
        if name in workspace_by_name:
            failures.append(f"duplicate workspace package name is not supported by policy: {name}")
        workspace_by_name[name] = package_id

    for name in sorted(set(workspace_by_name) - set(PACKAGE_POLICY)):
        failures.append(f"{name}: unknown workspace package has no reviewed dependency policy")

    for name in sorted(set(PACKAGE_POLICY) - set(workspace_by_name)):
        failures.append(f"{name}: policy expects workspace package but Cargo metadata does not contain it")

    resolve = metadata.get("resolve") or {}
    nodes = {node["id"]: node for node in resolve.get("nodes", [])}

    for package_name, package_id in sorted(workspace_by_name.items()):
        policy = PACKAGE_POLICY.get(package_name)
        if policy is None:
            continue

        node = nodes.get(package_id)
        if node is None:
            failures.append(f"{package_name}: missing resolved dependency node")
            continue

        for dependency in node.get("deps", []):
            target_id = dependency.get("pkg")
            target = packages.get(target_id)
            if target is None:
                failures.append(
                    f"{package_name}: resolved dependency {target_id!r} is missing from packages"
                )
                continue

            target_name = target["name"]
            if target_id in workspace_ids:
                if target_name not in policy["workspace"]:
                    failures.append(
                        f"{package_name}: forbidden workspace dependency on {target_name}"
                    )
                continue

            identity = (target_name, str(target.get("version", "")), target.get("source"))
            if identity not in policy["external"]:
                failures.append(
                    f"{package_name}: unreviewed external direct dependency "
                    f"{target_name} {identity[1]} from {identity[2]!r}"
                )

    return failures


def forbidden_crypto_features() -> list[str]:
    failures: list[str] = []
    forbidden = {"hazmat", "legacy_compatibility"}
    for manifest in ROOT.rglob("Cargo.toml"):
        data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        for table_name in ("dependencies", "dev-dependencies", "build-dependencies"):
            spec = data.get(table_name, {}).get("ed25519-dalek")
            if not isinstance(spec, dict):
                continue
            enabled = set(spec.get("features", []))
            bad = sorted(enabled & forbidden)
            if bad:
                failures.append(
                    f"{manifest.relative_to(ROOT)}: forbidden ed25519-dalek features enabled: {bad}"
                )
    return failures


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


def secret_wrapper_trait_check_sources(source_files: dict[str, str]) -> list[str]:
    """Conservatively reject forbidden traits for secret wrappers.

    This scans every provided Rust source file. It covers the current macro-based
    declarations, direct struct derives, and ordinary/qualified explicit impls.
    It is not a complete Rust grammar parser.
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

        for name in sorted(SECRET_WRAPPERS):
            declaration_re = re.compile(
                rf"#\s*\[\s*derive\s*\((?P<traits>[^)]*)\)\s*\]\s*"
                rf"(?:pub(?:\([^)]*\))?\s+)?struct\s+{re.escape(name)}\b",
                re.DOTALL,
            )
            for derive in declaration_re.finditer(text):
                traits = {_trait_leaf(item) for item in derive.group("traits").split(",")}
                for trait in sorted(traits & FORBIDDEN_SECRET_TRAITS):
                    failures.append(f"{path}: {name} derives forbidden trait {trait}")

            impl_re = re.compile(
                rf"\bimpl(?:\s*<[^{{}};]*>)?\s+"
                rf"(?P<trait>(?:(?:[A-Za-z_][A-Za-z0-9_]*)::)*"
                rf"(?:Copy|Clone|Debug|Serialize|Deserialize))\s+for\s+"
                rf"(?:(?:[A-Za-z_][A-Za-z0-9_]*)::)*{re.escape(name)}\b"
            )
            for impl in impl_re.finditer(text):
                trait = _trait_leaf(impl.group("trait"))
                failures.append(f"{path}: {name} explicitly implements forbidden trait {trait}")

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


def main() -> int:
    failures: list[str] = []
    metadata_failures, metadata = require_lockfile_and_locked_metadata()
    failures.extend(metadata_failures)

    failures.extend(check_tree(CORE, FORBIDDEN_CORE_TOKENS))
    failures.extend(check_tree(PORTS, FORBIDDEN_PORT_TOKENS))
    failures.extend(check_tree(CRYPTO_API, FORBIDDEN_CRYPTO_API_TOKENS))
    failures.extend(require_no_std())
    failures.extend(forbidden_crypto_features())
    failures.extend(forbid_secret_wrappers_outside_crypto_boundary())
    failures.extend(secret_wrapper_trait_check())
    failures.extend(first_party_unsafe_check())

    if metadata is not None:
        failures.extend(validate_dependency_policy(metadata))

    if failures:
        print("Architecture boundary violations:")
        for item in failures:
            print(f"  - {item}")
        return 1

    print("Architecture boundary check: PASS")
    print("Locked dependency graph check: PASS")
    print("Per-package dependency policy check: PASS")
    print("Secret material boundary check: PASS")
    print("Secret forbidden-trait source scan: PASS")
    print("First-party production unsafe scan: PASS")
    print(
        "NOTE: this checker is conservative source/metadata analysis, "
        "not a Rust AST, visibility, runtime-sandbox, or formal proof."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
