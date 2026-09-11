#!/usr/bin/env python3
"""Phase 2 architecture/dependency boundary guard.

This checker deliberately combines conservative source-token checks with Cargo's
resolved dependency graph from `cargo metadata --locked`. It is NOT a Rust AST
validator and does not claim to prove absence of every possible boundary escape.
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

SECRET_WRAPPERS = {
    "Ed25519SigningSeed",
    "X25519Secret",
    "SharedSecret32",
    "AeadKey32",
    "DerivedKey32",
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

# Approved external direct dependencies for each current Phase 2 layer. This is a
# direct-edge policy; cargo-deny separately evaluates the resolved transitive graph.
APPROVED_EXTERNAL: dict[str, set[str]] = {
    "core": set(),
    "ports": set(),
    "crypto_api": {"zeroize"},
    "crypto_provider": {
        "chacha20poly1305",
        "ed25519-dalek",
        "hkdf",
        "sha2",
        "x25519-dalek",
    },
    "platform": {"getrandom"},
    "testing": set(),
    "app": set(),
    "test": set(),
    "other": set(),
}

ALLOWED_WORKSPACE_EDGES: dict[str, set[str]] = {
    "core": {"core", "ports", "crypto_api"},
    "ports": {"core", "ports", "crypto_api"},
    "crypto_api": {"core", "crypto_api"},
    "crypto_provider": {"core", "crypto_api", "crypto_provider"},
    "platform": {"core", "ports"},
    "testing": {"core", "ports", "testing"},
    "app": {"core", "ports", "crypto_api", "crypto_provider", "platform"},
    "test": {"core", "ports", "testing", "crypto_api", "crypto_provider"},
    "other": set(),
}

UNSAFE_RE = re.compile(r"\bunsafe\s*(?:\{|fn\b|impl\b|trait\b|extern\b)")


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


def classify(path: Path) -> str:
    rel = path.resolve().relative_to(ROOT.resolve()).parts
    if rel[:2] == ("crates", "core"):
        return "core"
    if rel[:2] == ("crates", "ports"):
        return "ports"
    if rel[:3] == ("crates", "crypto", "icc-crypto-api"):
        return "crypto_api"
    if rel[:3] == ("crates", "crypto", "icc-crypto-rust"):
        return "crypto_provider"
    if rel[:2] == ("crates", "platform"):
        return "platform"
    if rel[:2] == ("crates", "testing"):
        return "testing"
    if rel and rel[0] == "apps":
        return "app"
    if rel and rel[0] == "tests":
        return "test"
    return "other"


def dependency_boundary_check(metadata: dict) -> list[str]:
    failures: list[str] = []
    workspace_ids = set(metadata.get("workspace_members", []))
    packages = {pkg["id"]: pkg for pkg in metadata.get("packages", [])}
    workspace_names = {
        pkg["name"]: classify(Path(pkg["manifest_path"]).parent)
        for pkg_id, pkg in packages.items()
        if pkg_id in workspace_ids
    }

    for package_id in workspace_ids:
        package = packages[package_id]
        src_kind = classify(Path(package["manifest_path"]).parent)
        package_name = package["name"]
        allowed_workspace = ALLOWED_WORKSPACE_EDGES.get(src_kind, set())
        allowed_external = APPROVED_EXTERNAL.get(src_kind, set())

        for dependency in package.get("dependencies", []):
            dep_name = dependency["name"]
            dep_path = dependency.get("path")
            if dep_path is not None and dep_name in workspace_names:
                dst_kind = workspace_names[dep_name]
                if dst_kind not in allowed_workspace:
                    failures.append(
                        f"{package_name}: {src_kind} crate depends on forbidden "
                        f"workspace layer {dst_kind} via {dep_name}"
                    )
            elif dep_name not in allowed_external:
                failures.append(
                    f"{package_name}: unreviewed external direct dependency {dep_name!r} "
                    f"is not approved for layer {src_kind}"
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


def secret_wrapper_derive_check() -> list[str]:
    failures: list[str] = []
    lib = CRYPTO_API / "src" / "lib.rs"
    text = lib.read_text(encoding="utf-8")
    try:
        macro = text.split("macro_rules! secret32_type", 1)[1].split(
            "secret32_type!(Ed25519SigningSeed);", 1
        )[0]
    except IndexError:
        return ["icc-crypto-api: secret32_type macro or Ed25519SigningSeed declaration missing"]

    forbidden = ("#[derive", "impl Clone", "impl Copy", "impl Debug", "Serialize", "Deserialize")
    for token in forbidden:
        if token in macro:
            failures.append(
                f"icc-crypto-api secret32_type macro contains forbidden trait/derive token {token!r}"
            )
    for name in SECRET_WRAPPERS:
        if f"secret32_type!({name});" not in text:
            failures.append(f"icc-crypto-api: expected secret wrapper declaration missing: {name}")
    return failures


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
    failures.extend(secret_wrapper_derive_check())
    failures.extend(first_party_unsafe_check())

    if metadata is not None:
        failures.extend(dependency_boundary_check(metadata))

    if failures:
        print("Architecture boundary violations:")
        for item in failures:
            print(f"  - {item}")
        return 1

    print("Architecture boundary check: PASS")
    print("Locked dependency graph check: PASS")
    print("Secret material boundary check: PASS")
    print("First-party production unsafe scan: PASS")
    print("NOTE: this checker is conservative source/metadata analysis, not a Rust AST proof.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
