#!/usr/bin/env python3
"""Dependency/boundary guard for Phase 2.

This is intentionally conservative and dependency-free. It is not a Rust parser.
It catches obvious architecture regressions before compiler/CI checks.
"""

from pathlib import Path
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "crates" / "core"
PORTS = ROOT / "crates" / "ports"
CRYPTO_API = ROOT / "crates" / "crypto" / "icc-crypto-api"

FORBIDDEN_CORE_TOKENS = {
    "std::fs": "filesystem access belongs in an adapter",
    "std::net": "network access belongs in an adapter",
    "std::env": "environment access belongs in the composition layer",
    "std::process": "process creation belongs in runtime/platform code",
    "std::os": "OS-specific APIs cannot enter Domain Core",
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


def check_tree(base: Path, rules: dict[str, str]) -> list[str]:
    failures = []
    for path in base.rglob("*.rs"):
        text = path.read_text(encoding="utf-8")
        for token, reason in rules.items():
            if token in text:
                failures.append(f"{path.relative_to(ROOT)}: found {token!r} — {reason}")
    return failures


def require_no_std() -> list[str]:
    failures = []
    bases = [CORE, PORTS, ROOT / "crates" / "crypto"]
    for base in bases:
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
    if rel[:3] == ("crates", "platform", "linux"):
        return "platform"
    if rel[:2] == ("crates", "testing"):
        return "testing"
    if rel and rel[0] == "apps":
        return "app"
    if rel and rel[0] == "tests":
        return "test"
    return "other"


def dependency_boundary_check() -> list[str]:
    failures = []
    manifests = list(ROOT.rglob("Cargo.toml"))

    for manifest in manifests:
        if manifest == ROOT / "Cargo.toml":
            continue
        src_kind = classify(manifest.parent)
        data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        package_name = data.get("package", {}).get("name", str(manifest.parent))
        for table_name in ("dependencies", "dev-dependencies", "build-dependencies"):
            for dep_name, spec in data.get(table_name, {}).items():
                if not isinstance(spec, dict) or "path" not in spec:
                    continue
                target = (manifest.parent / spec["path"]).resolve()
                dst_kind = classify(target)

                if src_kind == "core" and dst_kind not in {"core", "ports", "crypto_api"}:
                    failures.append(
                        f"{package_name}: core crate depends on forbidden {dst_kind} crate {dep_name}"
                    )
                if src_kind == "ports" and dst_kind not in {"core", "ports", "crypto_api"}:
                    failures.append(
                        f"{package_name}: ports crate depends on forbidden {dst_kind} crate {dep_name}"
                    )
                if src_kind == "crypto_api" and dst_kind not in {"core", "crypto_api"}:
                    failures.append(
                        f"{package_name}: crypto API depends on forbidden {dst_kind} crate {dep_name}"
                    )
                if src_kind == "crypto_provider" and dst_kind not in {"core", "crypto_api", "crypto_provider"}:
                    failures.append(
                        f"{package_name}: crypto provider depends on forbidden {dst_kind} crate {dep_name}"
                    )

    return failures


def forbid_crypto_implementation_in_domain_core() -> list[str]:
    failures = []
    tokens = ("ed25519-dalek", "x25519-dalek", "chacha20poly1305", "sha2", "hkdf")
    for manifest in CORE.rglob("Cargo.toml"):
        data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        for table_name in ("dependencies", "dev-dependencies", "build-dependencies"):
            deps = data.get(table_name, {})
            for token in tokens:
                if token in deps:
                    failures.append(
                        f"{manifest.relative_to(ROOT)}: Domain Core must depend on icc-crypto-api, not {token}"
                    )
    return failures


def main() -> int:
    failures = []
    failures.extend(check_tree(CORE, FORBIDDEN_CORE_TOKENS))
    failures.extend(check_tree(PORTS, FORBIDDEN_PORT_TOKENS))
    failures.extend(check_tree(CRYPTO_API, FORBIDDEN_CRYPTO_API_TOKENS))
    failures.extend(require_no_std())
    failures.extend(dependency_boundary_check())
    failures.extend(forbid_crypto_implementation_in_domain_core())

    if failures:
        print("Architecture boundary violations:")
        for item in failures:
            print(f"  - {item}")
        return 1

    print("Architecture boundary check: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
