#!/usr/bin/env python3
"""Negative/self-tests for the Phase 2 architecture checker."""

from __future__ import annotations

import unittest

import check_architecture as arch


def package_id(name: str) -> str:
    return f"path+file:///fixture/{name}#0.2.0"


def external_id(name: str, version: str) -> str:
    return f"{arch.CRATES_IO_SOURCE}#{name}@{version}"


def metadata_from_policy() -> dict:
    packages: list[dict] = []
    nodes: list[dict] = []
    workspace_members: list[str] = []

    for name in arch.PACKAGE_POLICY:
        pid = package_id(name)
        workspace_members.append(pid)
        packages.append(
            {
                "id": pid,
                "name": name,
                "version": "0.2.0",
                "source": None,
                "manifest_path": f"/fixture/{name}/Cargo.toml",
            }
        )
        nodes.append({"id": pid, "deps": []})

    external_packages: dict[tuple[str, str, str], str] = {}
    for policy in arch.PACKAGE_POLICY.values():
        for name, version, source in policy["external"]:
            key = (name, version, source)
            if key in external_packages:
                continue
            pid = external_id(name, version)
            external_packages[key] = pid
            packages.append(
                {
                    "id": pid,
                    "name": name,
                    "version": version,
                    "source": source,
                    "manifest_path": f"/registry/{name}-{version}/Cargo.toml",
                }
            )
            nodes.append({"id": pid, "deps": []})

    node_by_id = {node["id"]: node for node in nodes}
    for source_name, policy in arch.PACKAGE_POLICY.items():
        source_node = node_by_id[package_id(source_name)]
        for target_name in policy["workspace"]:
            source_node["deps"].append(
                {
                    "name": target_name.replace("-", "_"),
                    "pkg": package_id(target_name),
                    "dep_kinds": [{"kind": None, "target": None}],
                }
            )
        for name, version, source in policy["external"]:
            source_node["deps"].append(
                {
                    "name": name.replace("-", "_"),
                    "pkg": external_packages[(name, version, source)],
                    "dep_kinds": [{"kind": None, "target": None}],
                }
            )

    return {
        "packages": packages,
        "workspace_members": workspace_members,
        "resolve": {"nodes": nodes},
    }


def add_workspace_edge(metadata: dict, source: str, target: str, alias: str | None = None) -> None:
    node = next(node for node in metadata["resolve"]["nodes"] if node["id"] == package_id(source))
    node["deps"].append(
        {
            "name": alias or target.replace("-", "_"),
            "pkg": package_id(target),
            "dep_kinds": [{"kind": None, "target": None}],
        }
    )


def add_external_edge(
    metadata: dict,
    source: str,
    name: str,
    version: str = "99.0.0",
    registry: str = arch.CRATES_IO_SOURCE,
) -> None:
    pid = external_id(name, version)
    metadata["packages"].append(
        {
            "id": pid,
            "name": name,
            "version": version,
            "source": registry,
            "manifest_path": f"/registry/{name}-{version}/Cargo.toml",
        }
    )
    metadata["resolve"]["nodes"].append({"id": pid, "deps": []})
    node = next(node for node in metadata["resolve"]["nodes"] if node["id"] == package_id(source))
    node["deps"].append(
        {
            "name": name.replace("-", "_"),
            "pkg": pid,
            "dep_kinds": [{"kind": None, "target": None}],
        }
    )


def minimal_secret_sources() -> dict[str, str]:
    return {
        "crates/crypto/icc-crypto-api/src/lib.rs": """
macro_rules! secret32_type {
    ($name:ident) => {
        pub struct $name([u8; 32]);
    };
}
secret32_type!(Ed25519SigningSeed);
secret32_type!(X25519Secret);
secret32_type!(SharedSecret32);
secret32_type!(AeadKey32);
secret32_type!(DerivedKey32);
"""
    }


class DependencyPolicyTests(unittest.TestCase):
    def assert_rejected(self, metadata: dict, needle: str) -> None:
        failures = arch.validate_dependency_policy(metadata)
        self.assertTrue(
            any(needle in failure for failure in failures),
            f"expected rejection containing {needle!r}, got {failures!r}",
        )

    def test_current_reviewed_policy_fixture_is_accepted(self) -> None:
        self.assertEqual(arch.validate_dependency_policy(metadata_from_policy()), [])

    def test_l0_to_l2_is_rejected(self) -> None:
        metadata = metadata_from_policy()
        add_workspace_edge(metadata, "icc-types", "icc-identity-core")
        self.assert_rejected(metadata, "icc-types: forbidden workspace dependency on icc-identity-core")

    def test_l0_to_port_is_rejected(self) -> None:
        metadata = metadata_from_policy()
        add_workspace_edge(metadata, "icc-types", "icc-platform-api")
        self.assert_rejected(metadata, "icc-types: forbidden workspace dependency on icc-platform-api")

    def test_l1_to_l2_is_rejected(self) -> None:
        metadata = metadata_from_policy()
        add_workspace_edge(metadata, "icc-rights", "icc-capability-core")
        self.assert_rejected(metadata, "icc-rights: forbidden workspace dependency on icc-capability-core")

    def test_domain_core_to_crypto_provider_is_rejected(self) -> None:
        metadata = metadata_from_policy()
        add_workspace_edge(metadata, "icc-capability-core", "icc-crypto-rust")
        self.assert_rejected(
            metadata, "icc-capability-core: forbidden workspace dependency on icc-crypto-rust"
        )

    def test_platform_port_to_linux_adapter_is_rejected(self) -> None:
        metadata = metadata_from_policy()
        add_workspace_edge(metadata, "icc-platform-api", "icc-platform-linux")
        self.assert_rejected(
            metadata, "icc-platform-api: forbidden workspace dependency on icc-platform-linux"
        )

    def test_app_to_internal_crypto_api_is_rejected_even_with_alias(self) -> None:
        metadata = metadata_from_policy()
        add_workspace_edge(metadata, "indie-cli", "icc-crypto-api", alias="innocent_alias")
        self.assert_rejected(metadata, "indie-cli: forbidden workspace dependency on icc-crypto-api")

    def test_app_to_crypto_provider_is_rejected(self) -> None:
        metadata = metadata_from_policy()
        add_workspace_edge(metadata, "indie-cli", "icc-crypto-rust")
        self.assert_rejected(metadata, "indie-cli: forbidden workspace dependency on icc-crypto-rust")

    def test_unknown_workspace_package_is_rejected(self) -> None:
        metadata = metadata_from_policy()
        rogue_id = package_id("icc-unreviewed")
        metadata["workspace_members"].append(rogue_id)
        metadata["packages"].append(
            {
                "id": rogue_id,
                "name": "icc-unreviewed",
                "version": "0.2.0",
                "source": None,
                "manifest_path": "/fixture/icc-unreviewed/Cargo.toml",
            }
        )
        metadata["resolve"]["nodes"].append({"id": rogue_id, "deps": []})
        self.assert_rejected(metadata, "icc-unreviewed: unknown workspace package")

    def test_unreviewed_external_direct_dependency_is_rejected(self) -> None:
        metadata = metadata_from_policy()
        add_external_edge(metadata, "indie-cli", "reqwest")
        self.assert_rejected(metadata, "indie-cli: unreviewed external direct dependency reqwest")


class SecretTraitPolicyTests(unittest.TestCase):
    def assert_secret_rejected(self, sources: dict[str, str], needle: str) -> None:
        failures = arch.secret_wrapper_trait_check_sources(sources)
        self.assertTrue(
            any(needle in failure for failure in failures),
            f"expected rejection containing {needle!r}, got {failures!r}",
        )

    def test_healthy_secret_fixture_is_accepted(self) -> None:
        self.assertEqual(arch.secret_wrapper_trait_check_sources(minimal_secret_sources()), [])

    def test_macro_derive_debug_is_rejected(self) -> None:
        sources = minimal_secret_sources()
        key = next(iter(sources))
        sources[key] = sources[key].replace(
            "pub struct $name", "#[derive(Debug)]\n        pub struct $name"
        )
        self.assert_secret_rejected(sources, "secret32_type macro derives forbidden trait Debug")

    def test_macro_derive_clone_is_rejected(self) -> None:
        sources = minimal_secret_sources()
        key = next(iter(sources))
        sources[key] = sources[key].replace(
            "pub struct $name", "#[derive(Clone)]\n        pub struct $name"
        )
        self.assert_secret_rejected(sources, "secret32_type macro derives forbidden trait Clone")

    def test_explicit_qualified_debug_impl_is_rejected(self) -> None:
        sources = minimal_secret_sources()
        key = next(iter(sources))
        sources[key] += """
impl core::fmt::Debug for DerivedKey32 {
    fn fmt(&self, _: &mut core::fmt::Formatter<'_>) -> core::fmt::Result { Ok(()) }
}
"""
        self.assert_secret_rejected(sources, "DerivedKey32 explicitly implements forbidden trait Debug")

    def test_explicit_qualified_clone_impl_is_rejected(self) -> None:
        sources = minimal_secret_sources()
        key = next(iter(sources))
        sources[key] += """
impl core::clone::Clone for Ed25519SigningSeed {
    fn clone(&self) -> Self { loop {} }
}
"""
        self.assert_secret_rejected(
            sources, "Ed25519SigningSeed explicitly implements forbidden trait Clone"
        )

    def test_serialize_and_deserialize_impls_are_rejected(self) -> None:
        sources = minimal_secret_sources()
        key = next(iter(sources))
        sources[key] += """
impl serde::Serialize for AeadKey32 {}
impl serde::Deserialize for SharedSecret32 {}
"""
        self.assert_secret_rejected(sources, "AeadKey32 explicitly implements forbidden trait Serialize")
        self.assert_secret_rejected(
            sources, "SharedSecret32 explicitly implements forbidden trait Deserialize"
        )

    def test_missing_expected_secret_wrapper_is_rejected(self) -> None:
        sources = minimal_secret_sources()
        key = next(iter(sources))
        sources[key] = sources[key].replace("secret32_type!(X25519Secret);", "")
        self.assert_secret_rejected(
            sources, "expected secret wrapper declaration missing: X25519Secret"
        )


if __name__ == "__main__":
    unittest.main()
