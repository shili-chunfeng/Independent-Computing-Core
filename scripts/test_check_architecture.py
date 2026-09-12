#!/usr/bin/env python3
"""Self/negative tests for the production Phase 2 architecture checker."""

from __future__ import annotations

import unittest

import check_architecture as arch


FIXTURE_ROOT = "/fixture"


def package_id(name: str) -> str:
    return f"path+file://{FIXTURE_ROOT}/{name}#0.2.0"


def external_id(name: str, version: str) -> str:
    return f"{arch.CRATES_IO_SOURCE}#{name}@{version}"


def _dependency_metadata(rule: arch.DependencyDeclaration) -> dict:
    return {
        "name": rule.actual_package,
        "source": rule.source,
        "req": rule.version_requirement,
        "kind": None if rule.kind == "normal" else rule.kind,
        "rename": None if rule.alias == rule.actual_package else rule.alias,
        "optional": rule.optional,
        "uses_default_features": rule.uses_default_features,
        "features": list(rule.requested_features),
        "target": rule.target,
        "registry": rule.registry,
        "path": (
            f"{FIXTURE_ROOT}/{rule.path_target}"
            if rule.path_target is not None
            else None
        ),
    }


def metadata_from_policy() -> dict:
    """Build realistic Cargo metadata with declarations and resolved edges."""

    packages: list[dict] = []
    nodes: list[dict] = []
    workspace_members: list[str] = []

    for name in arch.PACKAGE_DECLARATION_POLICY:
        pid = package_id(name)
        workspace_members.append(pid)
        packages.append(
            {
                "id": pid,
                "name": name,
                "version": "0.2.0",
                "source": None,
                "manifest_path": f"{FIXTURE_ROOT}/{name}/Cargo.toml",
                "dependencies": [],
            }
        )
        nodes.append({"id": pid, "deps": [], "features": []})

    external_packages: dict[tuple[str, str, str], str] = {}
    for policy in arch.PACKAGE_DECLARATION_POLICY.values():
        for rule in policy:
            if rule.path_target is not None:
                continue
            version = rule.version_requirement.removeprefix("=")
            identity = (rule.actual_package, version, str(rule.source))
            if identity in external_packages:
                continue
            pid = external_id(rule.actual_package, version)
            external_packages[identity] = pid
            packages.append(
                {
                    "id": pid,
                    "name": rule.actual_package,
                    "version": version,
                    "source": rule.source,
                    "manifest_path": f"/registry/{rule.actual_package}-{version}/Cargo.toml",
                    "dependencies": [],
                }
            )
            enabled = arch.RESOLVED_FEATURE_POLICY[
                (rule.actual_package, version, str(rule.source))
            ]
            nodes.append({"id": pid, "deps": [], "features": sorted(enabled)})

    package_by_id = {package["id"]: package for package in packages}
    node_by_id = {node["id"]: node for node in nodes}
    for source_name, policy in arch.PACKAGE_DECLARATION_POLICY.items():
        source_package = package_by_id[package_id(source_name)]
        source_node = node_by_id[package_id(source_name)]
        for rule in sorted(policy, key=repr):
            source_package["dependencies"].append(_dependency_metadata(rule))
            if rule.path_target is not None:
                target_id = package_id(rule.path_target)
            else:
                version = rule.version_requirement.removeprefix("=")
                target_id = external_packages[
                    (rule.actual_package, version, str(rule.source))
                ]
            source_node["deps"].append(
                {
                    "name": rule.alias.replace("-", "_"),
                    "pkg": target_id,
                    "dep_kinds": [
                        {
                            "kind": None if rule.kind == "normal" else rule.kind,
                            "target": rule.target,
                        }
                    ],
                }
            )

    return {
        "packages": packages,
        "workspace_members": workspace_members,
        "workspace_root": FIXTURE_ROOT,
        "resolve": {"nodes": nodes},
    }


def workspace_package(metadata: dict, name: str) -> dict:
    return next(
        package
        for package in metadata["packages"]
        if package["id"] == package_id(name)
    )


def dependency(metadata: dict, source: str, actual_package: str) -> dict:
    return next(
        item
        for item in workspace_package(metadata, source)["dependencies"]
        if item["name"] == actual_package
    )


def resolved_node(metadata: dict, package: str, version: str | None = None) -> dict:
    if version is None:
        pid = package_id(package)
    else:
        pid = external_id(package, version)
    return next(node for node in metadata["resolve"]["nodes"] if node["id"] == pid)


def remove_resolved_edge(metadata: dict, source: str, target_id: str) -> None:
    node = resolved_node(metadata, source)
    node["deps"] = [item for item in node["deps"] if item["pkg"] != target_id]


def add_external_declaration(
    metadata: dict,
    source: str,
    name: str,
    *,
    rename: str | None = None,
    requirement: str = "=99.0.0",
    kind: str | None = None,
    target: str | None = None,
    optional: bool = False,
    uses_default_features: bool = False,
    features: tuple[str, ...] = (),
) -> None:
    workspace_package(metadata, source)["dependencies"].append(
        {
            "name": name,
            "source": arch.CRATES_IO_SOURCE,
            "req": requirement,
            "kind": kind,
            "rename": rename,
            "optional": optional,
            "uses_default_features": uses_default_features,
            "features": list(features),
            "target": target,
            "registry": None,
            "path": None,
        }
    )


def add_workspace_declaration(
    metadata: dict, source: str, target: str, alias: str | None = None
) -> None:
    workspace_package(metadata, source)["dependencies"].append(
        {
            "name": target,
            "source": None,
            "req": "*",
            "kind": None,
            "rename": alias,
            "optional": False,
            "uses_default_features": True,
            "features": [],
            "target": None,
            "registry": None,
            "path": f"{FIXTURE_ROOT}/{target}",
        }
    )
    resolved_node(metadata, source)["deps"].append(
        {
            "name": (alias or target).replace("-", "_"),
            "pkg": package_id(target),
            "dep_kinds": [{"kind": None, "target": None}],
        }
    )


def repository_manifests(metadata: dict) -> dict[str, str]:
    workspace_ids = set(metadata["workspace_members"])
    return {
        package["manifest_path"]: package["name"]
        for package in metadata["packages"]
        if package["id"] in workspace_ids
    }


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


class DependencyDeclarationPolicyTests(unittest.TestCase):
    def assert_rejected(self, metadata: dict, needle: str) -> None:
        failures = arch.validate_dependency_policy(metadata)
        self.assertTrue(
            any(needle in failure for failure in failures),
            f"expected rejection containing {needle!r}, got {failures!r}",
        )

    def test_healthy_current_policy_fixture_is_accepted(self) -> None:
        metadata = metadata_from_policy()
        self.assertEqual(arch.validate_dependency_policy(metadata), [])
        self.assertEqual(
            arch.validate_resolved_feature_policy(metadata, "fixture"), []
        )
        self.assertEqual(
            arch.validate_repository_manifest_membership(
                metadata, repository_manifests(metadata)
            ),
            [],
        )

    def test_inactive_optional_external_dependency_is_rejected(self) -> None:
        metadata = metadata_from_policy()
        add_external_declaration(
            metadata, "icc-crypto-api", "subtle-logger", optional=True
        )
        self.assert_rejected(metadata, "package subtle-logger")

    def test_inactive_optional_reqwest_is_rejected(self) -> None:
        metadata = metadata_from_policy()
        add_external_declaration(metadata, "indie-cli", "reqwest", optional=True)
        self.assert_rejected(metadata, "package reqwest")

    def test_optional_renamed_ed25519_hazmat_is_rejected(self) -> None:
        metadata = metadata_from_policy()
        item = dependency(metadata, "icc-crypto-rust", "ed25519-dalek")
        item["rename"] = "signature_backend"
        item["optional"] = True
        item["features"].append("hazmat")
        remove_resolved_edge(metadata, "icc-crypto-rust", external_id("ed25519-dalek", "3.0.0"))
        self.assert_rejected(metadata, "local alias/rename")
        self.assert_rejected(metadata, "requested features")

    def test_ed25519_serde_feature_is_rejected(self) -> None:
        metadata = metadata_from_policy()
        dependency(metadata, "icc-crypto-rust", "ed25519-dalek")["features"].append(
            "serde"
        )
        self.assert_rejected(metadata, "requested features")

    def test_ed25519_default_features_true_is_rejected(self) -> None:
        metadata = metadata_from_policy()
        dependency(metadata, "icc-crypto-rust", "ed25519-dalek")[
            "uses_default_features"
        ] = True
        self.assert_rejected(metadata, "uses_default_features")

    def test_chacha20poly1305_extra_feature_is_rejected(self) -> None:
        metadata = metadata_from_policy()
        dependency(metadata, "icc-crypto-rust", "chacha20poly1305")[
            "features"
        ].append("getrandom")
        self.assert_rejected(metadata, "requested features")

    def test_bare_version_is_not_an_exact_pin(self) -> None:
        metadata = metadata_from_policy()
        dependency(metadata, "icc-crypto-rust", "ed25519-dalek")["req"] = "3.0.0"
        self.assert_rejected(metadata, "version requirement")

    def test_caret_version_is_not_an_exact_pin(self) -> None:
        metadata = metadata_from_policy()
        dependency(metadata, "icc-crypto-rust", "ed25519-dalek")["req"] = "^3.0.0"
        self.assert_rejected(metadata, "version requirement")

    def test_missing_reviewed_declaration_is_rejected(self) -> None:
        metadata = metadata_from_policy()
        package = workspace_package(metadata, "icc-crypto-rust")
        package["dependencies"] = [
            item for item in package["dependencies"] if item["name"] != "sha2"
        ]
        remove_resolved_edge(metadata, "icc-crypto-rust", external_id("sha2", "0.11.0"))
        self.assert_rejected(metadata, "reviewed dependency declaration is missing")

    def test_unreviewed_build_dependency_is_rejected(self) -> None:
        metadata = metadata_from_policy()
        add_external_declaration(metadata, "icc-types", "cc", kind="build")
        self.assert_rejected(metadata, "kind=build")

    def test_unreviewed_dev_dependency_is_rejected(self) -> None:
        metadata = metadata_from_policy()
        add_external_declaration(metadata, "icc-types", "proptest", kind="dev")
        self.assert_rejected(metadata, "kind=dev")

    def test_unreviewed_target_specific_dependency_is_rejected(self) -> None:
        metadata = metadata_from_policy()
        add_external_declaration(
            metadata,
            "icc-types",
            "windows-sys",
            target="cfg(windows)",
        )
        self.assert_rejected(metadata, "target='cfg(windows)'")

    def test_renamed_dependency_is_judged_by_actual_package_identity(self) -> None:
        metadata = metadata_from_policy()
        add_external_declaration(
            metadata,
            "icc-crypto-api",
            "reqwest",
            rename="zeroize",
            optional=True,
        )
        self.assert_rejected(metadata, "zeroize (package reqwest")

    def test_repository_package_outside_workspace_is_rejected(self) -> None:
        metadata = metadata_from_policy()
        manifests = repository_manifests(metadata)
        manifests[f"{FIXTURE_ROOT}/rogue/Cargo.toml"] = "rogue-package"
        failures = arch.validate_repository_manifest_membership(metadata, manifests)
        self.assertTrue(
            any("rogue-package is not a workspace member" in failure for failure in failures),
            failures,
        )

    def test_all_features_feature_union_rejects_transitive_serde_enablement(self) -> None:
        metadata = metadata_from_policy()
        resolved_node(metadata, "ed25519-dalek", "3.0.0")["features"].append(
            "serde"
        )
        failures = arch.validate_resolved_feature_policy(metadata, "all-features")
        self.assertTrue(
            any("resolved feature union" in failure for failure in failures), failures
        )
        self.assertTrue(
            any("resolved forbidden features ['serde']" in failure for failure in failures),
            failures,
        )

    def test_l0_to_l2_declaration_is_rejected(self) -> None:
        metadata = metadata_from_policy()
        add_workspace_declaration(metadata, "icc-types", "icc-identity-core")
        self.assert_rejected(metadata, "package icc-identity-core")

    def test_l0_to_port_declaration_is_rejected(self) -> None:
        metadata = metadata_from_policy()
        add_workspace_declaration(metadata, "icc-types", "icc-platform-api")
        self.assert_rejected(metadata, "package icc-platform-api")

    def test_l1_to_l2_declaration_is_rejected(self) -> None:
        metadata = metadata_from_policy()
        add_workspace_declaration(metadata, "icc-rights", "icc-capability-core")
        self.assert_rejected(metadata, "package icc-capability-core")

    def test_domain_core_to_crypto_provider_is_rejected(self) -> None:
        metadata = metadata_from_policy()
        add_workspace_declaration(metadata, "icc-capability-core", "icc-crypto-rust")
        self.assert_rejected(metadata, "package icc-crypto-rust")

    def test_platform_port_to_linux_adapter_is_rejected(self) -> None:
        metadata = metadata_from_policy()
        add_workspace_declaration(metadata, "icc-platform-api", "icc-platform-linux")
        self.assert_rejected(metadata, "package icc-platform-linux")

    def test_app_to_internal_crypto_api_alias_is_rejected(self) -> None:
        metadata = metadata_from_policy()
        add_workspace_declaration(
            metadata, "indie-cli", "icc-crypto-api", alias="innocent-alias"
        )
        self.assert_rejected(metadata, "package icc-crypto-api")

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
                "manifest_path": f"{FIXTURE_ROOT}/icc-unreviewed/Cargo.toml",
                "dependencies": [],
            }
        )
        metadata["resolve"]["nodes"].append(
            {"id": rogue_id, "deps": [], "features": []}
        )
        self.assert_rejected(metadata, "icc-unreviewed: unknown workspace package")


class ManifestFeatureSourceTests(unittest.TestCase):
    def assert_manifest_rejected(self, text: str, needle: str) -> None:
        failures = arch.forbidden_crypto_features_in_manifest_texts(
            {"fixture/Cargo.toml": text}
        )
        self.assertTrue(
            any(needle in failure for failure in failures),
            f"expected rejection containing {needle!r}, got {failures!r}",
        )

    def test_renamed_optional_ed25519_hazmat_in_target_build_table_is_rejected(self) -> None:
        self.assert_manifest_rejected(
            """
[target.'cfg(unix)'.build-dependencies]
signature_backend = { package = "ed25519-dalek", version = "=3.0.0", optional = true, default-features = false, features = ["zeroize", "hazmat"] }
""",
            "hazmat",
        )

    def test_ed25519_serde_in_dev_table_is_rejected(self) -> None:
        self.assert_manifest_rejected(
            """
[dev-dependencies]
ed25519-dalek = { version = "=3.0.0", default-features = false, features = ["zeroize", "serde"] }
""",
            "serde",
        )

    def test_crypto_dependency_default_features_reenable_is_rejected(self) -> None:
        self.assert_manifest_rejected(
            """
[dependencies]
signer = { package = "ed25519-dalek", version = "=3.0.0", default-features = true, features = ["zeroize"] }
""",
            "uses_default_features expected False, got True",
        )

    def test_reviewed_getrandom_string_semantics_are_accepted(self) -> None:
        failures = arch.forbidden_crypto_features_in_manifest_texts(
            {"fixture/Cargo.toml": '[dependencies]\ngetrandom = "=0.4.3"\n'}
        )
        self.assertEqual(failures, [])


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
        self.assert_secret_rejected(sources, "macro derives forbidden trait Debug")

    def test_direct_derive_with_intervening_attribute_is_rejected(self) -> None:
        sources = minimal_secret_sources()
        key = next(iter(sources))
        sources[key] += """
#[derive(Clone)]
#[repr(transparent)]
pub struct DerivedKey32([u8; 32]);
"""
        self.assert_secret_rejected(sources, "DerivedKey32 derives forbidden trait Clone")

    def test_explicit_qualified_debug_impl_is_rejected(self) -> None:
        sources = minimal_secret_sources()
        key = next(iter(sources))
        sources[key] += """
impl core::fmt::Debug for DerivedKey32 {
    fn fmt(&self, _: &mut core::fmt::Formatter<'_>) -> core::fmt::Result { Ok(()) }
}
"""
        self.assert_secret_rejected(
            sources, "DerivedKey32 explicitly implements forbidden trait Debug"
        )

    def test_imported_trait_alias_impl_is_rejected(self) -> None:
        sources = minimal_secret_sources()
        key = next(iter(sources))
        sources[key] += """
use core::fmt::Debug as SecretDebug;
impl SecretDebug for X25519Secret {
    fn fmt(&self, _: &mut core::fmt::Formatter<'_>) -> core::fmt::Result { Ok(()) }
}
"""
        self.assert_secret_rejected(
            sources, "X25519Secret explicitly implements forbidden trait Debug"
        )

    def test_dependency_alias_serialize_impl_is_rejected(self) -> None:
        sources = minimal_secret_sources()
        key = next(iter(sources))
        sources[key] += """
impl serde_alias::Serialize for AeadKey32 {}
"""
        self.assert_secret_rejected(
            sources, "AeadKey32 explicitly implements forbidden trait Serialize"
        )

    def test_type_alias_trait_impl_is_rejected(self) -> None:
        sources = minimal_secret_sources()
        key = next(iter(sources))
        sources[key] += """
type SigningAlias = Ed25519SigningSeed;
impl core::clone::Clone for SigningAlias {
    fn clone(&self) -> Self { loop {} }
}
"""
        self.assert_secret_rejected(
            sources, "SigningAlias explicitly implements forbidden trait Clone"
        )

    def test_macro_generated_impl_is_a_documented_source_scan_limit(self) -> None:
        sources = minimal_secret_sources()
        key = next(iter(sources))
        sources[key] += """
macro_rules! implement_debug {
    ($target:ty) => {
        impl core::fmt::Debug for $target {
            fn fmt(&self, _: &mut core::fmt::Formatter<'_>) -> core::fmt::Result { Ok(()) }
        }
    };
}
implement_debug!(SharedSecret32);
"""
        # The dependency-free source scanner deliberately does not claim macro
        # expansion. The independent per-wrapper compile-fail doctest catches
        # the resulting compiler trait bound in production source.
        self.assertEqual(arch.secret_wrapper_trait_check_sources(sources), [])

    def test_missing_expected_secret_wrapper_is_rejected(self) -> None:
        sources = minimal_secret_sources()
        key = next(iter(sources))
        sources[key] = sources[key].replace("secret32_type!(X25519Secret);", "")
        self.assert_secret_rejected(
            sources, "expected secret wrapper declaration missing: X25519Secret"
        )


if __name__ == "__main__":
    unittest.main()
