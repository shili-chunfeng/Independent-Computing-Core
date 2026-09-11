#!/usr/bin/env python3
"""Render the locked third-party Cargo graph as a small Markdown inventory.

Input is Cargo metadata JSON produced with `cargo metadata --locked`. The script
reports facts available from Cargo metadata; it intentionally does not infer
maintenance, advisories, or unsafe-code properties that metadata cannot prove.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def enabled_features(metadata: dict) -> dict[str, list[str]]:
    resolve = metadata.get("resolve") or {}
    return {
        node["id"]: sorted(node.get("features", []))
        for node in resolve.get("nodes", [])
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("metadata", type=Path)
    args = parser.parse_args()

    metadata = json.loads(args.metadata.read_text(encoding="utf-8"))
    workspace_ids = set(metadata.get("workspace_members", []))
    packages = {package["id"]: package for package in metadata.get("packages", [])}
    features = enabled_features(metadata)

    direct_external: set[str] = set()
    resolve = metadata.get("resolve") or {}
    for node in resolve.get("nodes", []):
        if node["id"] not in workspace_ids:
            continue
        for dep in node.get("deps", []):
            if dep["pkg"] not in workspace_ids:
                direct_external.add(dep["pkg"])

    rows: list[tuple[str, ...]] = []
    for package_id, package in packages.items():
        if package_id in workspace_ids:
            continue
        target_kinds = {kind for target in package.get("targets", []) for kind in target.get("kind", [])}
        build_rs = "yes" if "custom-build" in target_kinds else "no"
        proc_macro = "yes" if "proc-macro" in target_kinds else "no"
        relationship = "direct" if package_id in direct_external else "transitive"
        source = package.get("source") or "unknown"
        license_expr = package.get("license") or "NOT VERIFIED"
        enabled = ", ".join(features.get(package_id, [])) or "(none)"
        rows.append(
            (
                package["name"],
                package["version"],
                relationship,
                license_expr,
                source,
                build_rs,
                proc_macro,
                enabled,
            )
        )

    rows.sort(key=lambda row: (row[0], row[1]))
    print("| Dependency | Version | Relationship | License | Source | build.rs | Proc macro | Enabled features |")
    print("|---|---:|---|---|---|---|---|---|")
    for row in rows:
        escaped = [value.replace("|", "\\|") for value in row]
        print("| " + " | ".join(escaped) + " |")
    print(f"\nResolved third-party packages: {len(rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
