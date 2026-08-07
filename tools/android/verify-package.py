#!/usr/bin/env python3
"""Bind packaged Android WalletCore libraries to their verified staging bytes."""

from __future__ import annotations

import argparse
import hashlib
import sys
import zipfile
from pathlib import Path, PurePosixPath


SUPPORTED_ABIS = {"armeabi-v7a", "arm64-v8a"}
LIBRARY_NAME = "libwallet_core.so"
FORBIDDEN_PARTS = {"unstripped", "wallet-core-rng-evidence"}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def packaged_wallet_core_entries(names: list[str]) -> dict[str, str]:
    entries: dict[str, str] = {}
    for name in names:
        parts = PurePosixPath(name).parts
        if any(part in FORBIDDEN_PARTS for part in parts):
            raise ValueError(f"build-only RNG provenance was packaged: {name}")
        if len(parts) < 3 or parts[-1] != LIBRARY_NAME:
            continue
        if parts[-3] != "lib" or parts[-2] not in SUPPORTED_ABIS:
            continue
        abi = parts[-2]
        if abi in entries:
            raise ValueError(f"duplicate packaged {LIBRARY_NAME} for {abi}")
        entries[abi] = name
    return entries


def verify_package(archive: Path, jni_libs_root: Path) -> None:
    if not archive.is_file():
        raise ValueError(f"package not found: {archive}")
    if not jni_libs_root.is_dir():
        raise ValueError(f"jniLibs root not found: {jni_libs_root}")

    staged = {
        abi: jni_libs_root / abi / LIBRARY_NAME
        for abi in SUPPORTED_ABIS
        if (jni_libs_root / abi / LIBRARY_NAME).is_file()
    }
    if not staged:
        raise ValueError(f"no staged {LIBRARY_NAME} artifacts under {jni_libs_root}")

    with zipfile.ZipFile(archive) as package:
        packaged = packaged_wallet_core_entries(package.namelist())
        if set(packaged) != set(staged):
            raise ValueError(
                "packaged WalletCore ABI set does not match verified staging: "
                f"package={sorted(packaged)}, staged={sorted(staged)}"
            )
        for abi, entry in sorted(packaged.items()):
            package_hash = digest(package.read(entry))
            staged_hash = digest(staged[abi].read_bytes())
            if package_hash != staged_hash:
                raise ValueError(
                    f"packaged {LIBRARY_NAME} bytes differ from verified staging "
                    f"for {abi}: package={package_hash}, staged={staged_hash}"
                )
            print(f"  ok {archive.name}: {abi} {LIBRARY_NAME} matches verified staging")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("jni_libs_root", type=Path)
    args = parser.parse_args()
    try:
        verify_package(args.archive, args.jni_libs_root)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        print(f"Android WalletCore package verification failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
