"""
Parses package-lock.json for npm dependencies.
Supports lockfileVersion 1 (dependencies key) and versions 2/3 (packages key).
"""
from __future__ import annotations
import json


def parse_npm(file_path: str) -> list[dict]:
    """
    Parses a package-lock.json file and returns a list of dependencies.

    Supports:
    - lockfileVersion 1: iterates the ``dependencies`` key.
    - lockfileVersion 2/3: iterates the ``packages`` key, skips the root
      ``""`` entry, and derives the package name from the last
      ``node_modules/`` segment of the key.

    Raises:
        ValueError: if the file contains invalid JSON.
    """
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Invalid JSON in {file_path}: {exc}"
        ) from exc

    lockfile_version = data.get('lockfileVersion', 1)
    dependencies = []

    if lockfile_version in (2, 3):
        for key, info in data.get('packages', {}).items():
            if key == '':          # root project entry — skip
                continue
            name = key.split('node_modules/')[-1]
            if 'version' not in info:
                continue
            dependencies.append({'name': name, 'version': info['version']})
    else:
        for name, info in data.get('dependencies', {}).items():
            dependencies.append({'name': name, 'version': info['version']})

    return dependencies
