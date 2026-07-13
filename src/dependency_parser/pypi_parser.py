"""
Parses requirements.txt for PyPI dependencies using a robust library.
"""
from __future__ import annotations
import sys
import re
from pip_requirements_parser import RequirementsFile


def _extract_version(req) -> str | None:
    """
    Returns pinned version string, or lower-bound for >= specifiers.
    Returns None if no version is available.
    """
    if not req.specifier:
        return None
    spec_str = str(req.specifier)
    if '==' in spec_str:
        return spec_str.replace('==', '').strip()
    if '>=' in spec_str and '<' not in spec_str and '~=' not in spec_str:
        version = re.sub(r'>=\s*', '', spec_str).strip()
        print(
            f"WARNING: {req.name}>={version} is not pinned; "
            f"scanning lower-bound version {version}.",
            file=sys.stderr
        )
        return version
    if '~=' in spec_str:
        return re.sub(r'~=\s*', '', spec_str).strip()
    return None


def parse_pypi(file_path: str) -> list[dict]:
    """
    Parses a requirements.txt file using pip-requirements-parser.
    Warns on unpinned dependencies and includes >= lower-bound versions.
    Skips entries with no version specifier.
    """
    dependencies = []
    req_file = RequirementsFile.from_file(file_path)
    for req in req_file.requirements:
        if not req.name:
            continue
        version = _extract_version(req)
        if version is None:
            print(
                f"WARNING: {req.name} has no version specifier; skipping.",
                file=sys.stderr
            )
            continue       # omit from list per Req 2.4
        dependencies.append({'name': req.name, 'version': version})
    return dependencies
