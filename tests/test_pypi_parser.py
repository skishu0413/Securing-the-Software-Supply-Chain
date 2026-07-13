"""
Tests for src/dependency_parser/pypi_parser.py

Validates Requirements 10.1 and 10.4:
  - Example tests using fixture files (requirements_pinned.txt, requirements_unpinned.txt)
  - Property 3: package>=V entry yields version == V
  - Property 4: list of bare package names → parse_pypi returns empty list without raising
"""
import os
import sys
import tempfile

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

# Add src/ to sys.path so the module can be imported directly
_PROJECT_ROOT = os.path.join(os.path.dirname(__file__), "..")
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from src.dependency_parser.pypi_parser import parse_pypi  # noqa: E402

# ---------------------------------------------------------------------------
# Fixture paths
# ---------------------------------------------------------------------------
FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
PINNED_TXT = os.path.join(FIXTURES_DIR, "requirements_pinned.txt")
UNPINNED_TXT = os.path.join(FIXTURES_DIR, "requirements_unpinned.txt")


# ---------------------------------------------------------------------------
# Example tests
# ---------------------------------------------------------------------------

class TestPinnedRequirements:
    """Tests against requirements_pinned.txt (all == specifiers)."""

    def test_all_entries_have_non_empty_version(self):
        """Every parsed dependency must have a non-empty version string."""
        deps = parse_pypi(PINNED_TXT)
        assert len(deps) > 0, "Expected at least one dependency"
        for dep in deps:
            assert dep["version"], (
                f"Dependency {dep['name']!r} has empty or missing version"
            )

    def test_expected_packages_present(self):
        """Spot-check that known packages from the fixture are returned."""
        deps = parse_pypi(PINNED_TXT)
        names = {d["name"].lower() for d in deps}
        assert "requests" in names
        assert "pyyaml" in names

    def test_pinned_version_values(self):
        """Verify exact version strings for pinned deps."""
        deps = parse_pypi(PINNED_TXT)
        by_name = {d["name"].lower(): d["version"] for d in deps}
        assert by_name["requests"] == "2.32.3"
        assert by_name["pyyaml"] == "6.0.2"


class TestUnpinnedRequirements:
    """Tests against requirements_unpinned.txt (mixed specifiers)."""

    def test_bare_name_dep_is_omitted(self):
        """'flask' (bare name, no specifier) must NOT appear in the output."""
        deps = parse_pypi(UNPINNED_TXT)
        names = [d["name"].lower() for d in deps]
        assert "flask" not in names, (
            "Bare-name dependency 'flask' should be omitted"
        )

    def test_gte_dep_included_with_lower_bound(self):
        """'pyyaml>=6.0.2' must be included with version '6.0.2'."""
        deps = parse_pypi(UNPINNED_TXT)
        by_name = {d["name"].lower(): d["version"] for d in deps}
        assert "pyyaml" in by_name, (
            "'pyyaml' (>= specifier) should be included in results"
        )
        assert by_name["pyyaml"] == "6.0.2", (
            f"Expected version '6.0.2' for pyyaml, got {by_name['pyyaml']!r}"
        )

    def test_pinned_dep_still_present(self):
        """'requests==2.32.3' (== specifier) must be included normally."""
        deps = parse_pypi(UNPINNED_TXT)
        by_name = {d["name"].lower(): d["version"] for d in deps}
        assert "requests" in by_name
        assert by_name["requests"] == "2.32.3"

    def test_does_not_raise_on_unpinned(self):
        """parse_pypi must not raise even when some deps are unpinned."""
        # Should complete without raising
        parse_pypi(UNPINNED_TXT)


# ---------------------------------------------------------------------------
# Property-based tests
# ---------------------------------------------------------------------------

# Strategy for valid PEP 508 package names.
# Must start and end with an alphanumeric character; middle chars may include . _ -
# This matches the PEP 508 normalisation rules that pip-requirements-parser enforces.
_package_name_strategy = st.from_regex(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}[A-Za-z0-9]", fullmatch=True)

# Strategy for PEP 440-like version strings (e.g. "1.2.3", "10.0", "1.2.3.post1")
_version_strategy = st.from_regex(r"[0-9]+(\.[0-9]+){0,4}(\.post[0-9]+|\.dev[0-9]+|[ab][0-9]+)?", fullmatch=True)


@settings(max_examples=200)
@given(package=_package_name_strategy, version=_version_strategy)
def test_property_3_gte_entry_yields_lower_bound_version(package: str, version: str):
    """
    **Validates: Requirements 10.4 / Property 3**

    For any valid package name and version string V,
    a requirements file containing `package>=V` must yield a dependency
    entry whose `version` field equals V.
    """
    content = f"{package}>={version}\n"
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False
    ) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        deps = parse_pypi(tmp_path)
        assert len(deps) == 1, (
            f"Expected exactly 1 entry for '{package}>={version}', got {deps}"
        )
        assert deps[0]["version"] == version, (
            f"Expected version {version!r}, got {deps[0]['version']!r}"
        )
    finally:
        os.unlink(tmp_path)


@settings(max_examples=200)
@given(packages=st.lists(
    _package_name_strategy,
    min_size=0,
    max_size=20,
    unique=True,
))
def test_property_4_bare_names_return_empty_list(packages: list):
    """
    **Validates: Requirements 10.4 / Property 4**

    For any list of bare package names (no version specifier),
    parse_pypi must return an empty list without raising any exception.
    """
    # Build a requirements file with only bare package names
    content = "\n".join(packages) + "\n" if packages else ""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False
    ) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        result = parse_pypi(tmp_path)
        assert result == [], (
            f"Expected empty list for bare-name packages, got {result}"
        )
    finally:
        os.unlink(tmp_path)
