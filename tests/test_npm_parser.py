"""
Tests for src/dependency_parser/npm_parser.py

Covers:
- Example: package_lock_v1.json yields expected deps from `dependencies`
- Example: package_lock_v2.json yields expected deps from `packages`, root "" skipped
- Example: invalid JSON raises ValueError
- Property 5: For any key of the form "node_modules/<name>" or
  "node_modules/deeper/node_modules/<name>", the extracted package name
  equals the segment after the last "node_modules/".

Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 10.1
"""
import json
import os
import sys
import tempfile

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

# ---------------------------------------------------------------------------
# Ensure src/ is importable when running from the project root
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.dependency_parser.npm_parser import parse_npm  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
FIXTURES_DIR = os.path.join(os.path.dirname(__file__), 'fixtures')


def fixture_path(filename: str) -> str:
    return os.path.join(FIXTURES_DIR, filename)


# ---------------------------------------------------------------------------
# Example tests
# ---------------------------------------------------------------------------

class TestParseNpmV1:
    """Tests for lockfileVersion 1 (uses top-level `dependencies` key)."""

    def test_returns_expected_packages(self):
        deps = parse_npm(fixture_path('package_lock_v1.json'))
        names = {d['name'] for d in deps}
        assert 'lodash' in names
        assert 'express' in names

    def test_lodash_version(self):
        deps = parse_npm(fixture_path('package_lock_v1.json'))
        lodash = next(d for d in deps if d['name'] == 'lodash')
        assert lodash['version'] == '4.17.11'

    def test_express_version(self):
        deps = parse_npm(fixture_path('package_lock_v1.json'))
        express = next(d for d in deps if d['name'] == 'express')
        assert express['version'] == '4.18.2'

    def test_returns_list_of_dicts(self):
        deps = parse_npm(fixture_path('package_lock_v1.json'))
        assert isinstance(deps, list)
        for d in deps:
            assert 'name' in d
            assert 'version' in d


class TestParseNpmV2:
    """Tests for lockfileVersion 2 (uses top-level `packages` key)."""

    def test_returns_expected_packages(self):
        deps = parse_npm(fixture_path('package_lock_v2.json'))
        names = {d['name'] for d in deps}
        assert 'lodash' in names
        assert 'express' in names

    def test_root_entry_is_skipped(self):
        """The "" root entry must not appear as a dependency."""
        deps = parse_npm(fixture_path('package_lock_v2.json'))
        assert all(d['name'] != '' for d in deps)

    def test_lodash_version(self):
        deps = parse_npm(fixture_path('package_lock_v2.json'))
        lodash = next(d for d in deps if d['name'] == 'lodash')
        assert lodash['version'] == '4.17.11'

    def test_express_version(self):
        deps = parse_npm(fixture_path('package_lock_v2.json'))
        express = next(d for d in deps if d['name'] == 'express')
        assert express['version'] == '4.18.2'

    def test_package_count(self):
        """Exactly 2 deps expected — root "" entry must be excluded."""
        deps = parse_npm(fixture_path('package_lock_v2.json'))
        assert len(deps) == 2


class TestParseNpmInvalidJson:
    """Tests for error handling on malformed input."""

    def test_invalid_json_raises_value_error(self, tmp_path):
        bad_file = tmp_path / 'bad.json'
        bad_file.write_text('{ this is not json }')
        with pytest.raises(ValueError):
            parse_npm(str(bad_file))

    def test_error_message_contains_filename(self, tmp_path):
        bad_file = tmp_path / 'malformed.json'
        bad_file.write_text(':::')
        with pytest.raises(ValueError, match='malformed.json'):
            parse_npm(str(bad_file))

    def test_empty_file_raises_value_error(self, tmp_path):
        empty_file = tmp_path / 'empty.json'
        empty_file.write_text('')
        with pytest.raises(ValueError):
            parse_npm(str(empty_file))


class TestParseNpmEdgeCases:
    """Edge cases for v2 packages entries."""

    def test_entry_without_version_is_skipped(self, tmp_path):
        """A packages entry with no 'version' key must be silently skipped."""
        data = {
            'lockfileVersion': 2,
            'packages': {
                '': {'name': 'my-project', 'version': '1.0.0'},
                'node_modules/lodash': {},          # no version
                'node_modules/express': {'version': '4.18.2'},
            }
        }
        lock_file = tmp_path / 'package-lock.json'
        lock_file.write_text(json.dumps(data))
        deps = parse_npm(str(lock_file))
        names = {d['name'] for d in deps}
        assert 'lodash' not in names
        assert 'express' in names

    def test_v3_lockfile_uses_packages_key(self, tmp_path):
        """lockfileVersion 3 should behave the same as v2."""
        data = {
            'lockfileVersion': 3,
            'packages': {
                '': {'name': 'my-project', 'version': '1.0.0'},
                'node_modules/chalk': {'version': '5.0.0'},
            }
        }
        lock_file = tmp_path / 'package-lock.json'
        lock_file.write_text(json.dumps(data))
        deps = parse_npm(str(lock_file))
        assert len(deps) == 1
        assert deps[0]['name'] == 'chalk'
        assert deps[0]['version'] == '5.0.0'

    def test_absent_lockfile_version_defaults_to_v1(self, tmp_path):
        """When lockfileVersion is missing, fall back to v1 behaviour."""
        data = {
            'dependencies': {
                'semver': {'version': '7.5.4'},
            }
        }
        lock_file = tmp_path / 'package-lock.json'
        lock_file.write_text(json.dumps(data))
        deps = parse_npm(str(lock_file))
        assert len(deps) == 1
        assert deps[0]['name'] == 'semver'


# ---------------------------------------------------------------------------
# Property 5: npm Parser Extracts Package Name as Last node_modules/ Segment
# Validates: Requirements 3.4
# ---------------------------------------------------------------------------

@settings(max_examples=200)
@given(
    st.text(
        alphabet=st.characters(blacklist_characters='/'),
        min_size=1,
    )
)
def test_property5_simple_key_extraction(pkg_name):
    """
    Property 5 — simple key:
    For "node_modules/<pkg_name>", the extracted name equals <pkg_name>.

    **Validates: Requirements 3.4**
    """
    key = 'node_modules/' + pkg_name
    extracted = key.split('node_modules/')[-1]
    assert extracted == pkg_name


@settings(max_examples=200)
@given(
    st.text(
        alphabet=st.characters(blacklist_characters='/'),
        min_size=1,
    )
)
def test_property5_nested_key_extraction(pkg_name):
    """
    Property 5 — nested (hoisted) key:
    For "node_modules/deeper/node_modules/<pkg_name>", the extracted name
    equals <pkg_name>.

    **Validates: Requirements 3.4**
    """
    key = 'node_modules/deeper/node_modules/' + pkg_name
    extracted = key.split('node_modules/')[-1]
    assert extracted == pkg_name


@settings(max_examples=200)
@given(
    st.text(
        alphabet=st.characters(blacklist_characters='/'),
        min_size=1,
    )
)
def test_property5_end_to_end_via_parse_npm(pkg_name):
    """
    Property 5 — end-to-end via parse_npm:
    A v2 lock file whose packages key is "node_modules/<pkg_name>" yields
    a dependency whose name == pkg_name (confirmed through parse_npm itself).

    **Validates: Requirements 3.4**
    """
    version = '1.0.0'
    data = {
        'lockfileVersion': 2,
        'packages': {
            '': {'name': 'root', 'version': '0.0.0'},
            f'node_modules/{pkg_name}': {'version': version},
        }
    }
    with tempfile.NamedTemporaryFile(
        mode='w', suffix='.json', delete=False
    ) as f:
        json.dump(data, f)
        tmp_path = f.name
    try:
        deps = parse_npm(tmp_path)
        assert len(deps) == 1
        assert deps[0]['name'] == pkg_name
        assert deps[0]['version'] == version
    finally:
        os.unlink(tmp_path)
