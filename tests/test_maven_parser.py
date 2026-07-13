"""
Tests for src/dependency_parser/maven_parser.py

Covers:
- Example: pom_with_properties.xml → property references resolved to literal versions
- Example: pom_no_properties.xml → literal versions returned as-is
- Example: pom_unresolved_property.xml → dep with unresolvable property omitted, warning on stderr
- Edge cases: empty pom, missing version element, missing groupId
- Toggle: _USE_DEFUSED monkeypatching (both False and True)
- Property 7: For any property name P and version string V, a dynamically
  constructed pom.xml with <P>V</P> and <version>${P}</version> must yield
  a dependency with version == V.

Validates: Requirements 9.1, 9.2, 9.5, 10.1
"""
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

from src.dependency_parser.maven_parser import parse_maven          # noqa: E402
import src.dependency_parser.maven_parser as maven_parser_module    # noqa: E402

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
FIXTURES_DIR = os.path.join(os.path.dirname(__file__), 'fixtures')


def fixture_path(filename: str) -> str:
    return os.path.join(FIXTURES_DIR, filename)


# ---------------------------------------------------------------------------
# Example tests: pom_with_properties.xml
# ---------------------------------------------------------------------------

class TestPomWithProperties:
    """Tests for pom_with_properties.xml — property references must be resolved."""

    def test_returns_two_dependencies(self):
        deps = parse_maven(fixture_path('pom_with_properties.xml'))
        assert len(deps) == 2

    def test_spring_core_version_resolved(self):
        deps = parse_maven(fixture_path('pom_with_properties.xml'))
        spring = next(d for d in deps if d['artifact_id'] == 'spring-core')
        assert spring['version'] == '5.3.27'

    def test_jackson_databind_version_resolved(self):
        deps = parse_maven(fixture_path('pom_with_properties.xml'))
        jackson = next(d for d in deps if d['artifact_id'] == 'jackson-databind')
        assert jackson['version'] == '2.15.2'

    def test_no_raw_property_placeholder_in_versions(self):
        deps = parse_maven(fixture_path('pom_with_properties.xml'))
        for dep in deps:
            assert not dep['version'].startswith('${'), (
                f"Unresolved placeholder found in version: {dep['version']}"
            )

    def test_name_format(self):
        deps = parse_maven(fixture_path('pom_with_properties.xml'))
        for dep in deps:
            assert ':' in dep['name'], (
                f"Expected 'groupId:artifactId' format, got: {dep['name']}"
            )


# ---------------------------------------------------------------------------
# Example tests: pom_no_properties.xml
# ---------------------------------------------------------------------------

class TestPomNoProperties:
    """Tests for pom_no_properties.xml — literal versions returned as-is."""

    def test_returns_two_dependencies(self):
        deps = parse_maven(fixture_path('pom_no_properties.xml'))
        assert len(deps) == 2

    def test_spring_core_literal_version(self):
        deps = parse_maven(fixture_path('pom_no_properties.xml'))
        spring = next(d for d in deps if d['artifact_id'] == 'spring-core')
        assert spring['version'] == '5.3.27'

    def test_jackson_databind_literal_version(self):
        deps = parse_maven(fixture_path('pom_no_properties.xml'))
        jackson = next(d for d in deps if d['artifact_id'] == 'jackson-databind')
        assert jackson['version'] == '2.15.2'

    def test_has_group_id_and_artifact_id_fields(self):
        deps = parse_maven(fixture_path('pom_no_properties.xml'))
        for dep in deps:
            assert 'group_id' in dep, f"Missing 'group_id' key in {dep}"
            assert 'artifact_id' in dep, f"Missing 'artifact_id' key in {dep}"


# ---------------------------------------------------------------------------
# Example tests: pom_unresolved_property.xml
# ---------------------------------------------------------------------------

class TestPomUnresolvedProperty:
    """Tests for pom_unresolved_property.xml — unresolvable property dep is omitted."""

    def test_only_resolvable_dep_returned(self):
        deps = parse_maven(fixture_path('pom_unresolved_property.xml'))
        assert len(deps) == 1

    def test_unresolvable_dep_omitted(self):
        deps = parse_maven(fixture_path('pom_unresolved_property.xml'))
        artifact_ids = [d['artifact_id'] for d in deps]
        assert 'jackson-databind' not in artifact_ids

    def test_warning_emitted_to_stderr(self, capsys):
        parse_maven(fixture_path('pom_unresolved_property.xml'))
        captured = capsys.readouterr()
        assert 'jackson.version' in captured.err, (
            f"Expected warning about 'jackson.version' in stderr, got: {captured.err!r}"
        )


# ---------------------------------------------------------------------------
# Edge case tests
# ---------------------------------------------------------------------------

class TestPomEdgeCases:
    """Edge cases: empty pom, missing elements."""

    def test_empty_pom_returns_empty_list(self, tmp_path):
        pom = tmp_path / 'pom.xml'
        pom.write_text(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<project>\n'
            '  <modelVersion>4.0.0</modelVersion>\n'
            '</project>\n'
        )
        deps = parse_maven(str(pom))
        assert deps == []

    def test_missing_version_element_skipped(self, tmp_path):
        pom = tmp_path / 'pom.xml'
        pom.write_text(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<project>\n'
            '  <dependencies>\n'
            '    <dependency>\n'
            '      <groupId>com.example</groupId>\n'
            '      <artifactId>no-version</artifactId>\n'
            '    </dependency>\n'
            '    <dependency>\n'
            '      <groupId>com.example</groupId>\n'
            '      <artifactId>has-version</artifactId>\n'
            '      <version>1.0.0</version>\n'
            '    </dependency>\n'
            '  </dependencies>\n'
            '</project>\n'
        )
        deps = parse_maven(str(pom))
        artifact_ids = [d['artifact_id'] for d in deps]
        assert 'no-version' not in artifact_ids
        assert 'has-version' in artifact_ids

    def test_missing_group_id_skipped(self, tmp_path):
        pom = tmp_path / 'pom.xml'
        pom.write_text(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<project>\n'
            '  <dependencies>\n'
            '    <dependency>\n'
            '      <artifactId>no-group</artifactId>\n'
            '      <version>1.0.0</version>\n'
            '    </dependency>\n'
            '    <dependency>\n'
            '      <groupId>com.example</groupId>\n'
            '      <artifactId>has-group</artifactId>\n'
            '      <version>2.0.0</version>\n'
            '    </dependency>\n'
            '  </dependencies>\n'
            '</project>\n'
        )
        deps = parse_maven(str(pom))
        artifact_ids = [d['artifact_id'] for d in deps]
        assert 'no-group' not in artifact_ids
        assert 'has-group' in artifact_ids


# ---------------------------------------------------------------------------
# Edge case tests: _USE_DEFUSED toggle
# ---------------------------------------------------------------------------

_SIMPLE_POM = """\
<?xml version="1.0" encoding="UTF-8"?>
<project>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>my-lib</artifactId>
      <version>3.1.4</version>
    </dependency>
  </dependencies>
</project>
"""


class TestDefusedxmlToggle:
    """Tests that the parser works correctly regardless of _USE_DEFUSED value."""

    def test_parses_with_defused_disabled(self, tmp_path, monkeypatch):
        """Parser must return correct results when _USE_DEFUSED is False."""
        monkeypatch.setattr(maven_parser_module, '_USE_DEFUSED', False)
        pom = tmp_path / 'pom.xml'
        pom.write_text(_SIMPLE_POM)
        deps = parse_maven(str(pom))
        assert len(deps) == 1
        assert deps[0]['name'] == 'com.example:my-lib'
        assert deps[0]['version'] == '3.1.4'

    def test_parses_with_defused_enabled(self, tmp_path, monkeypatch):
        """Parser must return correct results when _USE_DEFUSED is True (requires defusedxml)."""
        pytest.importorskip('defusedxml')
        monkeypatch.setattr(maven_parser_module, '_USE_DEFUSED', True)
        pom = tmp_path / 'pom.xml'
        pom.write_text(_SIMPLE_POM)
        deps = parse_maven(str(pom))
        assert len(deps) == 1
        assert deps[0]['name'] == 'com.example:my-lib'
        assert deps[0]['version'] == '3.1.4'


# ---------------------------------------------------------------------------
# Property 7: Maven Property Resolution Round-Trip
# Validates: Requirements 9.1, 9.2, 9.5
# ---------------------------------------------------------------------------

@settings(max_examples=200)
@given(
    prop_name=st.from_regex(r'[a-zA-Z][a-zA-Z0-9._-]{0,30}', fullmatch=True),
    version=st.from_regex(r'[0-9]+(\.[0-9]+){0,3}', fullmatch=True),
)
def test_property7_property_resolution_round_trip(prop_name, version):
    """
    Property 7: For any property name P and version string V,
    a pom.xml with <properties><P>V</P></properties> and
    <version>${P}</version> must yield a dependency with version == V.

    **Validates: Requirements 9.1, 9.2, 9.5**
    """
    pom_content = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<project>\n'
        '  <properties>\n'
        f'    <{prop_name}>{version}</{prop_name}>\n'
        '  </properties>\n'
        '  <dependencies>\n'
        '    <dependency>\n'
        '      <groupId>com.example</groupId>\n'
        '      <artifactId>test-artifact</artifactId>\n'
        f'      <version>${{{prop_name}}}</version>\n'
        '    </dependency>\n'
        '  </dependencies>\n'
        '</project>\n'
    )

    tmp_dir = tempfile.mkdtemp()
    pom_file = os.path.join(tmp_dir, 'pom.xml')
    try:
        with open(pom_file, 'w', encoding='utf-8') as f:
            f.write(pom_content)
        deps = parse_maven(pom_file)
        assert len(deps) == 1, (
            f"Expected 1 dependency, got {len(deps)} for prop_name={prop_name!r}, version={version!r}"
        )
        assert deps[0]['version'] == version, (
            f"Expected version={version!r}, got {deps[0]['version']!r} "
            f"for prop_name={prop_name!r}"
        )
    finally:
        os.unlink(pom_file)
        os.rmdir(tmp_dir)
