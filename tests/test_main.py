"""Tests for src/main.py.

Covers:
  - --risk-config flag: valid file calls scorer.apply_config; missing file exits 1;
    invalid YAML exits 1
  - Suspicious-only scan with --format json writes a JSON file
  - KEV future is submitted alongside OSV/NVD in the parallel block
  - Property 11: ThreatProcessor() from different working dirs → same cache_dir
  - Property 12: report_false_positive then is_false_positive → True

**Validates: Requirements 10.1**
"""

import json
import os
import sys
import tempfile

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from unittest.mock import patch, MagicMock, call

# ---------------------------------------------------------------------------
# Make src/ importable (mirrors pattern used in other test files)
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import main as main_mod  # noqa: E402
import risk_scorer.scorer as scorer_mod  # noqa: E402
from threat_analysis.threat_processor import ThreatProcessor  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers — shared mocks for the expensive network calls inside main()
# ---------------------------------------------------------------------------

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), 'fixtures')
PINNED_REQUIREMENTS = os.path.join(FIXTURES_DIR, 'requirements_pinned.txt')


def _make_base_argv(req_file=None, project_type='pypi', fmt='terminal',
                    output=None, extra=None):
    """Build a sys.argv list for a minimal main() invocation."""
    argv = ['scanner', req_file or PINNED_REQUIREMENTS, '--type', project_type,
            '--format', fmt]
    if output:
        argv += ['--output', output]
    if extra:
        argv += extra
    return argv


def _patch_heavy_deps(
    suspicious_findings=None,
    osv_vulns=None,
    nvd_vulns=None,
    kev_set=None,
):
    """Return a stack of patches that prevent any real network I/O inside main().

    Callers should use this as a context manager composed via contextlib.ExitStack
    or a series of 'with patch(...)' nesting.

    Returns a dict of patch targets → their mock objects after __enter__.
    """
    suspicious_findings = suspicious_findings if suspicious_findings is not None else {}
    osv_vulns = osv_vulns if osv_vulns is not None else []
    nvd_vulns = nvd_vulns if nvd_vulns is not None else []
    kev_set = kev_set if kev_set is not None else set()
    return {
        'detector.run_all_checks': suspicious_findings,
        'osv_checker.check_osv': osv_vulns,
        'nvd_checker.check_nvd_for_missing_vulnerabilities': nvd_vulns,
        'scorer.get_kev_database': kev_set,
        'nvd_checker.get_cve_details': None,
    }


# ---------------------------------------------------------------------------
# Example tests — --risk-config
# ---------------------------------------------------------------------------

class TestRiskConfigFlag:
    """Tests for the --risk-config CLI flag (Req 7)."""

    def test_risk_config_valid_calls_apply_config(self, tmp_path):
        """With a valid YAML file, scorer.apply_config must be called before scoring.

        **Validates: Requirements 7.1, 7.2, 10.1**
        """
        config_file = tmp_path / 'custom_risk.yaml'
        config_file.write_text('risk_weights:\n  base_severity: 42\n')

        apply_config_calls = []

        def mock_apply_config(cfg):
            apply_config_calls.append(cfg)

        with patch('sys.argv', _make_base_argv(
            extra=['--risk-config', str(config_file)]
        )):
            with patch.object(main_mod.scorer, 'apply_config', side_effect=mock_apply_config):
                with patch.object(main_mod.detector, 'run_all_checks', return_value={}):
                    with patch.object(main_mod.osv_checker, 'check_osv', return_value=[]):
                        with patch.object(
                            main_mod.nvd_checker,
                            'check_nvd_for_missing_vulnerabilities',
                            return_value=[],
                        ):
                            with patch.object(main_mod.scorer, 'get_kev_database', return_value=set()):
                                # main() may reach sys.exit(0) or just return; catch both
                                try:
                                    main_mod.main()
                                except SystemExit:
                                    pass

        # apply_config must have been called at least once with the parsed YAML
        assert len(apply_config_calls) >= 1, (
            "scorer.apply_config was not called; --risk-config flag may not be functional"
        )
        assert apply_config_calls[0].get('risk_weights', {}).get('base_severity') == 42

    def test_risk_config_missing_file_exits_nonzero(self, tmp_path):
        """A non-existent --risk-config path must cause sys.exit with non-zero status.

        **Validates: Requirements 7.3, 10.1**
        """
        missing_path = str(tmp_path / 'nonexistent_config.yaml')

        with patch('sys.argv', _make_base_argv(extra=['--risk-config', missing_path])):
            with pytest.raises(SystemExit) as exc_info:
                main_mod.main()

        assert exc_info.value.code != 0, (
            f"Expected non-zero exit for missing config, got {exc_info.value.code}"
        )

    def test_risk_config_invalid_yaml_exits_nonzero(self, tmp_path):
        """A file with invalid YAML must cause sys.exit with non-zero status.

        **Validates: Requirements 7.4, 10.1**
        """
        bad_yaml = tmp_path / 'bad.yaml'
        bad_yaml.write_text(': this: is: invalid: yaml: {{\n')

        with patch('sys.argv', _make_base_argv(extra=['--risk-config', str(bad_yaml)])):
            with pytest.raises(SystemExit) as exc_info:
                main_mod.main()

        assert exc_info.value.code != 0, (
            f"Expected non-zero exit for invalid YAML, got {exc_info.value.code}"
        )


# ---------------------------------------------------------------------------
# Example test — suspicious-only scan writes JSON
# ---------------------------------------------------------------------------

class TestSuspiciousOnlyScanJson:
    """Test that a scan with suspicious findings but no CVEs writes a JSON file
    when --format json is specified (Req 8)."""

    def test_suspicious_only_scan_writes_json(self, tmp_path):
        """No CVE findings + suspicious packages + --format json → JSON file written.

        **Validates: Requirements 8.1, 8.4, 10.1**
        """
        output_file = str(tmp_path / 'scan_output.json')

        # Simulate one suspicious package finding but zero vulnerabilities
        fake_suspicious = {
            'fake-requests': [
                {
                    'type': 'Typosquatting',
                    'message': 'Possible typosquatting of requests',
                    'details': {'similarity': 95, 'similar_to': 'requests'},
                }
            ]
        }

        with patch('sys.argv', _make_base_argv(fmt='json', output=output_file)):
            with patch.object(main_mod.detector, 'run_all_checks',
                              return_value=fake_suspicious):
                with patch.object(main_mod.osv_checker, 'check_osv', return_value=[]):
                    with patch.object(
                        main_mod.nvd_checker,
                        'check_nvd_for_missing_vulnerabilities',
                        return_value=[],
                    ):
                        with patch.object(
                            main_mod.scorer, 'get_kev_database', return_value=set()
                        ):
                            try:
                                main_mod.main()
                            except SystemExit:
                                pass

        assert os.path.exists(output_file), (
            f"JSON output file '{output_file}' was not created for a suspicious-only scan"
        )

        # File must contain valid JSON
        with open(output_file) as f:
            data = json.load(f)
        assert isinstance(data, (dict, list)), "JSON output must be a dict or list"


# ---------------------------------------------------------------------------
# Example test — KEV future submitted in parallel block
# ---------------------------------------------------------------------------

class TestKevFutureSubmitted:
    """Verify that scorer.get_kev_database is submitted as a future in the parallel
    scan block alongside OSV and NVD (Req 26)."""

    def test_kev_future_submitted(self):
        """scorer.get_kev_database must be invoked (submitted to the executor) during
        the parallel scan block in main().

        **Validates: Requirements 26.1, 10.1**
        """
        kev_call_count = {'n': 0}

        def mock_get_kev():
            kev_call_count['n'] += 1
            return set()

        with patch('sys.argv', _make_base_argv()):
            with patch.object(main_mod.detector, 'run_all_checks', return_value={}):
                with patch.object(main_mod.osv_checker, 'check_osv', return_value=[]):
                    with patch.object(
                        main_mod.nvd_checker,
                        'check_nvd_for_missing_vulnerabilities',
                        return_value=[],
                    ):
                        with patch.object(
                            main_mod.scorer, 'get_kev_database',
                            side_effect=mock_get_kev,
                        ):
                            try:
                                main_mod.main()
                            except SystemExit:
                                pass

        assert kev_call_count['n'] >= 1, (
            "scorer.get_kev_database was never called; "
            "KEV future may not be submitted in the parallel block"
        )


# ---------------------------------------------------------------------------
# Property test — Property 11: ThreatProcessor cache_dir invariant under cwd changes
# ---------------------------------------------------------------------------

@settings(max_examples=200)
@given(
    st.text(
        min_size=1,
        alphabet=st.characters(whitelist_categories=('L', 'N'), whitelist_characters='_-'),
    )
)
def test_property11_threat_processor_cache_dir_invariant(dirname_suffix):
    """Property 11: ThreatProcessor() from any working directory → same absolute cache_dir.

    Instantiating ThreatProcessor() while os.chdir'd to two different temporary
    directories must yield the same cache_dir each time.

    **Validates: Requirements 18.1, 18.2, 18.3**
    """
    original_cwd = os.getcwd()
    cache_dir_a = None
    cache_dir_b = None

    try:
        with tempfile.TemporaryDirectory() as dir_a:
            os.chdir(dir_a)
            tp_a = ThreatProcessor()
            cache_dir_a = tp_a.cache_dir

        with tempfile.TemporaryDirectory() as dir_b:
            os.chdir(dir_b)
            tp_b = ThreatProcessor()
            cache_dir_b = tp_b.cache_dir
    finally:
        os.chdir(original_cwd)

    assert os.path.isabs(cache_dir_a), f"cache_dir from dir_a is not absolute: {cache_dir_a}"
    assert os.path.isabs(cache_dir_b), f"cache_dir from dir_b is not absolute: {cache_dir_b}"
    assert cache_dir_a == cache_dir_b, (
        f"ThreatProcessor().cache_dir differs between working directories:\n"
        f"  dir_a → {cache_dir_a}\n"
        f"  dir_b → {cache_dir_b}\n"
        "cache_dir must be anchored to the project root, not os.getcwd()"
    )


# ---------------------------------------------------------------------------
# Property test — Property 12: report_false_positive → is_false_positive returns True
# ---------------------------------------------------------------------------

@settings(max_examples=200)
@given(
    st.text(min_size=1),
    st.text(min_size=1),
    st.text(min_size=1),
)
def test_property12_false_positive_exclusion_is_immediate(
    package_name, claimed_target, project_type
):
    """Property 12: for any (package_name, claimed_target, project_type),
    calling report_false_positive then is_false_positive returns True.

    Uses a ThreatProcessor backed by a fresh temporary cache dir so no
    pre-existing state interferes and file-system side effects are contained.

    **Validates: Requirements 25.1, 25.2**
    """
    with tempfile.TemporaryDirectory() as tmp_cache:
        tp = ThreatProcessor(cache_dir=tmp_cache)

        # Pre-condition: not yet reported
        assert not tp.is_false_positive(package_name, claimed_target, project_type), (
            "is_false_positive returned True before any report_false_positive call"
        )

        tp.report_false_positive(package_name, claimed_target, project_type)

        assert tp.is_false_positive(package_name, claimed_target, project_type), (
            f"is_false_positive returned False after report_false_positive for "
            f"({package_name!r}, {claimed_target!r}, {project_type!r})"
        )
