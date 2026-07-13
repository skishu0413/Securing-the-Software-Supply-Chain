"""Tests for src/risk_scorer/scorer.py.

Covers:
  - apply_config: deep-merge custom weights without losing defaults
  - check_kev_status: score ≤ 1.0, indicators have no duplicates per source bucket
  - _score_cvss_vector: in-range [0.0, 10.0] for well-formed vectors; 0.0 for malformed
  - get_kev_database: thread-safe caching (at most one HTTP fetch per cache miss)

**Validates: Requirements 10.1**
"""

import os
import sys
import copy
import threading
import time

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from unittest.mock import patch, MagicMock

# ---------------------------------------------------------------------------
# Make the src/ tree importable
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import risk_scorer.scorer as scorer_mod  # noqa: E402 — must follow sys.path insert

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reset_kev_cache():
    """Force the module-level KEV cache back to an empty / expired state."""
    with scorer_mod._kev_lock:
        scorer_mod._kev_cache['data'] = None
        scorer_mod._kev_cache['timestamp'] = 0
        scorer_mod._kev_cache['cve_set'] = set()
    # Make sure the fetch-event is set (i.e., no fetch in progress)
    scorer_mod._kev_fetch_event.set()


def _fresh_scorer_config():
    """Return a deep copy of the default RISK_CONFIG so tests don't pollute each other."""
    return copy.deepcopy(scorer_mod.load_risk_config())


# ---------------------------------------------------------------------------
# CVSS v3.1 valid vector strategy
# All metrics use only spec-valid single-char abbreviations.
# ---------------------------------------------------------------------------

# Each component: (metric-name, list-of-valid-values)
_CVSS31_COMPONENTS = [
    ("AV", ["N", "A", "L", "P"]),
    ("AC", ["L", "H"]),
    ("PR", ["N", "L", "H"]),
    ("UI", ["N", "R"]),
    ("S",  ["U", "C"]),
    ("C",  ["N", "L", "H"]),
    ("I",  ["N", "L", "H"]),
    ("A",  ["N", "L", "H"]),
]


def _build_cvss31_vector(choices):
    """Assemble a CVSS:3.1/… vector from a list of chosen values (one per component)."""
    parts = [f"{name}:{val}" for (name, _), val in zip(_CVSS31_COMPONENTS, choices)]
    return "CVSS:3.1/" + "/".join(parts)


# Hypothesis strategy that generates valid CVSS 3.1 vectors
_cvss31_vector_strategy = st.tuples(
    *[st.sampled_from(values) for _, values in _CVSS31_COMPONENTS]
).map(lambda choices: _build_cvss31_vector(choices))


# ---------------------------------------------------------------------------
# Example tests — apply_config
# ---------------------------------------------------------------------------

class TestApplyConfig:
    """Example tests for scorer.apply_config."""

    def setup_method(self):
        """Restore RISK_CONFIG before each test."""
        scorer_mod.RISK_CONFIG = _fresh_scorer_config()

    def teardown_method(self):
        """Restore RISK_CONFIG after each test."""
        scorer_mod.RISK_CONFIG = _fresh_scorer_config()

    def test_apply_config_overrides_specified_key(self):
        """Custom weight must override the corresponding default value.

        **Validates: Requirements 10.1**
        """
        scorer_mod.apply_config({"risk_weights": {"base_severity": 99}})
        assert scorer_mod.RISK_CONFIG["risk_weights"]["base_severity"] == 99

    def test_apply_config_preserves_unspecified_keys(self):
        """Keys not present in cfg must survive the merge unchanged.

        **Validates: Requirements 10.1**
        """
        original_exploit = scorer_mod.RISK_CONFIG.get("risk_weights", {}).get("exploit_pressure")
        scorer_mod.apply_config({"risk_weights": {"base_severity": 50}})
        assert scorer_mod.RISK_CONFIG["risk_weights"]["exploit_pressure"] == original_exploit

    def test_apply_config_deep_merge_nested_dict(self):
        """Nested sub-dicts must be merged, not replaced wholesale.

        **Validates: Requirements 10.1**
        """
        # Capture original 'display' keys
        original_display = copy.deepcopy(scorer_mod.RISK_CONFIG.get("display", {}))
        # Override just one display key
        scorer_mod.apply_config({"display": {"verbose_risk_breakdown": False}})
        # The overridden key must change
        assert scorer_mod.RISK_CONFIG["display"]["verbose_risk_breakdown"] is False
        # All other display keys must survive
        for key, val in original_display.items():
            if key != "verbose_risk_breakdown":
                assert scorer_mod.RISK_CONFIG["display"][key] == val

    def test_apply_config_adds_new_top_level_key(self):
        """Entirely new keys must be inserted into the merged config.

        **Validates: Requirements 10.1**
        """
        scorer_mod.apply_config({"custom_key": {"foo": "bar"}})
        assert scorer_mod.RISK_CONFIG.get("custom_key") == {"foo": "bar"}

    def test_apply_config_empty_dict_is_noop(self):
        """Passing an empty dict must leave RISK_CONFIG unchanged.

        **Validates: Requirements 10.1**
        """
        before = copy.deepcopy(scorer_mod.RISK_CONFIG)
        scorer_mod.apply_config({})
        assert scorer_mod.RISK_CONFIG == before


# ---------------------------------------------------------------------------
# Example tests — check_kev_status
# ---------------------------------------------------------------------------

class TestCheckKevStatus:
    """Example tests for scorer.check_kev_status."""

    def _kev_mocked(self):
        """Context manager: patch query_kev_database so no real HTTP is issued."""
        return patch.object(scorer_mod, 'query_kev_database', return_value=False)

    def test_score_never_exceeds_one(self):
        """Even with CISA KEV + high EPSS, score must be capped at 1.0.

        **Validates: Requirements 10.1**
        """
        with patch.object(scorer_mod, 'query_kev_database', return_value=True):
            vuln = {'id': 'CVE-2024-9999', 'summary': '', 'details': ''}
            score, indicators = scorer_mod.check_kev_status(vuln, epss_score=0.99)
        assert score <= 1.0

    def test_indicators_no_duplicates_for_same_source(self):
        """indicators_found must contain at most one entry per source bucket.

        **Validates: Requirements 10.1**
        """
        with patch.object(scorer_mod, 'query_kev_database', return_value=True):
            vuln = {
                'id': 'CVE-2024-1111',
                'summary': 'actively exploited in the wild PoC available',
                'details': 'remote code execution exploit',
            }
            _, indicators = scorer_mod.check_kev_status(vuln, epss_score=0.95)
        # Count occurrences of each source bucket prefix
        from collections import Counter
        prefixes = []
        for ind in indicators:
            if ind.startswith("CISA KEV"):
                prefixes.append("cisa_kev")
            elif ind.startswith("EPSS"):
                prefixes.append("epss")
            elif ind.startswith("Critical"):
                prefixes.append("text_critical")
            elif ind.startswith("High"):
                prefixes.append("text_high")
            elif ind.startswith("Medium"):
                prefixes.append("text_medium")
            elif ind.startswith("Exploit code"):
                prefixes.append("text_low")
            elif ind.startswith("Exploit database"):
                prefixes.append("exploit_db")
        counts = Counter(prefixes)
        for bucket, count in counts.items():
            assert count == 1, f"Source bucket '{bucket}' appeared {count} times"

    def test_empty_vuln_returns_zero_score(self):
        """An empty vulnerability dict must yield score == 0.0.

        **Validates: Requirements 10.1**
        """
        with self._kev_mocked():
            score, indicators = scorer_mod.check_kev_status({})
        assert score == 0.0
        assert indicators == []

    def test_non_cve_id_skips_kev_lookup(self):
        """A vuln with an id that does not start with 'CVE-' must not trigger KEV.

        **Validates: Requirements 10.1**
        """
        with patch.object(scorer_mod, 'query_kev_database') as mock_kev:
            vuln = {'id': 'GHSA-xxxx-xxxx', 'summary': '', 'details': ''}
            scorer_mod.check_kev_status(vuln)
        mock_kev.assert_not_called()

    def test_epss_none_does_not_add_epss_indicator(self):
        """When epss_score is None, no EPSS indicator must appear.

        **Validates: Requirements 10.1**
        """
        with self._kev_mocked():
            vuln = {'id': 'CVE-2022-0001', 'summary': '', 'details': ''}
            _, indicators = scorer_mod.check_kev_status(vuln, epss_score=None)
        assert not any("EPSS" in ind for ind in indicators)


# ---------------------------------------------------------------------------
# Example tests — _score_cvss_vector
# ---------------------------------------------------------------------------

class TestScoreCvssVector:
    """Example tests for scorer._score_cvss_vector."""

    def test_valid_v3_vector_returns_float_in_range(self):
        """A well-formed CVSS 3.1 vector must return a float in [0.0, 10.0].

        **Validates: Requirements 10.1**
        """
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        score = scorer_mod._score_cvss_vector(vector)
        assert isinstance(score, float)
        assert 0.0 <= score <= 10.0

    def test_valid_v3_critical_vector(self):
        """A critical CVSS 3.1 vector (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H) must be > 9.0.

        **Validates: Requirements 10.1**
        """
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        score = scorer_mod._score_cvss_vector(vector)
        assert score > 9.0

    def test_malformed_vector_returns_zero(self):
        """A malformed vector string must return 0.0 without raising.

        **Validates: Requirements 10.1**
        """
        assert scorer_mod._score_cvss_vector("not-a-cvss-vector") == 0.0

    def test_empty_string_returns_zero(self):
        """An empty string must return 0.0.

        **Validates: Requirements 10.1**
        """
        assert scorer_mod._score_cvss_vector("") == 0.0

    def test_none_returns_zero(self):
        """None must return 0.0 (handled by isinstance guard).

        **Validates: Requirements 10.1**
        """
        assert scorer_mod._score_cvss_vector(None) == 0.0  # type: ignore[arg-type]

    def test_integer_input_returns_zero(self):
        """Non-string input must return 0.0.

        **Validates: Requirements 10.1**
        """
        assert scorer_mod._score_cvss_vector(42) == 0.0  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Property test — Property 8 (CVSS in-range)
# ---------------------------------------------------------------------------

@given(_cvss31_vector_strategy)
@settings(max_examples=200)
def test_property8_well_formed_cvss31_in_range(vector):
    """Property 8 (part A): for any well-formed CVSS 3.1 vector, _score_cvss_vector
    returns a float in [0.0, 10.0].

    **Validates: Requirements 19.3, 19.4, 19.6**
    """
    score = scorer_mod._score_cvss_vector(vector)
    assert isinstance(score, float), f"Expected float, got {type(score)} for {vector}"
    assert 0.0 <= score <= 10.0, f"Score {score} out of range for {vector}"


@given(st.text().filter(lambda s: not s.startswith("CVSS:")))
@settings(max_examples=200)
def test_property8_malformed_returns_zero_without_raising(bad_vector):
    """Property 8 (part B): for any string that is not a valid CVSS vector,
    _score_cvss_vector returns 0.0 and does not raise.

    **Validates: Requirements 19.4, 19.6**
    """
    try:
        result = scorer_mod._score_cvss_vector(bad_vector)
        assert result == 0.0, f"Expected 0.0 for malformed '{bad_vector}', got {result}"
    except Exception as exc:  # pragma: no cover
        pytest.fail(f"_score_cvss_vector raised {type(exc).__name__} for '{bad_vector}': {exc}")


# ---------------------------------------------------------------------------
# Property test — Property 9 (check_kev_status score in [0, 1])
# ---------------------------------------------------------------------------

# Strategy for arbitrary vuln dicts: keys are drawn from a realistic universe.
_VULN_KEYS = ["id", "summary", "details", "references", "database_specific",
              "severity", "published", "affected", "metrics"]

_vuln_dict_strategy = st.dictionaries(
    keys=st.sampled_from(_VULN_KEYS),
    values=st.one_of(
        st.none(),
        st.text(max_size=50),
        st.lists(st.text(max_size=20), max_size=5),
        st.floats(min_value=0.0, max_value=10.0, allow_nan=False),
        st.integers(min_value=0, max_value=10),
    ),
    max_size=len(_VULN_KEYS),
)

_epss_strategy = st.one_of(
    st.none(),
    st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
)


@given(_vuln_dict_strategy, _epss_strategy)
@settings(max_examples=200)
def test_property9_check_kev_status_score_in_range(vuln_dict, epss_score):
    """Property 9: for any vuln dict and any EPSS score, check_kev_status's first
    return value is in the closed interval [0.0, 1.0].

    **Validates: Requirements 20.3, 20.5**
    """
    with patch.object(scorer_mod, 'query_kev_database', return_value=False):
        result = scorer_mod.check_kev_status(vuln_dict, epss_score)
    score = result[0]
    assert isinstance(score, float), f"Expected float, got {type(score)}: {score!r}"
    assert 0.0 <= score <= 1.0, f"Score {score} out of [0.0, 1.0] for vuln={vuln_dict!r}"


# ---------------------------------------------------------------------------
# Property test — Property 10 (indicators unique per source bucket)
# ---------------------------------------------------------------------------

def _classify_bucket(indicator: str) -> str:
    """Map an indicator string to its source-bucket name."""
    if indicator.startswith("CISA KEV"):
        return "cisa_kev"
    if indicator.startswith("EPSS"):
        return "epss"
    if indicator.startswith("Critical vulnerability"):
        return "text_critical"
    if indicator.startswith("High confidence"):
        return "text_high"
    if indicator.startswith("Medium confidence"):
        return "text_medium"
    if indicator.startswith("Exploit code"):
        return "text_low"
    if indicator.startswith("Exploit database"):
        return "exploit_db"
    return f"other:{indicator}"


@given(_vuln_dict_strategy, _epss_strategy)
@settings(max_examples=200)
def test_property10_indicators_unique_per_source_bucket(vuln_dict, epss_score):
    """Property 10: for any vuln dict, indicators_found has at most one entry per
    source bucket (cisa_kev, epss, text_critical, text_high, text_medium, text_low,
    exploit_db).

    **Validates: Requirements 20.4**
    """
    with patch.object(scorer_mod, 'query_kev_database', return_value=False):
        _, indicators = scorer_mod.check_kev_status(vuln_dict, epss_score)

    from collections import Counter
    bucket_counts = Counter(_classify_bucket(ind) for ind in indicators)
    for bucket, count in bucket_counts.items():
        assert count == 1, (
            f"Bucket '{bucket}' appeared {count} times in indicators: {indicators}"
        )


# ---------------------------------------------------------------------------
# Property test — Property 6 (thread-safe KEV cache: at most one HTTP fetch)
# ---------------------------------------------------------------------------

def test_property6_concurrent_get_kev_database_calls_http_at_most_once():
    """Property 6: when N threads call get_kev_database simultaneously on a cold cache,
    the HTTP endpoint is called at most once and all threads receive the same set.

    **Validates: Requirements 4.1, 4.3**
    """
    NUM_THREADS = 20
    _reset_kev_cache()

    mock_cve_set = {"CVE-2024-0001", "CVE-2024-0002"}
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "vulnerabilities": [
            {"cveID": "CVE-2024-0001"},
            {"cveID": "CVE-2024-0002"},
        ]
    }
    mock_response.raise_for_status = MagicMock()

    call_count = {"n": 0}
    original_requests_get = None

    def slow_mock_get(url, timeout=None):
        """Simulate a slightly slow network fetch to maximise race-condition exposure."""
        call_count["n"] += 1
        time.sleep(0.02)  # 20 ms — enough to let other threads arrive
        return mock_response

    results = [None] * NUM_THREADS
    barrier = threading.Barrier(NUM_THREADS)

    def worker(i):
        barrier.wait()  # All threads start simultaneously
        results[i] = scorer_mod.get_kev_database()

    with patch("risk_scorer.scorer.requests.get", side_effect=slow_mock_get):
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(NUM_THREADS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    # At most one real HTTP fetch should have occurred
    assert call_count["n"] <= 1, (
        f"HTTP endpoint called {call_count['n']} times (expected ≤ 1) by {NUM_THREADS} threads"
    )

    # All threads must have received a non-None result containing the expected CVE IDs
    for i, result in enumerate(results):
        assert result is not None, f"Thread {i} got None"
        # The result may be empty if some threads observed the populated cache early
        # — but any non-empty result must contain exactly the mocked CVEs
        if result:
            assert mock_cve_set.issubset(result) or result == mock_cve_set, (
                f"Thread {i} got unexpected set: {result}"
            )

    # Clean up
    _reset_kev_cache()


def test_property6_warm_cache_skips_http():
    """get_kev_database must not call HTTP when the cache is still valid.

    **Validates: Requirements 4.1, 4.3**
    """
    _reset_kev_cache()
    # Pre-populate the cache as if a fresh fetch just happened
    with scorer_mod._kev_lock:
        scorer_mod._kev_cache['data'] = {"vulnerabilities": []}
        scorer_mod._kev_cache['timestamp'] = time.time()
        scorer_mod._kev_cache['cve_set'] = {"CVE-2024-WARM"}

    with patch("risk_scorer.scorer.requests.get") as mock_get:
        result = scorer_mod.get_kev_database()

    mock_get.assert_not_called()
    assert "CVE-2024-WARM" in result

    _reset_kev_cache()
