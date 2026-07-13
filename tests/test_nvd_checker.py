"""Tests for nvd_checker.py — lazy init, CVE validation, API key masking.

**Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5, 14.1, 14.2, 14.3, 14.4, 17.1, 17.2, 17.3, 17.4**
"""
import os
import re
import sys

from hypothesis import given, settings
from hypothesis import strategies as st

# Make src importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))


# ---------------------------------------------------------------------------
# Example tests — lazy init
# ---------------------------------------------------------------------------

def test_import_has_no_side_effects():
    """Importing nvd_checker must not call get_config or read environment at import time.

    **Validates: Requirements 17.1, 17.2**
    """
    from unittest.mock import patch
    # Reload the module inside a patch to detect any eager get_config calls
    import importlib
    import vulnerability_checker.nvd_checker as nvd_mod

    # Force a clean reload inside the patch
    with patch('config.get_config', side_effect=AssertionError("get_config called at import time")):
        # Just re-importing (already cached by Python) should NOT call get_config
        importlib.reload(nvd_mod)

    # After the reload, _config_loaded must still be False (no init happened)
    assert nvd_mod._config_loaded is False


# ---------------------------------------------------------------------------
# Example tests — _mask_api_key
# ---------------------------------------------------------------------------

def test_mask_api_key_redacts_value():
    """_mask_api_key must replace the key value with *** in any string.

    **Validates: Requirements 14.3, 14.4**
    """
    from vulnerability_checker.nvd_checker import _mask_api_key
    key = "mysecretapikey123"
    text = f"Request to https://api.example.com?apiKey={key}"
    masked = _mask_api_key(text, key)
    assert key not in masked
    assert "***" in masked


def test_mask_api_key_with_none_key():
    """_mask_api_key must return the original text unchanged when key is None or empty.

    **Validates: Requirements 14.3**
    """
    from vulnerability_checker.nvd_checker import _mask_api_key
    text = "some text"
    assert _mask_api_key(text, None) == text
    assert _mask_api_key(text, "") == text


# ---------------------------------------------------------------------------
# Example tests — _is_valid_api_key
# ---------------------------------------------------------------------------

def test_is_valid_api_key_rejects_short():
    """_is_valid_api_key must reject strings shorter than 8 characters.

    **Validates: Requirements 14.1**
    """
    from vulnerability_checker.nvd_checker import _is_valid_api_key
    assert _is_valid_api_key("short") is False
    assert _is_valid_api_key("1234567") is False  # exactly 7 chars


def test_is_valid_api_key_accepts_long_printable():
    """_is_valid_api_key must accept printable strings of 8+ characters.

    **Validates: Requirements 14.1, 14.2**
    """
    from vulnerability_checker.nvd_checker import _is_valid_api_key
    assert _is_valid_api_key("validapikey12345") is True


def test_is_valid_api_key_rejects_non_printable():
    """_is_valid_api_key must reject strings containing non-printable characters.

    **Validates: Requirements 14.1**
    """
    from vulnerability_checker.nvd_checker import _is_valid_api_key
    assert _is_valid_api_key("key\x00with\x01null") is False


# ---------------------------------------------------------------------------
# Example tests — _is_valid_cve_id
# ---------------------------------------------------------------------------

def test_is_valid_cve_id_accepts_valid():
    """_is_valid_cve_id must return True for properly-formatted CVE IDs.

    **Validates: Requirements 1.1, 1.2**
    """
    from vulnerability_checker.nvd_checker import _is_valid_cve_id
    assert _is_valid_cve_id("CVE-2024-1234") is True
    assert _is_valid_cve_id("CVE-1999-10000") is True


def test_is_valid_cve_id_rejects_invalid():
    """_is_valid_cve_id must return False for path-traversal attempts and malformed IDs.

    **Validates: Requirements 1.1, 1.3, 1.4**
    """
    from vulnerability_checker.nvd_checker import _is_valid_cve_id
    assert _is_valid_cve_id("../etc/passwd") is False
    assert _is_valid_cve_id("CVE-XXXX") is False
    assert _is_valid_cve_id("") is False
    assert _is_valid_cve_id("CVE-2024-\x00") is False


# ---------------------------------------------------------------------------
# Example tests — _load_cve_from_disk
# ---------------------------------------------------------------------------

def test_load_cve_from_disk_rejects_invalid_id():
    """_load_cve_from_disk must return None for invalid CVE IDs without performing file I/O.

    **Validates: Requirements 1.3, 1.4, 1.5**
    """
    from vulnerability_checker.nvd_checker import _load_cve_from_disk
    result = _load_cve_from_disk("../etc/passwd")
    assert result is None


def test_load_cve_from_disk_rejects_empty_id():
    """_load_cve_from_disk must return None for an empty string.

    **Validates: Requirements 1.3**
    """
    from vulnerability_checker.nvd_checker import _load_cve_from_disk
    result = _load_cve_from_disk("")
    assert result is None


# ---------------------------------------------------------------------------
# Property tests
# ---------------------------------------------------------------------------

@given(st.from_regex(r'CVE-\d{4}-\d+', fullmatch=True))
@settings(max_examples=200)
def test_property1_valid_cve_ids_accepted(cve_id):
    """Property 1: any string matching CVE-\\d{4}-\\d+ is accepted by _is_valid_cve_id.

    **Validates: Requirements 1.1, 1.2**
    """
    from vulnerability_checker.nvd_checker import _is_valid_cve_id
    assert _is_valid_cve_id(cve_id) is True


@given(st.text().filter(lambda s: not re.match(r'^CVE-\d{4}-\d+$', s)))
@settings(max_examples=200)
def test_property2_invalid_cve_ids_rejected(s):
    """Property 2: any string NOT matching CVE-\\d{4}-\\d+ is rejected, and _load_cve_from_disk
    returns None without raising.

    **Validates: Requirements 1.1, 1.3, 1.4, 1.5**
    """
    from vulnerability_checker.nvd_checker import _is_valid_cve_id, _load_cve_from_disk
    assert _is_valid_cve_id(s) is False
    result = _load_cve_from_disk(s)
    assert result is None


@given(
    st.text(min_size=8).filter(
        lambda s: all(c in __import__('string').printable for c in s)
    )
)
@settings(max_examples=200)
def test_property13_valid_api_keys_accepted(key):
    """Property 13 (part A): printable strings of length >= 8 are accepted by _is_valid_api_key.

    **Validates: Requirements 14.1, 14.2**
    """
    from vulnerability_checker.nvd_checker import _is_valid_api_key
    assert _is_valid_api_key(key) is True


@given(st.text(max_size=7))
@settings(max_examples=200)
def test_property13_short_api_keys_rejected(key):
    """Property 13 (part B): strings of length <= 7 are rejected by _is_valid_api_key.

    **Validates: Requirements 14.1**
    """
    from vulnerability_checker.nvd_checker import _is_valid_api_key
    assert _is_valid_api_key(key) is False
