"""Tests for src/threat_analysis/trainer.py.

Covers:
  - trainer.main() completes without raising AttributeError when ThreatProcessor
    is mocked (verifies the learner.threat_processor attribute is used, not
    the non-existent learner.learning_system).
  - trainer.py source file contains no sys.path manipulation
    (sys.path.append / sys.path.insert).

**Validates: Requirements 10.1**
"""

import asyncio
import os
import sys

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

# ---------------------------------------------------------------------------
# Make the src/ tree importable
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

TRAINER_SOURCE_PATH = os.path.join(
    os.path.dirname(__file__), '..', 'src', 'threat_analysis', 'trainer.py'
)


def _read_trainer_source() -> str:
    """Return the raw source text of trainer.py."""
    with open(TRAINER_SOURCE_PATH, 'r', encoding='utf-8') as fh:
        return fh.read()


# ---------------------------------------------------------------------------
# Example test — no sys.path manipulation in trainer.py
# ---------------------------------------------------------------------------

class TestTrainerSourceCodeRequirements:
    """Verify that trainer.py no longer contains sys.path hacks."""

    def test_no_sys_path_append(self):
        """trainer.py must not contain sys.path.append(...).

        **Validates: Requirements 10.1, 15.1**
        """
        source = _read_trainer_source()
        assert 'sys.path.append' not in source, (
            "trainer.py still contains sys.path.append — this must be removed (Req 15.1)"
        )

    def test_no_sys_path_insert(self):
        """trainer.py must not contain sys.path.insert(...).

        **Validates: Requirements 10.1, 15.1**
        """
        source = _read_trainer_source()
        assert 'sys.path.insert' not in source, (
            "trainer.py still contains sys.path.insert — this must be removed (Req 15.1)"
        )

    def test_uses_relative_import_for_threat_processor(self):
        """trainer.py must use a relative import for threat_processor (not a sys.path hack).

        **Validates: Requirements 10.1, 15.1, 15.2**
        """
        source = _read_trainer_source()
        assert 'from .threat_processor import' in source, (
            "trainer.py should use a relative import: 'from .threat_processor import ...'"
        )

    def test_does_not_reference_learning_system_attribute(self):
        """trainer.py must not reference learner.learning_system (non-existent attribute).

        **Validates: Requirements 10.1, 6.2**
        """
        source = _read_trainer_source()
        assert 'learning_system' not in source, (
            "trainer.py still references 'learning_system' which does not exist on BatchLearner"
        )

    def test_references_threat_processor_save(self):
        """trainer.py must call learner.threat_processor.save_all_learning_data().

        **Validates: Requirements 10.1, 6.1**
        """
        source = _read_trainer_source()
        assert 'threat_processor.save_all_learning_data()' in source, (
            "trainer.py must call 'learner.threat_processor.save_all_learning_data()' (Req 6.1)"
        )


# ---------------------------------------------------------------------------
# Example test — main() does NOT raise AttributeError with mocked ThreatProcessor
# ---------------------------------------------------------------------------

class TestTrainerMain:
    """Verify that trainer.main() runs without AttributeError when dependencies
    are mocked to avoid live network calls."""

    def _make_mock_threat_processor(self):
        """Return a MagicMock with the required ThreatProcessor interface."""
        mock_tp = MagicMock()
        mock_tp.save_all_learning_data = MagicMock()
        mock_tp.learn_from_package = MagicMock()
        mock_tp.get_learning_stats.return_value = {
            'total_packages_learned': 0,
            'popular_packages_discovered': {'pypi': 0, 'npm': 0, 'maven': 0},
            'false_positives_reported': 0,
            'confirmed_typosquats': 0,
            'last_updated': '2024-01-01 00:00:00',
            'ecosystem_averages': {'pypi': 0.0, 'npm': 0.0, 'maven': 0.0},
        }
        return mock_tp

    def test_main_does_not_raise_attribute_error(self):
        """Calling trainer.main() with a mocked ThreatProcessor must not raise AttributeError.

        This verifies Req 6.1/6.2/6.3: the fixed code uses
        learner.threat_processor.save_all_learning_data() rather than the
        non-existent learner.learning_system.save_all_learning_data().

        **Validates: Requirements 10.1, 6.1, 6.2, 6.3**
        """
        import threat_analysis.trainer as trainer_mod

        mock_tp = self._make_mock_threat_processor()

        # Patch get_threat_processor so BatchLearner receives our mock instead of
        # creating a real ThreatProcessor (which would do disk I/O).
        with patch.object(trainer_mod, 'get_threat_processor', return_value=mock_tp):
            # Patch sys.argv so argparse sees an empty argument list (use defaults).
            with patch('sys.argv', ['trainer.py', '--limit', '0']):
                # Patch the async fetch helpers so no real HTTP calls are made.
                async def _empty_list(*args, **kwargs):
                    return []

                with patch.object(trainer_mod.BatchLearner, 'fetch_pypi_popular_packages',
                                  new=_empty_list), \
                     patch.object(trainer_mod.BatchLearner, 'fetch_npm_popular_packages',
                                  new=_empty_list), \
                     patch.object(trainer_mod.BatchLearner, 'fetch_maven_popular_packages',
                                  new=_empty_list):
                    try:
                        asyncio.run(trainer_mod.main())
                    except AttributeError as exc:
                        pytest.fail(
                            f"trainer.main() raised AttributeError: {exc}\n"
                            "This indicates the broken 'learner.learning_system' reference "
                            "was not fixed (Req 6.2)."
                        )
                    except SystemExit:
                        # argparse may call sys.exit on --help or invalid args; ignore.
                        pass

    def test_main_calls_save_all_learning_data(self):
        """trainer.main() must call threat_processor.save_all_learning_data() on the
        BatchLearner's threat_processor attribute (not on a non-existent learning_system).

        **Validates: Requirements 10.1, 6.1, 6.3**
        """
        import threat_analysis.trainer as trainer_mod

        mock_tp = self._make_mock_threat_processor()

        with patch.object(trainer_mod, 'get_threat_processor', return_value=mock_tp):
            with patch('sys.argv', ['trainer.py', '--limit', '0']):
                async def _empty_list(*args, **kwargs):
                    return []

                with patch.object(trainer_mod.BatchLearner, 'fetch_pypi_popular_packages',
                                  new=_empty_list), \
                     patch.object(trainer_mod.BatchLearner, 'fetch_npm_popular_packages',
                                  new=_empty_list), \
                     patch.object(trainer_mod.BatchLearner, 'fetch_maven_popular_packages',
                                  new=_empty_list):
                    try:
                        asyncio.run(trainer_mod.main())
                    except (AttributeError, SystemExit):
                        pass

        # save_all_learning_data must have been called on our mock ThreatProcessor.
        mock_tp.save_all_learning_data.assert_called()

    def test_batch_learner_has_threat_processor_attribute(self):
        """BatchLearner.__init__ must assign self.threat_processor (not self.learning_system).

        **Validates: Requirements 10.1, 6.1, 6.2**
        """
        import threat_analysis.trainer as trainer_mod

        mock_tp = self._make_mock_threat_processor()

        with patch.object(trainer_mod, 'get_threat_processor', return_value=mock_tp):
            learner = trainer_mod.BatchLearner()

        assert hasattr(learner, 'threat_processor'), (
            "BatchLearner must expose a 'threat_processor' attribute (Req 6.1)"
        )
        assert not hasattr(learner, 'learning_system'), (
            "BatchLearner must NOT expose a 'learning_system' attribute (Req 6.2)"
        )
        assert learner.threat_processor is mock_tp
