"""
Unified Configuration for Dependency Security Scanner.
Centralizes all thresholds, lists, parameters, and external configuration.
"""

import yaml
import os


class DetectionConfig:
    """Unified configuration class for all scanner parameters."""

    # Similarity thresholds
    TYPOSQUATTING_SIMILARITY_EXISTING = 80  # For packages that exist (200 status)
    TYPOSQUATTING_SIMILARITY_MISSING = 75   # For packages that don't exist (404 status)
    COMMON_TARGETS_SIMILARITY = 70          # Threshold for adding common targets to candidates

    # Candidate generation limits (optimized for speed)
    MAX_MAVEN_CANDIDATES = 3               # Reduced from 5
    MAX_SIMPLE_CANDIDATES = 5              # Reduced from 8
    MAX_CANDIDATES_TO_CHECK_EXISTING = 2   # Reduced from 3 - For existing packages
    MAX_CANDIDATES_TO_CHECK_MISSING = 2    # Reduced from 3 - For missing packages
    MAX_COMMON_VARIATIONS = 1              # How many prefix variations to try

    # Popularity and scoring
    POPULARITY_DIFFERENCE_THRESHOLD = 20    # How much more popular candidate must be
    SIMILARITY_WEIGHT_MULTIPLIER = 10       # Weight for similarity in scoring
    LENGTH_DIFFERENCE_WEIGHT = 5            # Weight for length similarity
    ENDING_BONUS = 20                       # Bonus for packages ending with popular names
    POPULAR_PACKAGE_BONUS = 30              # Bonus for exact popular package matches
    WELL_KNOWN_PACKAGE_BONUS = 40           # Bonus for well-known packages

    # Versioning thresholds
    ABNORMAL_VERSION_MAJOR = 90             # Major version considered abnormally high
    PACKAGE_ABANDONMENT_YEARS = 2           # Years without update = abandoned

    # Package legitimacy thresholds
    PYPI_HIGH_POPULARITY_THRESHOLD = 50     # High popularity for PyPI
    PYPI_DESCRIPTION_MIN_LENGTH = 50        # Minimum description length
    PYPI_MULTIPLE_RELEASES_THRESHOLD = 5    # Minimum releases for legitimacy
    PYPI_MANY_RELEASES_THRESHOLD = 20       # Many releases threshold

    NPM_POPULARITY_THRESHOLD = 30           # NPM legitimacy threshold
    MAVEN_POPULARITY_THRESHOLD = 20         # Maven legitimacy threshold
    DEFAULT_POPULARITY_THRESHOLD = 30       # Default for other project types

    # Description requirements
    PACKAGE_DESCRIPTION_MIN_LENGTH = 20     # Minimum for "poor metadata" flag
    GOOD_DESCRIPTION_MIN_LENGTH = 100       # For popularity scoring

    # API and networking (loaded from config.yaml at class initialization)
    _external_config_cache = None

    @classmethod
    def _get_detection_config(cls):
        """Get detection configuration from config.yaml."""
        if cls._external_config_cache is None:
            cls._external_config_cache = cls.get_external_config()
        return cls._external_config_cache.get('detection', {})

    # Load timeouts from YAML
    REQUEST_TIMEOUT = None
    MAVEN_REQUEST_TIMEOUT = None

    # Prefixes and suffixes for candidate generation
    PREFIXES_TO_REMOVE = ['py-', 'python-', 'js-', 'node-']
    SUFFIXES_TO_REMOVE = ['-py', '-python', '-js', '-node', 'y', '2', '3']
    COMMON_PREFIXES = ['py-', 'python-', 'js-', 'node-']
    COMMON_VARIATIONS = ['py', 'py2', 'py3', 'python', 'python2', 'python3', 'js', 'node']

    # Character substitutions for typosquatting detection
    HIGH_PRIORITY_SUBSTITUTIONS = {
        'o': ['0', 'a'], '0': ['o'], 'l': ['1'], '1': ['l'],
        'rn': ['m'], 'm': ['rn'], 'a': ['o'], 'e': ['o'],
        'i': ['y'], 'y': ['i'], 'u': ['o']
    }

    VOWEL_REPLACEMENTS = 'aeiou'

    # Maven structural rules (algorithmic patterns - should stay)
    LEGITIMATE_MAVEN_PREFIXES = [
        # Generic top-level domains
        'com.', 'org.', 'net.', 'io.', 'edu.', 'gov.',
        # Well-known organizations and frameworks
        'org.springframework', 'org.apache', 'org.eclipse', 'org.hibernate',
        'org.jenkins-ci', 'io.jenkins', 'org.junit', 'org.slf4j',
        'org.mockito', 'org.testng', 'org.codehaus', 'org.sonatype',
        'com.google', 'com.fasterxml', 'com.github', 'com.amazonaws',
        'com.microsoft', 'com.oracle', 'com.sun', 'com.ibm',
        'io.netty', 'io.dropwizard', 'io.vertx', 'io.github',
        'de.eacg', 'ro.pippo', 'com.surenpi', 'com.vrondakis',
        'com.brianfromoregon', 'io.leetcrunch'
    ]

    # Base suspicious keywords (fundamental security patterns)
    SUSPICIOUS_MAVEN_KEYWORDS = [
        'test', 'fake', 'temp', 'example', 'evil', 'hack', 'malware'
    ]

    # Scoring limits
    MAX_POPULARITY_FROM_RELEASES = 50       # Max points from release count
    MAX_POPULARITY_FROM_AGE = 25            # Max points from package age
    MAX_POPULARITY_FROM_DOWNLOADS = 100     # Max points from NPM downloads
    MAX_POPULARITY_FROM_MAVEN_VERSIONS = 25  # Max points from Maven version count
    MAX_MAVEN_GROUP_DEPTH = 6               # Max allowed dots in Maven group
    MIN_PACKAGE_NAME_LENGTH = 2             # Minimum package name length
    MIN_MAVEN_GROUP_PART_LENGTH = 2         # Minimum Maven group part length
    MIN_MAVEN_DOMAIN_PART_LENGTH = 2        # Minimum Maven domain part length

    # Age-based scoring
    DOWNLOADS_PER_POPULARITY_POINT = 1000   # NPM downloads per popularity point
    AGE_YEARS_PER_POPULARITY_POINT = 5      # Years of age per popularity point

    @classmethod
    def get_similarity_threshold(cls, package_exists: bool) -> int:
        """Get similarity threshold based on whether package exists."""
        return cls.TYPOSQUATTING_SIMILARITY_EXISTING if package_exists else cls.TYPOSQUATTING_SIMILARITY_MISSING

    @classmethod
    def get_max_candidates_to_check(cls, package_exists: bool) -> int:
        """Get max candidates to check based on whether package exists."""
        return cls.MAX_CANDIDATES_TO_CHECK_EXISTING if package_exists else cls.MAX_CANDIDATES_TO_CHECK_MISSING

    @classmethod
    def get_popularity_threshold(cls, project_type: str) -> int:
        """Get popularity threshold for different project types."""
        thresholds = {
            'pypi': cls.PYPI_HIGH_POPULARITY_THRESHOLD,
            'npm': cls.NPM_POPULARITY_THRESHOLD,
            'maven': cls.MAVEN_POPULARITY_THRESHOLD
        }
        return thresholds.get(project_type, cls.DEFAULT_POPULARITY_THRESHOLD)

    @classmethod
    def get_external_config(cls):
        """
        Load external configuration from config.yaml.
        This replaces the old get_config() function.
        """
        config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            print(f"Warning: Configuration file not found at {config_path}")
            # Return default configuration
            return {
                'osv_api_url': "https://api.osv.dev/v1/querybatch",
                'nvd_api_url': "https://services.nvd.nist.gov/rest/json/cves/2.0",
                'detection': {
                    'request_timeout': 3,
                    'maven_request_timeout': 5
                }
            }


# Initialize timeouts from config.yaml when module loads
_config = DetectionConfig.get_external_config()
DetectionConfig.REQUEST_TIMEOUT = _config.get('detection', {}).get('request_timeout', 3)
DetectionConfig.MAVEN_REQUEST_TIMEOUT = _config.get('detection', {}).get('maven_request_timeout', 5)


# Backward compatibility function for existing imports
def get_config():
    """
    Backward compatibility function.
    Use DetectionConfig.get_external_config() instead.
    """
    return DetectionConfig.get_external_config()
