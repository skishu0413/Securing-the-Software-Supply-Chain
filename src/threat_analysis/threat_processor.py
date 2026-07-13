"""
Threat Processor

Enterprise-grade threat processing engine for adaptive threat intelligence analysis.
Automatically discovers attack patterns, analyzes threat landscapes, and optimizes
detection capabilities through continuous learning and pattern recognition.
"""

import json
import os
import pathlib
import sys
import time
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Set
import requests
from threading import Lock

from config import DetectionConfig

_MODULE_DIR = pathlib.Path(__file__).resolve().parent
_DEFAULT_CACHE_DIR = str(_MODULE_DIR.parent.parent / 'cache')


class ThreatProcessor:
    """
    Enterprise threat processing engine for adaptive security intelligence.

    Automatically processes threat data, analyzes attack patterns, and maintains
    real-time threat intelligence for enhanced security detection capabilities.
    """

    def __init__(self, cache_dir: str = _DEFAULT_CACHE_DIR):
        self.cache_dir = str(pathlib.Path(cache_dir).resolve())
        self.learning_data_file = os.path.join(self.cache_dir, "learning_data.json")
        self.popular_packages_file = os.path.join(self.cache_dir, "popular_packages.json")
        self.patterns_file = os.path.join(self.cache_dir, "learned_patterns.json")

        # Thread-safe lock for concurrent access
        self._lock = Lock()

        # Create cache directory if it doesn't exist
        os.makedirs(self.cache_dir, exist_ok=True)

        # Load existing learning data
        self.learning_data = self._load_learning_data()
        self.popular_packages = self._load_popular_packages()
        self.learned_patterns = self._load_learned_patterns()

        # In-memory false-positive exclusion set (not persisted; cleared on process restart)
        self._fp_exclusions: set[tuple[str, str, str]] = set()

        # Learning thresholds
        self.min_popularity_samples = 10
        self.popularity_update_interval = 24 * 3600  # 24 hours
        self.pattern_confidence_threshold = 0.7

    def _load_learning_data(self) -> Dict:
        """Load existing learning data from cache."""
        if os.path.exists(self.learning_data_file):
            try:
                with open(self.learning_data_file, 'r') as f:
                    return json.load(f)
            except (OSError, json.JSONDecodeError, ValueError) as e:
                # Intentionally suppressed: corrupt/missing cache falls back to defaults
                print(f"WARNING: Could not load learning data from cache: {e}", file=sys.stderr)

        return {
            'package_popularity': {},
            'ecosystem_stats': {
                'pypi': {'total_packages': 0, 'avg_popularity': 0},
                'npm': {'total_packages': 0, 'avg_popularity': 0},
                'maven': {'total_packages': 0, 'avg_popularity': 0}
            },
            'last_updated': 0,
            'similarity_patterns': defaultdict(list),
            'false_positives': [],
            'confirmed_typosquats': []
        }

    def _load_popular_packages(self) -> Dict[str, Set[str]]:
        """Load dynamically discovered popular packages."""
        if os.path.exists(self.popular_packages_file):
            try:
                with open(self.popular_packages_file, 'r') as f:
                    data = json.load(f)
                    # Convert lists back to sets
                    return {k: set(v) for k, v in data.items()}
            except (OSError, json.JSONDecodeError, ValueError) as e:
                # Intentionally suppressed: corrupt/missing cache falls back to defaults
                print(f"WARNING: Could not load popular packages from cache: {e}", file=sys.stderr)

        # Start with empty configuration - fully dynamic bootstrap
        return {
            'pypi': set(),
            'npm': set(),
            'maven': set()
        }

    def _load_learned_patterns(self) -> Dict:
        """Load learned typosquatting patterns."""
        if os.path.exists(self.patterns_file):
            try:
                with open(self.patterns_file, 'r') as f:
                    return json.load(f)
            except (OSError, json.JSONDecodeError, ValueError) as e:
                # Intentionally suppressed: corrupt/missing cache falls back to defaults
                print(f"WARNING: Could not load learned patterns from cache: {e}", file=sys.stderr)

        return {
            'character_substitutions': dict(DetectionConfig.HIGH_PRIORITY_SUBSTITUTIONS),
            'common_prefixes': list(DetectionConfig.COMMON_PREFIXES),
            'common_suffixes': list(DetectionConfig.SUFFIXES_TO_REMOVE),
            'package_name_patterns': {},
            'similarity_thresholds': {
                'pypi': {
                    'existing': DetectionConfig.TYPOSQUATTING_SIMILARITY_EXISTING,
                    'missing': DetectionConfig.TYPOSQUATTING_SIMILARITY_MISSING
                },
                'npm': {
                    'existing': DetectionConfig.TYPOSQUATTING_SIMILARITY_EXISTING,
                    'missing': DetectionConfig.TYPOSQUATTING_SIMILARITY_MISSING
                },
                'maven': {
                    'existing': DetectionConfig.TYPOSQUATTING_SIMILARITY_EXISTING,
                    'missing': DetectionConfig.TYPOSQUATTING_SIMILARITY_MISSING
                }
            }
        }

    def _save_learning_data(self):
        """Save learning data to cache."""
        try:
            with open(self.learning_data_file, 'w') as f:
                json.dump(self.learning_data, f, indent=2, default=str)
        except OSError as e:
            print(f"Warning: Could not save learning data: {e}", file=sys.stderr)

    def _save_popular_packages(self):
        """Save popular packages to cache."""
        try:
            # Convert sets to lists for JSON serialization
            data = {k: list(v) for k, v in self.popular_packages.items()}
            with open(self.popular_packages_file, 'w') as f:
                json.dump(data, f, indent=2)
        except OSError as e:
            print(f"Warning: Could not save popular packages: {e}", file=sys.stderr)

    def _save_learned_patterns(self):
        """Save learned patterns to cache."""
        try:
            with open(self.patterns_file, 'w') as f:
                json.dump(self.learned_patterns, f, indent=2)
        except OSError as e:
            print(f"Warning: Could not save learned patterns: {e}", file=sys.stderr)

    def learn_from_package(self, package_name: str, metadata: Dict, project_type: str):
        """Learn patterns from a real package (thread-safe)."""
        if not metadata:
            return

        with self._lock:
            # Calculate popularity score
            popularity = self._calculate_detailed_popularity(package_name, metadata, project_type)

            # Store package data
            package_key = f"{project_type}:{package_name}"
            self.learning_data['package_popularity'][package_key] = {
                'popularity': popularity,
                'last_seen': time.time(),
                'metadata_quality': self._assess_metadata_quality(metadata, project_type)
            }

            # Update ecosystem statistics
            ecosystem = self.learning_data['ecosystem_stats'][project_type]
            ecosystem['total_packages'] = ecosystem.get('total_packages', 0) + 1

            # Running average of popularity
            current_avg = ecosystem.get('avg_popularity', 0)
            total = ecosystem['total_packages']
            new_avg = ((current_avg * (total - 1)) + popularity) / total
            ecosystem['avg_popularity'] = new_avg

            # Update popular packages list
            if popularity > self._get_dynamic_popularity_threshold(project_type):
                self.popular_packages[project_type].add(package_name)

            # Learn naming patterns
            self._learn_naming_patterns(package_name, project_type)

            # Update last learning time
            self.learning_data['last_updated'] = time.time()

    def _calculate_detailed_popularity(self, package_name: str, metadata: Dict, project_type: str) -> float:
        """Calculate more sophisticated popularity score."""
        score = 0.0

        if project_type == 'pypi':
            info = metadata.get('info', {}) or {}
            releases = metadata.get('releases', {}) or {}

            # GitHub stars/repository quality
            project_urls = info.get('project_urls', {}) or {}
            homepage = info.get('home_page', '') or ''

            github_indicators = 0
            for url in [homepage] + list(project_urls.values()):
                if url and 'github.com' in url:
                    github_indicators += 1

            score += github_indicators * 15

            # Documentation quality
            description = (info.get('description') or info.get('summary') or '')
            if description:
                score += min(len(description) / 100, 20)

            # Release frequency and consistency
            if releases:
                recent_releases = 0
                now = datetime.now()

                for release_files in releases.values():
                    for file_info in release_files:
                        try:
                            upload_time = datetime.fromisoformat(file_info.get('upload_time', ''))
                            if (now - upload_time).days < 365:
                                recent_releases += 1
                        except (ValueError, TypeError):
                            # upload_time field missing or malformed; skip this file entry
                            pass

                score += min(recent_releases * 2, 30)
                score += min(len(releases) * 0.5, 25)

            # Maintainer indicators
            author = info.get('author') or ''
            maintainer = info.get('maintainer') or ''
            if author or maintainer:
                score += 10

        elif project_type == 'npm':
            # NPM-specific popularity calculation
            if 'downloads' in metadata:
                downloads = metadata.get('downloads', {}) or {}
                weekly_downloads = downloads.get('weekly', 0) if downloads else 0
                score += min(weekly_downloads / 1000, 50)

            # Repository quality
            repository = metadata.get('repository', {}) or {}
            if repository and 'github.com' in str(repository):
                score += 25

            # Dependency count (popular packages are often dependencies)
            if 'dependents' in metadata:
                score += min(metadata['dependents'] / 100, 30)

        elif project_type == 'maven':
            # Maven-specific popularity
            if 'versionCount' in metadata:
                score += min(metadata['versionCount'] * 2, 40)

            # Group legitimacy - check against learned patterns
            group_id = metadata.get('g', '')
            learned_patterns = self.get_learned_open_source_patterns()
            if any(group_id.startswith(prefix) for prefix in learned_patterns):
                score += 50

            # Age factor
            if 'timestamp' in metadata:
                age_years = (time.time() * 1000 - metadata['timestamp']) / (1000 * 60 * 60 * 24 * 365)
                if age_years > 2:
                    score += min(age_years * 5, 25)

        return score

    def _assess_metadata_quality(self, metadata: Dict, project_type: str) -> float:
        """Assess the quality of package metadata."""
        quality_score = 0.0

        if project_type == 'pypi':
            info = metadata.get('info', {})

            # Check for essential fields
            if info.get('description') or info.get('summary'):
                quality_score += 0.3
            if info.get('home_page') or info.get('project_urls'):
                quality_score += 0.2
            if info.get('author') or info.get('maintainer'):
                quality_score += 0.2
            if info.get('license'):
                quality_score += 0.1
            if metadata.get('releases'):
                quality_score += 0.2

        return min(quality_score, 1.0)

    def _learn_naming_patterns(self, package_name: str, project_type: str):
        """Learn common naming patterns for the ecosystem."""
        patterns = self.learned_patterns['package_name_patterns']
        ecosystem_patterns = patterns.setdefault(project_type, {
            'prefixes': {},
            'suffixes': {},
            'separators': {},
            'length_distribution': {}
        })

        # Analyze prefixes
        for prefix in ['py-', 'python-', 'js-', 'node-', 'lib', 'ng-']:
            if package_name.startswith(prefix):
                ecosystem_patterns['prefixes'][prefix] = ecosystem_patterns['prefixes'].get(prefix, 0) + 1

        # Analyze suffixes
        for suffix in ['-py', '-js', '-lib', '-core', '-utils', '-tool']:
            if package_name.endswith(suffix):
                ecosystem_patterns['suffixes'][suffix] = ecosystem_patterns['suffixes'].get(suffix, 0) + 1

        # Analyze separators
        if '-' in package_name:
            ecosystem_patterns['separators']['-'] = ecosystem_patterns['separators'].get('-', 0) + 1
        if '_' in package_name:
            ecosystem_patterns['separators']['_'] = ecosystem_patterns['separators'].get('_', 0) + 1
        if '.' in package_name:
            ecosystem_patterns['separators']['.'] = ecosystem_patterns['separators'].get('.', 0) + 1

        # Length distribution
        length_bucket = (len(package_name) // 5) * 5  # Group by 5s
        key_lb = str(length_bucket)
        ecosystem_patterns['length_distribution'][key_lb] = (
            ecosystem_patterns['length_distribution'].get(key_lb, 0) + 1
        )

    def _get_dynamic_popularity_threshold(self, project_type: str) -> float:
        """Get dynamic popularity threshold based on learned ecosystem data."""
        ecosystem = self.learning_data['ecosystem_stats'].get(project_type, {})
        avg_popularity = ecosystem.get('avg_popularity', 30)

        # Set threshold at 1.5x average popularity
        return avg_popularity * 1.5

    def get_dynamic_popular_packages(self, project_type: str) -> List[str]:
        """Get dynamically discovered popular packages with auto-bootstrap."""
        learned_packages = list(self.popular_packages.get(project_type, set()))

        # If we have sufficient learned data, use only that
        if len(learned_packages) >= 10:
            return learned_packages

        # If we have some learned data but not enough, combine with bootstrap
        if len(learned_packages) >= 3:
            bootstrap_packages = self.bootstrap_from_live_data(project_type)
            return list(set(learned_packages).union(set(bootstrap_packages)))

        # If we have no learned data, bootstrap from live sources
        return self.bootstrap_from_live_data(project_type)

    def get_dynamic_well_known_packages(self, project_type: str) -> List[str]:
        """Get well-known packages with learned data and auto-bootstrap."""
        learned_packages = list(self.popular_packages.get(project_type, set()))

        # If we have sufficient learned data, use high-popularity packages
        if len(learned_packages) >= 15:
            # Filter for very popular packages
            well_known = []
            threshold = self._get_dynamic_popularity_threshold(project_type) * 1.5
            for package in learned_packages:
                package_key = f"{project_type}:{package}"
                if package_key in self.learning_data['package_popularity']:
                    popularity = self.learning_data['package_popularity'][package_key]['popularity']
                    if popularity > threshold:
                        well_known.append(package)

            if len(well_known) >= 8:  # Minimum viable well-known packages
                return well_known

        # Bootstrap from live data if insufficient learned data
        bootstrap_packages = self.bootstrap_from_live_data(project_type)
        return list(set(bootstrap_packages).union(set(learned_packages)))

    def get_dynamic_similarity_threshold(self, project_type: str, package_exists: bool) -> int:
        """Get learned similarity threshold for the ecosystem."""
        thresholds = self.learned_patterns['similarity_thresholds'].get(project_type, {})
        key = 'existing' if package_exists else 'missing'

        # Start with default, adjust based on learning
        default_threshold = (DetectionConfig.TYPOSQUATTING_SIMILARITY_EXISTING
                             if package_exists
                             else DetectionConfig.TYPOSQUATTING_SIMILARITY_MISSING)
        base_threshold = thresholds.get(key, default_threshold)

        # Adjust based on false positive rate
        ecosystem_key = f"{project_type}:{key}"
        false_positive_rate = self._calculate_false_positive_rate(ecosystem_key)

        if false_positive_rate > 0.1:  # If >10% false positives, be stricter
            return min(base_threshold + 5, 95)
        elif false_positive_rate < 0.05:  # If <5% false positives, be more lenient
            return max(base_threshold - 5, 60)

        return base_threshold

    def _calculate_false_positive_rate(self, ecosystem_key: str) -> float:
        """Calculate false positive rate for adjusting thresholds."""
        # This would be implemented with user feedback or validation data
        # For now, return a reasonable default
        return 0.07

    def report_false_positive(self, package_name: str, claimed_target: str, project_type: str):
        """Report a false positive detection for learning."""
        # Add to in-memory exclusion set immediately so subsequent scans skip this triple
        self._fp_exclusions.add((package_name.lower(), claimed_target.lower(), project_type))

        self.learning_data['false_positives'].append({
            'package': package_name,
            'claimed_target': claimed_target,
            'project_type': project_type,
            'timestamp': time.time()
        })

        # Adjust thresholds if too many false positives
        if len(self.learning_data['false_positives']) % 10 == 0:
            self._adjust_thresholds_for_false_positives(project_type)

    def is_false_positive(self, package_name: str, claimed_target: str, project_type: str) -> bool:
        """Check if a package has been reported as a false positive in this process."""
        return (package_name.lower(), claimed_target.lower(), project_type) in self._fp_exclusions

    def report_confirmed_typosquat(self, package_name: str, target: str, project_type: str):
        """Report a confirmed typosquatting case for learning."""
        self.learning_data['confirmed_typosquats'].append({
            'package': package_name,
            'target': target,
            'project_type': project_type,
            'timestamp': time.time()
        })

    def _adjust_thresholds_for_false_positives(self, project_type: str):
        """Adjust similarity thresholds based on false positive feedback."""
        thresholds = self.learned_patterns['similarity_thresholds'][project_type]

        # Increase thresholds slightly to reduce false positives
        thresholds['existing'] = min(thresholds['existing'] + 2, 95)
        thresholds['missing'] = min(thresholds['missing'] + 2, 90)

    def should_update_popularity_data(self) -> bool:
        """Check if we should fetch new popularity data."""
        last_update = self.learning_data.get('last_updated', 0)
        return (time.time() - last_update) > self.popularity_update_interval

    def get_learned_common_targets(self, project_type: str) -> List[str]:
        """Get learned common targets for typosquatting detection."""
        # Get learned popular packages
        learned_targets = self.popular_packages.get(project_type, set())

        # If we have sufficient learned data, use only that
        if len(learned_targets) >= 8:
            filtered_targets = []
            for target in learned_targets:
                package_key = f"{project_type}:{target}"
                if package_key in self.learning_data['package_popularity']:
                    popularity = self.learning_data['package_popularity'][package_key]['popularity']
                    if popularity > self._get_dynamic_popularity_threshold(project_type):
                        filtered_targets.append(target)

            if len(filtered_targets) >= 5:  # Minimum viable targets
                return filtered_targets

        # Bootstrap from live data if insufficient learned data
        bootstrap_targets = self.bootstrap_from_live_data(project_type)
        return list(set(bootstrap_targets).union(learned_targets))

    def get_learned_tech_companies(self) -> List[str]:
        """Get dynamically learned tech companies from Maven groups."""
        # Extract learned tech companies from Maven groups we've seen
        learned_companies = set()

        for package_key in self.learning_data['package_popularity']:
            if package_key.startswith('maven:') and ':' in package_key:
                _, group_artifact = package_key.split(':', 1)
                if ':' in group_artifact:
                    group_id = group_artifact.split(':', 1)[0]
                    # Extract potential company names from group IDs
                    if group_id.startswith(('com.', 'org.', 'io.')):
                        parts = group_id.split('.')
                        if len(parts) >= 2:
                            potential_company = parts[1].lower()
                            if len(potential_company) > 3:  # Filter short/generic names
                                learned_companies.add(potential_company)

        # Combine with seed companies, prioritizing learned data
        if len(learned_companies) >= 8:
            return list(learned_companies)

        # If insufficient learned data, combine with basic tech companies
        basic_companies = [
            'google', 'microsoft', 'apache', 'oracle', 'spring', 'eclipse'
        ]
        return list(set(basic_companies).union(learned_companies))

    def get_learned_open_source_patterns(self) -> List[str]:
        """Get dynamically learned open source Maven patterns."""
        learned_patterns = set()

        # Analyze Maven groups we've seen for common open source patterns
        for package_key in self.learning_data['package_popularity']:
            if package_key.startswith('maven:') and ':' in package_key:
                _, group_artifact = package_key.split(':', 1)
                if ':' in group_artifact:
                    group_id = group_artifact.split(':', 1)[0]

                    # Look for common open source patterns (org.*, com.*, javax.*)
                    parts = group_id.split('.')
                    if len(parts) >= 2:
                        # Extract patterns like "org.apache.", "com.google.", etc.
                        if parts[0] in ['org', 'com', 'javax']:
                            if len(parts) >= 3:
                                pattern = '.'.join(parts[:3]) + '.'
                            else:
                                pattern = '.'.join(parts[:2]) + '.'
                            learned_patterns.add(pattern)
                    elif group_id.startswith('junit'):
                        learned_patterns.add('junit')

        # If we have learned enough patterns, use only those
        # Otherwise return empty list to let system learn from scratch
        return list(learned_patterns) if len(learned_patterns) >= 5 else []

    def bootstrap_from_live_data(self, project_type: str) -> List[str]:
        """
        Bootstrap popular packages by querying live package registries.
        This eliminates the need for manual seed package maintenance.
        """
        try:
            if project_type == 'pypi':
                return self._bootstrap_pypi_packages()
            elif project_type == 'npm':
                return self._bootstrap_npm_packages()
            elif project_type == 'maven':
                return self._bootstrap_maven_packages()
        except requests.exceptions.RequestException as e:
            print(f"Bootstrap failed for {project_type}: {e}", file=sys.stderr)

        # Return empty list to force learning from actual scanned packages
        # No hardcoded fallbacks - system will learn dynamically
        return []

    def _bootstrap_pypi_packages(self) -> List[str]:
        """Bootstrap from PyPI's most downloaded packages."""
        try:
            # Query PyPI's stats API for most popular packages
            response = requests.get(
                "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json",
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                # Extract top 20 package names
                popular = [pkg['project'].lower() for pkg in data['rows'][:20]]
                return popular
        except requests.exceptions.RequestException as e:
            # Network failure during optional bootstrap; system learns from scanned packages
            print(f"WARNING: Could not bootstrap PyPI packages: {e}", file=sys.stderr)

        # Return empty list - system will learn from actual scanned packages
        return []

    def _bootstrap_npm_packages(self) -> List[str]:
        """Bootstrap from npm's most downloaded packages."""
        try:
            # Query npm registry for popular packages
            # Note: npm doesn't have a simple popularity API, so we use known patterns
            response = requests.get(
                "https://registry.npmjs.org/-/v1/search?text=popularity-score:>0.8&size=20",
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                popular = [pkg['package']['name'] for pkg in data.get('objects', [])]
                return popular[:20]
        except requests.exceptions.RequestException as e:
            # Network failure during optional bootstrap; system learns from scanned packages
            print(f"WARNING: Could not bootstrap npm packages: {e}", file=sys.stderr)

        # Return empty list - system will learn from actual scanned packages
        return []

    def _bootstrap_maven_packages(self) -> List[str]:
        """Bootstrap Maven patterns from Maven Central."""
        # Maven is different - we learn from group patterns, not individual packages
        return []

    def get_learned_character_substitutions(self) -> Dict[str, List[str]]:
        """Get learned character substitutions."""
        return self.learned_patterns['character_substitutions']

    def get_learned_suspicious_keywords(self) -> List[str]:
        """Get dynamically learned suspicious Maven keywords."""
        # Start with base keywords from config
        base_keywords = DetectionConfig.SUSPICIOUS_MAVEN_KEYWORDS.copy()

        # Could be enhanced to learn from flagged packages in the future
        # For now, return the base set as these are fundamental security patterns
        return base_keywords

    def save_all_learning_data(self):
        """Save all learning data to cache files."""
        self._save_learning_data()
        self._save_popular_packages()
        self._save_learned_patterns()

    def get_learning_stats(self) -> Dict:
        """Get statistics about the learning system."""
        total_packages = sum(
            self.learning_data['ecosystem_stats'][eco].get('total_packages', 0)
            for eco in ['pypi', 'npm', 'maven']
        )

        return {
            'total_packages_learned': total_packages,
            'popular_packages_discovered': {
                eco: len(packages) for eco, packages in self.popular_packages.items()
            },
            'false_positives_reported': len(self.learning_data.get('false_positives', [])),
            'confirmed_typosquats': len(self.learning_data.get('confirmed_typosquats', [])),
            'last_updated': datetime.fromtimestamp(self.learning_data.get('last_updated', 0)),
            'ecosystem_averages': {
                eco: stats.get('avg_popularity', 0)
                for eco, stats in self.learning_data['ecosystem_stats'].items()
            }
        }


# Global threat processor instance
_threat_processor = None


def get_threat_processor() -> ThreatProcessor:
    """Get the global threat processor instance."""
    global _threat_processor
    if _threat_processor is None:
        _threat_processor = ThreatProcessor()
    return _threat_processor
