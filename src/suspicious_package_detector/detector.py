"""
Detects suspicious packages by checking for multiple indicators.
"""
import requests
import re
import sys
import os
import json
import hashlib
from datetime import datetime, timedelta
from thefuzz import fuzz
from packaging import version
from config import DetectionConfig
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from threat_analysis.threat_processor import get_threat_processor

# ─── Persistent metadata cache ───────────────────────────────────────────────
# In-memory layer (per-process, zero cost after first hit)
_metadata_cache = {}
_cache_lock = Lock()

# Disk cache – survives across runs so large dependency lists don't re-hit
# the registry on every scan.
_CACHE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'cache'
)
_PKG_CACHE_DIR = os.path.join(_CACHE_DIR, 'pkg_metadata')
_PKG_CACHE_TTL_HOURS = 24   # re-fetch after 24 h; balances freshness vs speed


def _pkg_cache_path(cache_key: str) -> str:
    """Return the disk path for a cache key (hash to avoid FS-illegal chars)."""
    safe = hashlib.sha256(cache_key.encode()).hexdigest()
    return os.path.join(_PKG_CACHE_DIR, f"{safe}.json")


def _load_from_disk_cache(cache_key: str):
    """Return (status_code, data) from disk, or None if missing/expired."""
    path = _pkg_cache_path(cache_key)
    try:
        if not os.path.exists(path):
            return None
        with open(path, 'r') as f:
            entry = json.load(f)
        saved_at = datetime.fromisoformat(entry['saved_at'])
        if datetime.now() - saved_at > timedelta(hours=_PKG_CACHE_TTL_HOURS):
            return None          # expired – let caller re-fetch
        return (entry['status'], entry['data'])
    except (OSError, json.JSONDecodeError, KeyError, ValueError):
        return None             # corrupt entry – re-fetch silently


def _save_to_disk_cache(cache_key: str, status: int, data) -> None:
    """Persist a registry response to disk."""
    try:
        os.makedirs(_PKG_CACHE_DIR, exist_ok=True)
        entry = {
            'saved_at': datetime.now().isoformat(),
            'status': status,
            'data': data,
        }
        path = _pkg_cache_path(cache_key)
        # Write atomically: write to temp file then rename
        tmp = path + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(entry, f)
        os.replace(tmp, path)
    except OSError:
        pass    # Non-fatal – next run will just re-fetch


def _cached_registry_call(cache_key: str, fetch_fn):
    """
    Two-level cache lookup:
      1. In-memory dict  (process lifetime, zero I/O)
      2. Disk cache      (cross-run, TTL-based)
    Falls through to fetch_fn() only on a true miss.
    """
    # Level 1 – in-memory
    with _cache_lock:
        if cache_key in _metadata_cache:
            return _metadata_cache[cache_key]

    # Level 2 – disk
    disk_hit = _load_from_disk_cache(cache_key)
    if disk_hit is not None:
        with _cache_lock:
            _metadata_cache[cache_key] = disk_hit
        return disk_hit

    # Cache miss – hit the network
    result = fetch_fn()

    # Persist to both layers (only cache definitive answers)
    _save_to_disk_cache(cache_key, result[0], result[1])
    with _cache_lock:
        _metadata_cache[cache_key] = result
    return result
# ─────────────────────────────────────────────────────────────────────────────


def generate_typosquat_candidates(package_name, project_type='pypi'):
    """
    Generate potential legitimate package names that the given package might be typosquatting.
    """
    candidates = set()
    base_name = package_name.lower()

    if ':' in base_name:
        group_id, artifact_id = base_name.split(':', 1)

        # PRIORITY 1: Well-known corrections (most important)
        well_known_corrections = {
            'org.apache.commmons': 'org.apache.commons',
            'org.apache.common': 'org.apache.commons',
            'org.springframwork': 'org.springframework',
            'org.springframework.framework': 'org.springframework',
            'com.fasterxml.jacksoon': 'com.fasterxml.jackson.core',
            'com.fasterxml.jakson': 'com.fasterxml.jackson.core',
            'com.fasterxml.jackson': 'com.fasterxml.jackson.core',
            'org.hybernate': 'org.hibernate',
            'org.hibernat': 'org.hibernate',
            'org.junit.jupiter': 'org.junit',
            'com.google.guav': 'com.google.guava'
        }

        priority_candidates = []
        if group_id in well_known_corrections:
            corrected_group = well_known_corrections[group_id]
            priority_candidates.append(f"{corrected_group}:{artifact_id}")

        # PRIORITY 2: Generate corrected group IDs for obvious typos
        group_candidates = generate_simple_candidates(group_id.replace('.', '-'), 'maven')
        for group_candidate in group_candidates[:1]:  # Reduced to 1 to save space
            corrected_group = group_candidate.replace('-', '.')
            if corrected_group != group_id:
                candidates.add(f"{corrected_group}:{artifact_id}")

        # PRIORITY 3: Generate corrected artifact IDs
        artifact_candidates = generate_simple_candidates(artifact_id, 'maven')
        for artifact in artifact_candidates[:1]:  # Reduced to 1 to save space
            if artifact != artifact_id:
                candidates.add(f"{group_id}:{artifact}")

        # Convert to list and prioritize well-known corrections at the front
        candidates_list = priority_candidates + list(candidates)

        # Remove duplicates while preserving order
        seen = set()
        final_candidates = []
        for candidate in candidates_list:
            if candidate not in seen and candidate != base_name:
                seen.add(candidate)
                final_candidates.append(candidate)

        return final_candidates[:DetectionConfig.MAX_MAVEN_CANDIDATES]

    simple_candidates = list(generate_simple_candidates(base_name, project_type))
    return simple_candidates[:DetectionConfig.MAX_SIMPLE_CANDIDATES]


def generate_simple_candidates(base_name, project_type='pypi'):
    """Helper function to generate candidates for a simple package name (non-Maven)."""
    candidates = set()
    threat_processor = get_threat_processor()

    if '-' in base_name:
        parts = base_name.split('-', 1)
        if len(parts) == 2:
            prefix, suffix = parts
            for variation in DetectionConfig.COMMON_VARIATIONS[:DetectionConfig.MAX_COMMON_VARIATIONS]:
                if prefix != variation:
                    candidates.add(f"{variation}-{suffix}")
            candidates.add(suffix)

            # Add variations with numbers (e.g., py-requests -> py2-requests, py3-requests)
            for num in ['2', '3', '4']:
                candidates.add(f"{prefix}{num}-{suffix}")
                # Also try without hyphen
                candidates.add(f"{prefix}{num}{suffix}")

    for prefix in DetectionConfig.COMMON_PREFIXES:
        if not base_name.startswith(prefix.rstrip('-')):
            candidates.add(f"{prefix}{base_name}")

    for suffix in DetectionConfig.SUFFIXES_TO_REMOVE:
        if base_name.endswith(suffix) and len(base_name) > len(suffix):
            candidates.add(base_name[:-len(suffix)])

    deduped = re.sub(r'(.)\1+', r'\1', base_name)
    if deduped != base_name:
        candidates.add(deduped)

    # Use learned character substitutions
    learned_substitutions = threat_processor.get_learned_character_substitutions()
    for i, char in enumerate(base_name):
        if char in learned_substitutions:
            for replacement in learned_substitutions[char]:
                new_candidate = base_name[:i] + replacement + base_name[i+1:]
                candidates.add(new_candidate)

    for i in range(len(base_name)):
        for replacement_char in DetectionConfig.VOWEL_REPLACEMENTS:
            if base_name[i] != replacement_char:
                new_candidate = base_name[:i] + replacement_char + base_name[i+1:]
                candidates.add(new_candidate)

    if 'rn' in base_name:
        candidates.add(base_name.replace('rn', 'm'))
    if 'm' in base_name:
        candidates.add(base_name.replace('m', 'rn'))

    if '-' in base_name:
        candidates.add(base_name.replace('-', ''))
        candidates.add(base_name.replace('-', '_'))
    if '_' in base_name:
        candidates.add(base_name.replace('_', ''))
        candidates.add(base_name.replace('_', '-'))

    if len(base_name) > 3:
        candidates.add(base_name[:-1])
        candidates.add(base_name[1:])

    candidates.discard('')
    candidates = {c for c in candidates if len(c) >= DetectionConfig.MIN_PACKAGE_NAME_LENGTH}

    candidate_list = list(candidates)

    def candidate_priority(candidate):
        score = 0

        similarity = fuzz.ratio(base_name, candidate)
        score += similarity * DetectionConfig.SIMILARITY_WEIGHT_MULTIPLIER

        score += (10 - abs(len(candidate) - len(base_name))) * DetectionConfig.LENGTH_DIFFERENCE_WEIGHT

        # Use dynamic popular packages instead of hardcoded
        popular_packages = threat_processor.get_dynamic_popular_packages(project_type)
        well_known_packages = threat_processor.get_dynamic_well_known_packages(project_type)

        # Check for popular package endings
        if any(candidate.endswith(pkg) for pkg in popular_packages):
            score += DetectionConfig.ENDING_BONUS

        if candidate in popular_packages:
            score += DetectionConfig.POPULAR_PACKAGE_BONUS

        if candidate in well_known_packages:
            score += DetectionConfig.WELL_KNOWN_PACKAGE_BONUS

        return score

    # Use learned common targets instead of static list
    common_targets = threat_processor.get_learned_common_targets(project_type)
    for target in common_targets:
        if target not in candidate_list:
            similarity = fuzz.ratio(base_name, target)
            if similarity >= DetectionConfig.COMMON_TARGETS_SIMILARITY:
                candidate_list.append(target)

    candidate_list.sort(key=candidate_priority, reverse=True)

    return candidate_list


def is_legitimate_maven_group(group_id):
    """
    Dynamically determine if a Maven groupId follows legitimate patterns.
    Rejects private/internal package patterns.
    """
    if not group_id or len(group_id) < 3:
        return False

    parts = group_id.split('.')
    if len(parts) < 2:
        return False

    # Check for private/internal package indicators (high priority)
    private_indicators = [
        'company', 'enterprise', 'private', 'internal', 'mycompany',
        'myorg', 'corp', 'organization', 'example', 'test', 'temp',
        'demo', 'sample', 'local', 'custom'
    ]

    # Reject if any part contains private indicators
    for part in parts:
        if part.lower() in private_indicators:
            return False
        # Reject generic single-word patterns like "com.company" or "org.internal"
        if len(parts) == 2 and part.lower() in private_indicators:
            return False

    # Use dynamic suspicious keywords
    threat_processor = get_threat_processor()
    suspicious_keywords = threat_processor.get_learned_suspicious_keywords()
    if any(part in suspicious_keywords for part in parts):
        return False

    if len(parts) > 1 and any(char.isdigit() for char in parts[1]):
        return False

    if len(parts) > 1 and len(parts[1]) <= DetectionConfig.MIN_MAVEN_DOMAIN_PART_LENGTH:
        return False

    if group_id.count('.') > DetectionConfig.MAX_MAVEN_GROUP_DEPTH:
        return False

    if any(len(part) < DetectionConfig.MIN_MAVEN_GROUP_PART_LENGTH for part in parts):
        return False

    if any(group_id.startswith(prefix) for prefix in DetectionConfig.LEGITIMATE_MAVEN_PREFIXES):
        if len(parts) >= 3:
            domain_part = parts[1]
            if len(domain_part) >= DetectionConfig.MIN_MAVEN_DOMAIN_PART_LENGTH and domain_part.isalpha():
                return True

    # Use dynamic open source patterns
    open_source_patterns = threat_processor.get_learned_open_source_patterns()
    for pattern in open_source_patterns:
        if group_id.startswith(pattern):
            return True

    # Use dynamic tech companies
    tech_companies = threat_processor.get_learned_tech_companies()
    if len(parts) >= 2:
        for company in tech_companies:
            if company in group_id.lower():
                return True

    if '.' in group_id and len(parts) >= 2:
        if all(len(part) >= DetectionConfig.MIN_MAVEN_GROUP_PART_LENGTH and
               part.replace('-', '').replace('_', '').isalnum() for part in parts):
            return True

    return False


def check_package_popularity(package_name, metadata, project_type):
    """
    Estimate package popularity based on download counts, stars, or other metrics.
    """
    if not metadata:
        return 0

    popularity_score = 0

    if project_type == 'pypi':
        info = metadata.get('info', {})

        if info.get('home_page') or info.get('project_urls'):
            popularity_score += 10

        description = info.get('description', '')
        if description and len(description) > DetectionConfig.GOOD_DESCRIPTION_MIN_LENGTH:
            popularity_score += 10

        releases = metadata.get('releases', {})
        popularity_score += min(len(releases), DetectionConfig.MAX_POPULARITY_FROM_RELEASES)

        if releases:
            latest_versions = sorted(releases.keys(), key=lambda x: len(releases[x]), reverse=True)
            if latest_versions and releases[latest_versions[0]]:
                popularity_score += 20

        first_release_date = None
        if releases:
            all_release_dates = []
            for release_files in releases.values():
                for file_info in release_files:
                    if 'upload_time' in file_info:
                        try:
                            all_release_dates.append(datetime.fromisoformat(file_info['upload_time']))
                        except (ValueError, TypeError):
                            # upload_time field malformed; skip this file entry
                            pass
            if all_release_dates:
                first_release_date = min(all_release_dates)
                age_years = (datetime.now() - first_release_date).days / 365.25
                popularity_score += min(age_years * DetectionConfig.AGE_YEARS_PER_POPULARITY_POINT,
                                        DetectionConfig.MAX_POPULARITY_FROM_AGE)

    elif project_type == 'npm':
        if 'downloads' in metadata:
            downloads = metadata.get('downloads', {}).get('weekly', 0)
            popularity_score += min(downloads // DetectionConfig.DOWNLOADS_PER_POPULARITY_POINT,
                                    DetectionConfig.MAX_POPULARITY_FROM_DOWNLOADS)

        repository = metadata.get('repository', {})
        if repository and 'github.com' in str(repository):
            popularity_score += 20

    elif project_type == 'maven':
        if 'timestamp' in metadata:
            import time
            age_days = (time.time() * 1000 - metadata['timestamp']) / (1000 * 60 * 60 * 24)
            if age_days < 365:
                popularity_score += 10
            elif age_days > 365 * 3:
                popularity_score += 20

        if 'g' in metadata:
            group_id = metadata['g']
            if is_legitimate_maven_group(group_id):
                popularity_score += 30

        if 'versionCount' in metadata:
            popularity_score += min(metadata['versionCount'],
                                    DetectionConfig.MAX_POPULARITY_FROM_MAVEN_VERSIONS)

    return popularity_score


def is_legitimate_package(package_name, metadata, project_type):
    """
    Determine if a package is likely legitimate and established.
    """
    if not metadata:
        return False

    popularity = check_package_popularity(package_name, metadata, project_type)

    if project_type == 'pypi':
        info = metadata.get('info', {})
        releases = metadata.get('releases', {})

        description = info.get('description', '')
        has_good_description = description and len(description) > DetectionConfig.PYPI_DESCRIPTION_MIN_LENGTH
        has_multiple_releases = len(releases) > DetectionConfig.PYPI_MULTIPLE_RELEASES_THRESHOLD
        has_homepage = bool(info.get('home_page') or info.get('project_urls'))

        if popularity > DetectionConfig.get_popularity_threshold('pypi'):
            return True

        well_known_indicators = [
            has_good_description and has_multiple_releases,
            has_homepage and has_multiple_releases,
            len(releases) > DetectionConfig.PYPI_MANY_RELEASES_THRESHOLD
        ]

        return any(well_known_indicators)

    elif project_type == 'npm':
        return popularity > DetectionConfig.get_popularity_threshold('npm')

    elif project_type == 'maven':
        if popularity > DetectionConfig.get_popularity_threshold('maven'):
            return True

        if ':' in package_name:
            group_id, _ = package_name.split(':', 1)
            if is_legitimate_maven_group(group_id):
                return True

        return False

    return popularity > DetectionConfig.get_popularity_threshold('default')


def get_pypi_metadata(package_name):
    """Fetches package metadata from the PyPI JSON API with two-level caching."""
    cache_key = f"pypi:{package_name}"

    def fetch():
        try:
            response = requests.get(
                f"https://pypi.org/pypi/{package_name}/json",
                timeout=DetectionConfig.REQUEST_TIMEOUT
            )
            if response.status_code == 404:
                return (404, None)
            elif response.status_code == 200:
                return (200, response.json())
            else:
                response.raise_for_status()
                return (response.status_code, response.json())
        except requests.exceptions.RequestException:
            return (500, None)

    return _cached_registry_call(cache_key, fetch)


def get_npm_metadata(package_name):
    """Fetches package metadata from the npm registry API with two-level caching."""
    cache_key = f"npm:{package_name}"

    def fetch():
        try:
            response = requests.get(
                f"https://registry.npmjs.org/{package_name}",
                timeout=DetectionConfig.REQUEST_TIMEOUT
            )
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, dict) and data.get('error') == 'Not found':
                    return (404, None)
                elif isinstance(data, dict) and data.get('name', '').lower() != package_name.lower():
                    return (404, None)
                else:
                    return (200, data)
            else:
                return (response.status_code, None)
        except requests.exceptions.RequestException:
            return (500, None)

    return _cached_registry_call(cache_key, fetch)


def get_maven_metadata(package_name):
    """Checks for a Maven package's existence using the Maven Central search API with two-level caching."""
    cache_key = f"maven:{package_name}"

    def fetch():
        try:
            group_id, artifact_id = package_name.split(':')
            url = (
                f"https://search.maven.org/solrsearch/select"
                f"?q=g:\"{group_id}\"+AND+a:\"{artifact_id}\"&rows=1&wt=json"
            )
            response = requests.get(
                url,
                timeout=DetectionConfig.MAVEN_REQUEST_TIMEOUT,
                headers={'User-Agent': 'Dependency-Security-Scanner'}
            )
            if response.status_code == 200:
                data = response.json()
                if data['response']['numFound'] > 0:
                    return (200, data['response']['docs'][0])
                else:
                    return (404, None)
            elif response.status_code == 403:
                if is_legitimate_maven_group(group_id):
                    return (200, {
                        'g': group_id, 'a': artifact_id,
                        'timestamp': 1640995200000, 'versionCount': 10,
                        'description': f'Legitimate package from {group_id}',
                        'legitimate_group': True
                    })
                else:
                    return (404, None)
            else:
                return (response.status_code, None)
        except (requests.exceptions.RequestException, ValueError, requests.exceptions.Timeout):
            group_id_parts = package_name.split(':')
            if len(group_id_parts) >= 2:
                gid = group_id_parts[0]
                if is_legitimate_maven_group(gid):
                    return (200, {
                        'g': gid, 'a': group_id_parts[1],
                        'timestamp': 1640995200000, 'versionCount': 10,
                        'description': f'Legitimate package from {gid}',
                        'legitimate_group': True
                    })
            return (500, None)

    return _cached_registry_call(cache_key, fetch)


def check_candidates_batch(candidates, dep_name, project_type, current_metadata=None, current_popularity=None):
    """
    Check multiple candidates in parallel for typosquatting.
    Returns the best match found (if any) with its details.
    Uses threat analysis to pre-filter and optimize checking.
    """
    threat_processor = get_threat_processor()

    # Pre-filter candidates using threat analysis
    # Prioritize learned popular packages
    popular_packages = threat_processor.get_dynamic_popular_packages(project_type)
    well_known_packages = threat_processor.get_dynamic_well_known_packages(project_type)

    # Score and sort candidates
    def candidate_score(candidate):
        score = fuzz.ratio(dep_name, candidate) * 10
        if candidate in well_known_packages:
            score += 500  # Highest priority
        elif candidate in popular_packages:
            score += 300  # High priority
        return score

    candidates_sorted = sorted(candidates, key=candidate_score, reverse=True)

    # Early check: If top candidate is well-known and highly similar, check it first
    if candidates_sorted:
        top_candidate = candidates_sorted[0]
        top_similarity = fuzz.ratio(dep_name, top_candidate)

        if top_candidate in well_known_packages and top_similarity >= 75:
            # Quick check this one first before batch processing
            status, metadata = get_package_metadata(top_candidate, project_type)
            if status == 200 and metadata:
                threat_processor.learn_from_package(top_candidate, metadata, project_type)
                candidate_popularity = check_package_popularity(top_candidate, metadata, project_type)

                # Determine thresholds
                similarity_threshold = threat_processor.get_dynamic_similarity_threshold(
                    project_type, package_exists=(current_metadata is not None)
                )

                if current_metadata:
                    # Existing package case
                    popularity_threshold = DetectionConfig.POPULARITY_DIFFERENCE_THRESHOLD
                    if (top_similarity >= similarity_threshold and
                            candidate_popularity >= current_popularity + popularity_threshold):
                        return {
                            'similar_to': top_candidate,
                            'similarity': top_similarity,
                            'candidate_popularity': candidate_popularity
                        }
                else:
                    # Missing package case
                    if (top_similarity >= similarity_threshold and
                            is_legitimate_package(top_candidate, metadata, project_type)):
                        return {
                            'similar_to': top_candidate,
                            'similarity': top_similarity,
                            'candidate_popularity': candidate_popularity
                        }

    # Batch process remaining candidates with parallel execution
    best_match = None
    best_similarity = 0
    best_candidate_popularity = 0

    # Limit candidates to check based on context
    max_candidates = DetectionConfig.get_max_candidates_to_check(package_exists=(current_metadata is not None))
    candidates_to_check = candidates_sorted[:max_candidates]

    # Parallel candidate checking - thread-safe since cache uses a Lock
    results = []
    with ThreadPoolExecutor(max_workers=min(len(candidates_to_check), 5)) as pool:
        future_to_candidate = {
            pool.submit(get_package_metadata, candidate, project_type): candidate
            for candidate in candidates_to_check
        }
        for future in as_completed(future_to_candidate):
            candidate = future_to_candidate[future]
            try:
                cand_status, cand_metadata = future.result()
                results.append((candidate, cand_status, cand_metadata))
            except requests.exceptions.RequestException as e:
                print(f"WARNING: Error fetching metadata for candidate '{candidate}': {e}", file=sys.stderr)

    for candidate, cand_status, cand_metadata in results:
        if cand_status == 200 and cand_metadata:
            # Learn from this package
            threat_processor.learn_from_package(candidate, cand_metadata, project_type)

            similarity = fuzz.ratio(dep_name, candidate)
            similarity_threshold = threat_processor.get_dynamic_similarity_threshold(
                project_type, package_exists=(current_metadata is not None)
            )

            if similarity >= similarity_threshold:
                candidate_popularity = check_package_popularity(candidate, cand_metadata, project_type)

                if current_metadata:
                    # Existing package case - check if candidate is more popular
                    popularity_threshold = DetectionConfig.POPULARITY_DIFFERENCE_THRESHOLD
                    if candidate_popularity >= current_popularity + popularity_threshold:
                        score = similarity + (candidate_popularity / 10)
                        best_score = best_similarity + (best_candidate_popularity / 10)

                        if score > best_score:
                            best_similarity = similarity
                            best_match = candidate
                            best_candidate_popularity = candidate_popularity
                else:
                    # Missing package case - check if candidate is legitimate
                    if is_legitimate_package(candidate, cand_metadata, project_type):
                        if similarity > best_similarity:
                            best_similarity = similarity
                            best_match = candidate
                            best_candidate_popularity = candidate_popularity

    # Return best match if found and meets thresholds
    if best_match:
        similarity_threshold = threat_processor.get_dynamic_similarity_threshold(
            project_type, package_exists=(current_metadata is not None)
        )

        if current_metadata:
            popularity_threshold = DetectionConfig.POPULARITY_DIFFERENCE_THRESHOLD
            if (best_similarity >= similarity_threshold and
                    best_candidate_popularity > current_popularity + popularity_threshold):
                return {
                    'similar_to': best_match,
                    'similarity': best_similarity,
                    'candidate_popularity': best_candidate_popularity
                }
        else:
            if best_similarity >= similarity_threshold:
                return {
                    'similar_to': best_match,
                    'similarity': best_similarity,
                    'candidate_popularity': best_candidate_popularity
                }

    return None


def get_package_metadata(package_name, project_type):
    """Unified function to get package metadata based on project type."""
    if project_type == 'pypi':
        return get_pypi_metadata(package_name)
    elif project_type == 'npm':
        return get_npm_metadata(package_name)
    elif project_type == 'maven':
        return get_maven_metadata(package_name)
    else:
        return 500, None


def process_single_dependency(dep, project_type, threat_processor):
    """
    Process a single dependency for suspicious patterns.
    Uses prioritized waterfall approach:
    1. Typosquatting (highest priority)
    2. Dependency Confusion
    3. Unusual Versioning
    4. Poor Metadata
    5. Abnormal Update Frequency (lowest priority)

    Once a package is flagged in a higher priority category,
    lower priority checks are skipped to avoid duplicate classifications.
    """
    dep_name = dep['name'].lower()
    dep_version = dep.get('version')
    findings = []

    # Check if package has private/internal indicators (Maven-specific)
    is_private_package = False
    if project_type == 'maven':
        private_indicators = [
            'company', 'enterprise', 'private', 'internal', 'mycompany',
            'myorg', 'corp', 'organization', 'example', 'test', 'temp',
            'demo', 'sample', 'local', 'custom'
        ]
        package_parts = dep_name.split(':')[0].split('.')  # Get groupId parts
        is_private_package = any(part in private_indicators for part in package_parts)

    # Use dynamic popular packages list instead of static
    dynamic_well_known = threat_processor.get_dynamic_popular_packages(project_type)
    skip_typosquat_check = dep_name in dynamic_well_known or is_private_package  # Skip typosquat for private packages

    # PRIORITY 1: Typosquatting Check (only for pypi, npm, maven)
    if project_type in ['pypi', 'npm', 'maven'] and not skip_typosquat_check:
        current_status, current_metadata = get_package_metadata(dep_name, project_type)

        if current_status == 200 and current_metadata:
            # Learn from this package
            threat_processor.learn_from_package(dep_name, current_metadata, project_type)

            if not is_legitimate_package(dep_name, current_metadata, project_type):
                candidates = generate_typosquat_candidates(dep_name, project_type)
                current_popularity = check_package_popularity(dep_name, current_metadata, project_type)

                # Use optimized batch checking with parallel API calls
                match_result = check_candidates_batch(
                    candidates, dep_name, project_type,
                    current_metadata, current_popularity
                )

                if match_result:
                    if not threat_processor.is_false_positive(dep_name, match_result['similar_to'], project_type):
                        findings.append({
                            'type': 'Typosquatting',
                            'details': {
                                'similar_to': match_result['similar_to'],
                                'similarity': match_result['similarity']
                            }
                        })
                    # Stop here - typosquatting detected (or excluded), skip remaining checks
                    return dep_name, findings

        status_code, metadata = current_status, current_metadata
    else:
        status_code, metadata = get_package_metadata(dep_name, project_type)

    # PRIORITY 2: Dependency Confusion (package not found)
    if status_code == 404:
        # Skip typosquatting check for private packages - they should be flagged as dependency confusion
        if project_type in ['pypi', 'npm', 'maven'] and not is_private_package:
            candidates = generate_typosquat_candidates(dep_name, project_type)

            # Fast pre-filter: Check top 5 most likely candidates for missing packages
            popular_packages = threat_processor.get_dynamic_popular_packages(project_type)

            # Sort by popularity first
            priority_candidates = [c for c in candidates if c in popular_packages][:5]
            if len(priority_candidates) < 5:
                # Add other high-similarity candidates
                remaining = [c for c in candidates if c not in popular_packages]
                priority_candidates.extend(remaining[:5 - len(priority_candidates)])

            # Quick sequential check for missing packages (faster than batch for 5 items)
            best_match = None
            best_similarity = 0
            similarity_threshold = threat_processor.get_dynamic_similarity_threshold(project_type, package_exists=False)

            for candidate in priority_candidates:
                similarity = fuzz.ratio(dep_name, candidate)
                if similarity >= similarity_threshold:
                    cand_status, cand_metadata = get_package_metadata(candidate, project_type)
                    if cand_status == 200 and cand_metadata:
                        if is_legitimate_package(candidate, cand_metadata, project_type):
                            if similarity > best_similarity:
                                best_similarity = similarity
                                best_match = candidate
                                break  # Found good match, stop checking

            if best_match:
                if not threat_processor.is_false_positive(dep_name, best_match, project_type):
                    findings.append({
                        'type': 'Typosquatting',
                        'details': {
                            'similar_to': best_match,
                            'similarity': best_similarity
                        }
                    })
                # Stop here - typosquatting detected (or excluded), skip remaining checks
                return dep_name, findings

        # No typosquatting found, flag as dependency confusion
        findings.append({
            'type': 'Dependency Confusion',
            'message': (
                f"Package not found on public {project_type} registry. "
                "If this is a private package, it is vulnerable."
            )
        })
        # Stop here - dependency confusion detected, skip remaining checks
        return dep_name, findings

    # PRIORITY 3: Unusual Versioning Check
    if dep_version:
        try:
            v = version.parse(dep_version)
            if v.major > DetectionConfig.ABNORMAL_VERSION_MAJOR:
                findings.append({
                    'type': 'Unusual Versioning',
                    'message': f"Version number ({dep_version}) is abnormally high."
                })
                # Stop here - unusual versioning detected, skip remaining checks
                return dep_name, findings
        except version.InvalidVersion:
            findings.append({
                'type': 'Unusual Versioning',
                'message': f"Version '{dep_version}' is not a valid PEP 440 version."
            })
            # Stop here - invalid version detected, skip remaining checks
            return dep_name, findings

    # PRIORITY 4 & 5: Poor Metadata and Abnormal Update Frequency (lowest priority)
    # Only check these if package exists and no higher priority issues found
    if status_code == 200 and metadata:
        # Skip metadata checks for legitimate Maven groups (API timeouts can cause synthetic responses)
        is_legitimate_fallback = metadata.get('legitimate_group', False)

        # Check Poor Metadata (skip for legitimate fallback packages)
        if not is_legitimate_fallback:
            description = metadata.get('info', {}).get('summary', '') or metadata.get('description', '')
            if not description or len(description) < DetectionConfig.PACKAGE_DESCRIPTION_MIN_LENGTH:
                findings.append({
                    'type': 'Poor Metadata',
                    'message': "Package description is missing or very short."
                })
                # Stop here - poor metadata detected, skip update frequency check
                return dep_name, findings

        # Check Abnormal Update Frequency (only if no other issues found)
        # Also skip for legitimate fallback packages
        if not is_legitimate_fallback:
            latest_release_date = None
            if project_type == 'pypi':
                if 'releases' in metadata and metadata['releases']:
                    all_release_dates = [datetime.fromisoformat(file_info['upload_time'])
                                         for release_files in metadata['releases'].values()
                                         for file_info in release_files if 'upload_time' in file_info]
                    if all_release_dates:
                        latest_release_date = max(all_release_dates)
            elif project_type == 'npm':
                time_data = metadata.get('time', {})
                if 'modified' in time_data:
                    latest_release_date = datetime.fromisoformat(time_data['modified'].replace('Z', ''))
            elif project_type == 'maven':
                if 'timestamp' in metadata:
                    latest_release_date = datetime.fromtimestamp(metadata['timestamp'] / 1000)

            abandonment_threshold_days = DetectionConfig.PACKAGE_ABANDONMENT_YEARS * 365
            if latest_release_date and (datetime.now() - latest_release_date).days > abandonment_threshold_days:
                findings.append({
                    'type': 'Abnormal Update Frequency',
                    'message': f"Package has not been updated since {latest_release_date.year} (abandoned)."
                })

    elif status_code is not None:
        # Handle metadata check failures (only if no other issues found)
        if project_type == 'maven':
            group_id_parts = dep_name.split(':')
            if len(group_id_parts) >= 2:
                group_id = group_id_parts[0]
                if not (('.' in group_id and len(group_id) > 5) or
                        group_id.startswith(('org.', 'com.', 'io.', 'net.'))):
                    findings.append({
                        'type': 'Metadata Check Failed',
                        'message': "Could not fetch package data due to a network or server error."
                    })
            else:
                findings.append({
                    'type': 'Invalid Package Format',
                    'message': "Maven package should be in groupId:artifactId format."
                })
        else:
            findings.append({
                'type': 'Metadata Check Failed',
                'message': "Could not fetch package data due to a network or server error."
            })

    return dep_name, findings


def run_all_checks(dependencies, project_type):
    """
    Runs all suspicious package checks and aggregates the results.
    Uses parallel dependency processing and two-level caching (memory + disk)
    so repeated or large scans hit the registry only for genuinely new packages.
    """
    all_suspicious_findings = {}
    threat_processor = get_threat_processor()

    max_workers = min(10, max(5, len(dependencies) // 4))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_dep = {
            executor.submit(process_single_dependency, dep, project_type, threat_processor): dep
            for dep in dependencies
        }

        for future in as_completed(future_to_dep):
            try:
                dep_name, findings = future.result()
                if findings:
                    all_suspicious_findings[dep_name] = findings
            except Exception as e:
                # Log error but continue processing other dependencies
                dep = future_to_dep[future]
                print(f"Warning: Error processing {dep.get('name', 'unknown')}: {e}", file=sys.stderr)

    # Save learning data after processing all dependencies
    threat_processor.save_all_learning_data()

    return all_suspicious_findings
