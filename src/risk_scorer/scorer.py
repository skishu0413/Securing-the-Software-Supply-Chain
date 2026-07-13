"""
Calculates a risk score for a given set of vulnerabilities using a sophisticated algorithm.
"""

import yaml
import os
import requests
import time
import threading
from datetime import datetime, timezone
from cvss import CVSS3, CVSS2
import cvss.exceptions

# Global cache for KEV data
_kev_cache = {
    'data': None,
    'timestamp': 0,
    'cve_set': set()
}

# Global cache for EPSS data
_epss_cache = {
    'data': {},  # CVE_ID -> EPSS score mapping
    'timestamp': 0
}

# Thread-safety locks for cache access
_kev_lock = threading.Lock()
_epss_lock = threading.Lock()

# Event used to coordinate concurrent KEV fetches: at most one thread fetches at a
# time; all others wait on the event and then read the freshly populated cache.
_kev_fetch_event = threading.Event()
_kev_fetch_event.set()  # Initially "no fetch in progress" (set == ready)

# Load configurable risk weights


def load_risk_config():
    """Load risk configuration from main config YAML file."""
    config_path = os.path.join(os.path.dirname(__file__), '..', 'config.yaml')

    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        return config
    except (FileNotFoundError, yaml.YAMLError) as e:
        print(f"Warning: Could not load risk config from {config_path}: {e}")
        # Return default configuration
        return {
            'risk_weights': {
                'base_severity': 35,
                'exploit_pressure': 25,
                'exposure_context': 15,
                'volume': 10,
                'patch_gap': 10,
                'credibility': 5
            },
            'display': {
                'verbose_risk_breakdown': True,
                'show_exploit_indicators': True,
                'show_methodology': False,
                'compact_format': False
            }
        }


# Global config (loaded once)
RISK_CONFIG = load_risk_config()


def get_kev_database():
    """
    Fetch and cache CISA KEV database.
    Returns set of CVE IDs that are in the KEV catalog.

    Thread-safe: at most one thread performs a network fetch per cache miss.
    All other threads wait on _kev_fetch_event and then read the populated cache.
    """
    risk_scoring_config = RISK_CONFIG.get('risk_scoring', {})
    _default_kev_url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
    kev_url = risk_scoring_config.get('kev_api_url', _default_kev_url)
    cache_hours = risk_scoring_config.get('kev_cache_hours', 24)
    cache_duration = cache_hours * 3600  # Convert to seconds

    while True:
        # Phase 1: check cache validity (or wait for an in-progress fetch to finish).
        with _kev_lock:
            if _kev_cache['data'] and (time.time() - _kev_cache['timestamp']) < cache_duration:
                # Cache is fresh — return immediately.
                return _kev_cache.get('cve_set', set())

            # Cache is stale or empty.
            if _kev_fetch_event.is_set():
                # No fetch is in progress — claim the fetch slot by clearing the event.
                _kev_fetch_event.clear()
                do_fetch = True
            else:
                # Another thread is already fetching — we'll wait for it.
                do_fetch = False

        if not do_fetch:
            # Wait (with timeout) for the active fetcher to finish, then loop back
            # and read the freshly populated cache.
            _kev_fetch_event.wait(timeout=15)
            continue  # Re-enter loop to read cache under lock

        # Phase 2: we are the designated fetcher — perform the HTTP request outside the lock.
        try:
            response = requests.get(kev_url, timeout=10)
            response.raise_for_status()
            kev_data = response.json()
            cve_set = {v.get('cveID', '').upper() for v in kev_data.get('vulnerabilities', []) if v.get('cveID')}

            with _kev_lock:
                _kev_cache.update({'data': kev_data, 'timestamp': time.time(), 'cve_set': cve_set})
            return cve_set

        except requests.exceptions.RequestException as e:
            import sys
            print(f"WARNING: KEV fetch failed: {e}", file=sys.stderr)
            with _kev_lock:
                return _kev_cache.get('cve_set', set())

        finally:
            # Always signal waiting threads that the fetch attempt (success or failure) is done.
            _kev_fetch_event.set()


def query_kev_database(cve_id):
    """
    Query CISA's KEV database for a specific CVE.
    Returns True if CVE is in the Known Exploited Vulnerabilities catalog.
    """
    if not cve_id or not isinstance(cve_id, str):
        return False

    cve_id_upper = cve_id.upper()
    if not cve_id_upper.startswith('CVE-'):
        return False

    kev_cves = get_kev_database()
    return cve_id_upper in kev_cves


def get_epss_scores(cve_ids):
    """
    Fetch EPSS scores for multiple CVEs with caching.
    Returns dict mapping CVE_ID -> EPSS score (0.0-1.0).
    """
    risk_scoring_config = RISK_CONFIG.get('risk_scoring', {})
    epss_url = risk_scoring_config.get('epss_api_url', 'https://api.first.org/data/v1/epss')
    cache_hours = risk_scoring_config.get('epss_cache_hours', 24)
    batch_size = risk_scoring_config.get('epss_batch_size', 30)
    cache_duration = cache_hours * 3600

    current_time = time.time()

    # Check whether the cache has expired; if so, clear it under lock
    with _epss_lock:
        if (current_time - _epss_cache['timestamp']) >= cache_duration:
            _epss_cache['data'] = {}
            _epss_cache['timestamp'] = current_time

        # Identify which CVEs are not yet cached
        cves_to_fetch = [cve for cve in cve_ids if cve.upper() not in _epss_cache['data']]

    # Fetch EPSS data in batches OUTSIDE the lock to avoid blocking during I/O
    for i in range(0, len(cves_to_fetch), batch_size):
        batch = cves_to_fetch[i:i + batch_size]
        try:
            cve_param = ','.join(batch)
            response = requests.get(f"{epss_url}?cve={cve_param}", timeout=10)
            response.raise_for_status()
            epss_data = response.json()

            # Parse and write results under lock
            if 'data' in epss_data:
                with _epss_lock:
                    for entry in epss_data['data']:
                        cve_id = entry.get('cve', '').upper()
                        epss_score = float(entry.get('epss', 0.0))
                        _epss_cache['data'][cve_id] = epss_score

        except requests.exceptions.RequestException as e:
            import sys
            print(f"WARNING: EPSS fetch failed for batch: {e}", file=sys.stderr)

    # Return scores for requested CVEs (read under lock)
    with _epss_lock:
        return {cve: _epss_cache['data'].get(cve.upper(), 0.0) for cve in cve_ids}


def get_vulnerability_age_days(vuln):
    """
    Calculate how many days since vulnerability was published.
    Returns days as float, or None if date unavailable.
    """
    published_str = vuln.get('published')
    if not published_str:
        return None

    try:
        published_date = datetime.fromisoformat(published_str.replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        age_days = (now - published_date).days
        return age_days
    except (ValueError, TypeError):
        return None


def parse_attack_vector(vuln):
    """
    Parse CVSS attack vector and complexity from vulnerability data.
    Returns dict with attack_vector, attack_complexity, and exploitability_score.
    """
    result = {
        'attack_vector': None,
        'attack_complexity': None,
        'user_interaction': None,
        'exploitability_score': 0.5  # Default medium
    }

    try:
        metrics = vuln.get('metrics', {})

        # Try CVSS v3.1, v3.0, then v2
        cvss_data = None
        if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
            cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
        elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
            cvss_data = metrics['cvssMetricV30'][0].get('cvssData', {})
        elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
            cvss_data = metrics['cvssMetricV2'][0].get('cvssData', {})

        if cvss_data:
            av = cvss_data.get('attackVector', cvss_data.get('accessVector'))
            ac = cvss_data.get('attackComplexity', cvss_data.get('accessComplexity'))
            ui = cvss_data.get('userInteraction')

            result['attack_vector'] = av
            result['attack_complexity'] = ac
            result['user_interaction'] = ui

            # Calculate exploitability score (0.0-1.0)
            score = 0.5

            # Attack Vector scoring
            if av in ['NETWORK', 'N']:
                score += 0.3  # Network accessible = most dangerous
            elif av in ['ADJACENT_NETWORK', 'ADJACENT', 'A']:
                score += 0.2  # Adjacent network
            elif av in ['LOCAL', 'L']:
                score += 0.1  # Local access required
            elif av in ['PHYSICAL', 'P']:
                score += 0.0  # Physical access required = least dangerous

            # Attack Complexity scoring (inverse - low complexity = higher score)
            if ac in ['LOW', 'L']:
                score += 0.15  # Easy to exploit
            elif ac in ['MEDIUM', 'M']:
                score += 0.10
            elif ac in ['HIGH', 'H']:
                score += 0.05  # Hard to exploit

            # User Interaction (inverse - none required = higher score)
            if ui in ['NONE', 'N']:
                score += 0.05  # No user interaction needed

            result['exploitability_score'] = min(1.0, score)

    except (TypeError, KeyError):
        pass

    return result


def _score_cvss_vector(vector_string: str) -> float:
    """
    Parse and score a CVSS vector using the official cvss library.
    Returns the base score (0.0–10.0) or 0.0 on parse failure.

    Note: CVSS v4.0 vectors are not supported by the cvss library yet.
    They are silently skipped here; scores come from the numeric baseScore
    field provided by NVD/OSV directly.
    """
    if not vector_string or not isinstance(vector_string, str):
        return 0.0
    # CVSS v4.0 vectors cannot be parsed by the current cvss library —
    # skip silently rather than emitting hundreds of warnings.
    if vector_string.startswith('CVSS:4'):
        return 0.0
    try:
        if vector_string.startswith('CVSS:3'):
            return float(CVSS3(vector_string).base_score)
        elif vector_string.startswith('CVSS:2'):
            return float(CVSS2(vector_string).base_score)
        else:
            # Try v3 first, fall back to v2
            try:
                return float(CVSS3(vector_string).base_score)
            except cvss.exceptions.CVSSError:
                return float(CVSS2(vector_string).base_score)
    except cvss.exceptions.CVSSError as e:
        import sys
        print(f"WARNING: Malformed CVSS vector '{vector_string[:60]}': {e}", file=sys.stderr)
        return 0.0


def calculate_severity_distribution_score(vulnerabilities):
    """
    Analyze severity distribution to assess overall risk profile.
    A package with many high-severity vulns is worse than one with mostly low.
    Returns score 0.0-1.0 based on distribution.
    """
    if not vulnerabilities:
        return 0.0

    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

    for vuln in vulnerabilities:
        cvss = get_cvss_score(vuln)
        if cvss >= 9.0:
            severity_counts['critical'] += 1
        elif cvss >= 7.0:
            severity_counts['high'] += 1
        elif cvss >= 4.0:
            severity_counts['medium'] += 1
        else:
            severity_counts['low'] += 1

    total = len(vulnerabilities)
    if total == 0:
        return 0.0

    # Weighted scoring: critical=1.0, high=0.7, medium=0.4, low=0.1
    weighted_sum = (
        severity_counts['critical'] * 1.0 +
        severity_counts['high'] * 0.7 +
        severity_counts['medium'] * 0.4 +
        severity_counts['low'] * 0.1
    )

    # Normalize by total count
    distribution_score = weighted_sum / total

    return min(1.0, distribution_score)


def get_cvss_score(vuln):
    """
    Extracts a representative CVSS score from a vulnerability entry with improved validation.
    Supports CVSS v4.0, v3.1, v3.0, and v2.0 with priority ordering.
    Now includes support for OSV severity format.
    """
    cvss_candidates = []

    # Try OSV severity format first (array of severity objects)
    try:
        if 'severity' in vuln and isinstance(vuln.get('severity'), list):
            for sev_entry in vuln['severity']:
                if isinstance(sev_entry, dict):
                    sev_type = sev_entry.get('type', '')
                    score_str = sev_entry.get('score', '')

                    # OSV stores CVSS as vector string like "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
                    # We need to calculate the numeric score from the vector
                    if 'CVSS' in sev_type and isinstance(score_str, str) and score_str.startswith('CVSS:'):
                        # Extract numeric score from CVSS vector string
                        # For now, use a simplified approach based on severity components
                        numeric_score = _score_cvss_vector(score_str)
                        if numeric_score > 0:
                            if '3.1' in score_str or 'CVSS_V3' in sev_type:
                                cvss_candidates.append(('v31_osv', numeric_score))
                            elif '3.0' in score_str:
                                cvss_candidates.append(('v30_osv', numeric_score))
                            elif '2.0' in score_str:
                                cvss_candidates.append(('v2_osv', numeric_score))
    except (TypeError, KeyError, IndexError):
        pass

    try:
        if 'metrics' in vuln and isinstance(vuln.get('metrics'), dict):
            metrics = vuln['metrics']

            # CVSS v4.0 (highest priority)
            if 'cvssMetricV40' in metrics and metrics['cvssMetricV40']:
                score = metrics['cvssMetricV40'][0].get('cvssData', {}).get('baseScore')
                if score is not None:
                    cvss_candidates.append(('v40', validate_cvss_score(score)))

            # CVSS v3.1
            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                score = metrics['cvssMetricV31'][0].get('cvssData', {}).get('baseScore')
                if score is not None:
                    cvss_candidates.append(('v31', validate_cvss_score(score)))

            # CVSS v3.0
            if 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                score = metrics['cvssMetricV30'][0].get('cvssData', {}).get('baseScore')
                if score is not None:
                    cvss_candidates.append(('v30', validate_cvss_score(score)))

            # CVSS v2
            if 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                score = metrics['cvssMetricV2'][0].get('cvssData', {}).get('baseScore')
                if score is not None:
                    cvss_candidates.append(('v2', validate_cvss_score(score)))
    except (TypeError, KeyError, IndexError):
        pass

    try:
        if 'cvss_score' in vuln:
            score = validate_cvss_score(vuln['cvss_score'])
            if score > 0:
                cvss_candidates.append(('direct', score))

        if 'baseScore' in vuln:
            score = validate_cvss_score(vuln['baseScore'])
            if score > 0:
                cvss_candidates.append(('base', score))
    except (TypeError, KeyError):
        pass

    if cvss_candidates:
        version_priority = {
            'v40': 0, 'v31': 1, 'v31_osv': 2, 'v30': 3, 'v30_osv': 4,
            'v2': 5, 'v2_osv': 6, 'direct': 7, 'base': 8
        }
        cvss_candidates.sort(key=lambda x: version_priority.get(x[0], 999))
        return cvss_candidates[0][1]

    # Fallback to severity string mapping
    risk_scoring_config = RISK_CONFIG.get('risk_scoring', {})
    severity_scores = risk_scoring_config.get('severity_scores', {
        'CRITICAL': 9.5, 'HIGH': 8.0, 'MODERATE': 5.5, 'LOW': 2.0, 'NONE': 0.0
    })

    try:
        severity_sources = [
            vuln.get('database_specific', {}).get('severity'),
            vuln.get('severity'),
            vuln.get('impact', {}).get('severity') if isinstance(vuln.get('impact'), dict) else None
        ]

        for severity_str in severity_sources:
            if severity_str and isinstance(severity_str, str):
                score = severity_scores.get(severity_str.upper())
                if score is not None and score > 0:
                    return score
    except (TypeError, KeyError):
        pass

    return 0.0


def deduplicate_vulnerabilities(vulnerabilities):
    """
    Remove duplicate vulnerabilities with more conservative deduplication.
    Only removes exact duplicates, preserves different IDs that refer to same issue.
    """
    if not vulnerabilities:
        return []

    seen = set()
    unique_vulns = []

    for vuln in vulnerabilities:
        # Create a unique identifier based on ID only (most conservative)
        vuln_id = vuln.get('id', '')

        # Only deduplicate if exact same ID
        if vuln_id and vuln_id not in seen:
            seen.add(vuln_id)
            unique_vulns.append(vuln)
        elif not vuln_id:  # Keep vulnerabilities without IDs
            unique_vulns.append(vuln)

    return unique_vulns


def validate_cvss_score(score):
    """
    Validate CVSS score is within expected range and reasonable.
    """
    if not isinstance(score, (int, float)):
        return 0.0

    # CVSS scores should be between 0.0 and 10.0
    if score < 0.0 or score > 10.0:
        return 0.0

    return float(score)


def is_vulnerability_recent(vuln, max_age_years=10):
    """
    Check if vulnerability is recent enough to be relevant.
    Very old vulnerabilities (>10 years) might be less relevant.
    """
    published_str = vuln.get('published')
    if not published_str:
        return True  # Assume recent if no date available

    try:
        published_date = datetime.fromisoformat(published_str.replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        age_years = (now - published_date).days / 365.25
        return age_years <= max_age_years
    except (ValueError, TypeError):
        return True  # Assume recent if date parsing fails


def get_severity_label(score):
    if score >= 85:
        return "CRITICAL"
    if score >= 65:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def detect_language_from_package(package_name, ecosystem=None):
    """
    Determine the programming language/ecosystem from package information.
    Supports PyPI (Python), npm (JavaScript), and Maven (Java) ecosystems.
    """
    if ecosystem:
        ecosystem_lower = ecosystem.lower()
        if "pypi" in ecosystem_lower or "pip" in ecosystem_lower or "python" in ecosystem_lower:
            return "python"
        elif "maven" in ecosystem_lower or "java" in ecosystem_lower:
            return "java"
        elif "npm" in ecosystem_lower or "node" in ecosystem_lower or "javascript" in ecosystem_lower:
            return "javascript"

    # Fallback to package name patterns for the three supported ecosystems
    if package_name:
        name_lower = package_name.lower()
        if any(indicator in name_lower for indicator in ["java", "spring", "apache", "javax", "org.", "com."]):
            return "java"
        elif any(indicator in name_lower for indicator in ["js", "node", "react", "vue", "angular", "@"]):
            return "javascript"
        # Python packages often have underscores or simple names, so it's harder to detect
        # Will default to "default" which gets 1.0 modifier

    return "default"


def check_kev_status(vuln: dict, epss_score=None) -> tuple:
    """
    Check if vulnerability is a Known Exploited Vulnerability per CISA KEV database.
    Also integrates EPSS (Exploit Prediction Scoring System) data.

    Uses real KEV API checking, EPSS scores, and text-based indicators.
    Each source bucket (cisa_kev, epss, text_critical, text_high, text_medium,
    text_low, exploit_db) contributes at most once to prevent double-counting.

    Returns: (exploit_score, indicators_found) tuple where exploit_score is in [0.0, 1.0]
    """
    kev_score = 0.0
    indicators_found = []
    sources_counted: set = set()  # track which source buckets have contributed

    # Get exploit pressure config and risk scoring config
    exploit_config = RISK_CONFIG.get('exploit_pressure', {})
    risk_scoring_config = RISK_CONFIG.get('risk_scoring', {})
    kev_indicators_config = risk_scoring_config.get('kev_indicators', {})

    # 1. PRIMARY: Check CVE ID against real CISA KEV database
    _raw_id = vuln.get('id', '') or ''
    cve_id = _raw_id.upper() if isinstance(_raw_id, str) else ''
    if cve_id.startswith('CVE-') and 'cisa_kev' not in sources_counted:
        if query_kev_database(cve_id):
            kev_score += exploit_config.get('cisa_kev_listed', 1.0)
            indicators_found.append(f"CISA KEV: {cve_id}")
            sources_counted.add('cisa_kev')

    # 2. EPSS Score Integration (if provided)
    if epss_score is not None and 'epss' not in sources_counted:
        epss_high = risk_scoring_config.get('epss_high_threshold', 0.7)
        epss_medium = risk_scoring_config.get('epss_medium_threshold', 0.3)

        # EPSS is probability (0-1), convert to risk score
        if epss_score >= epss_high:
            kev_score += exploit_config.get('high_confidence_exploited', 0.8)
            indicators_found.append(f"EPSS high: {epss_score:.2%}")
            sources_counted.add('epss')
        elif epss_score >= epss_medium:
            kev_score += exploit_config.get('medium_confidence_exploited', 0.6)
            indicators_found.append(f"EPSS medium: {epss_score:.2%}")
            sources_counted.add('epss')
        elif epss_score > 0:
            kev_score += epss_score * exploit_config.get('exploit_code_available', 0.4)
            indicators_found.append(f"EPSS: {epss_score:.2%}")
            sources_counted.add('epss')

    # 3. TERTIARY: Text-based KEV indicators
    # Collect all available text for analysis
    text_fields = []
    text_fields.append(str(vuln.get('summary', '')))
    text_fields.append(str(vuln.get('details', '')))

    # Also check database_specific for additional info
    db_specific = vuln.get('database_specific', {})
    if isinstance(db_specific, dict):
        for key, value in db_specific.items():
            if isinstance(value, str):
                text_fields.append(value)

    description = ' '.join(text_fields).lower()

    # Load indicators from config
    critical_indicators = kev_indicators_config.get('critical', [])
    high_confidence_indicators = kev_indicators_config.get('high_confidence', [])
    medium_confidence_indicators = kev_indicators_config.get('medium_confidence', [])
    low_confidence_indicators = kev_indicators_config.get('low_confidence', [])

    # For each text category, contribute at most one score entry via sources_counted
    for category, indicators, score_key, label_prefix in [
        ('text_critical', critical_indicators, 'high_confidence_exploited', 'Critical vulnerability'),
        ('text_high', high_confidence_indicators, 'high_confidence_exploited', 'High confidence'),
        ('text_medium', medium_confidence_indicators, 'medium_confidence_exploited', 'Medium confidence'),
        ('text_low', low_confidence_indicators, 'exploit_code_available', 'Exploit code'),
    ]:
        if category not in sources_counted:
            for indicator in indicators:
                if indicator in description:
                    kev_score += exploit_config.get(score_key, 0.0)
                    indicators_found.append(f"{label_prefix}: '{indicator}'")
                    sources_counted.add(category)
                    break  # at most one indicator per category

    # 4. Check references for exploit databases
    if 'exploit_db' not in sources_counted:
        references = vuln.get('references', [])
        if isinstance(references, (set, list)):
            refs_text = ' '.join(str(ref) for ref in references).lower()
            if any(db in refs_text for db in ["exploit-db", "metasploit", "exploitdb"]):
                kev_score += exploit_config.get('exploit_db_reference', 0.3)
                indicators_found.append("Exploit database reference")
                sources_counted.add('exploit_db')

    return min(1.0, kev_score), indicators_found


def check_patch_availability(vuln):
    """
    Assess patch availability with enhanced detection and confidence scoring.
    Returns a score from 0 (no patch info) to 1 (clear patch available).
    """
    summary = str(vuln.get('summary', ''))
    details = str(vuln.get('details', ''))
    references = vuln.get('references', [])

    # Handle references which might be a set, list, or other type
    if isinstance(references, (set, list)):
        references_str = ' '.join(str(ref) for ref in references)
    else:
        references_str = str(references)

    description = (summary + ' ' + details + ' ' + references_str).lower()

    patch_score = 0
    confidence_multiplier = 1.0

    # Load patch indicators from config
    risk_scoring_config = RISK_CONFIG.get('risk_scoring', {})
    patch_indicators_config = risk_scoring_config.get('patch_indicators', {})

    high_confidence_indicators = patch_indicators_config.get('high_confidence', [])
    medium_confidence_indicators = patch_indicators_config.get('medium_confidence', [])
    low_confidence_indicators = patch_indicators_config.get('low_confidence', [])

    for indicator in high_confidence_indicators:
        if indicator in description:
            patch_score += 2  # Higher weight for strong indicators
            confidence_multiplier = max(confidence_multiplier, 1.0)

    for indicator in medium_confidence_indicators:
        if indicator in description:
            patch_score += 1.5
            confidence_multiplier = max(confidence_multiplier, 0.8)

    for indicator in low_confidence_indicators:
        if indicator in description:
            patch_score += 0.5
            confidence_multiplier = max(confidence_multiplier, 0.6)

    # Strong evidence: structured version information
    version_info_score = 0

    # Check for direct fixed_version field
    if vuln.get('fixed_version'):
        version_info_score += 3  # Strong indicator
        confidence_multiplier = max(confidence_multiplier, 1.0)

    # Check affected array for ranges with fix information
    affected_list = vuln.get('affected', [])
    if isinstance(affected_list, list):
        for affected_item in affected_list:
            if isinstance(affected_item, dict):
                ranges = affected_item.get('ranges', [])
                if isinstance(ranges, list):
                    for range_info in ranges:
                        if isinstance(range_info, dict) and 'events' in range_info:
                            events = range_info.get('events', [])
                            for event in events:
                                if isinstance(event, dict) and ('fixed' in event or 'last_affected' in event):
                                    version_info_score += 3  # Strong indicator of patch availability
                                    confidence_multiplier = max(confidence_multiplier, 1.0)
                                    break

    # Legacy: Check for ranges at top level (some vulnerability formats)
    if 'ranges' in vuln and isinstance(vuln['ranges'], list):
        for range_info in vuln['ranges']:
            if isinstance(range_info, dict) and 'events' in range_info:
                for event in range_info['events']:
                    if isinstance(event, dict) and ('fixed' in event or 'last_affected' in event):
                        version_info_score += 2
                        confidence_multiplier = max(confidence_multiplier, 0.9)
                        break

    # Combine scores with confidence adjustment
    total_score = (patch_score + version_info_score) * confidence_multiplier

    # Normalize to 0-1 scale (higher score means patch is available, which reduces risk)
    return min(1.0, total_score / 6)  # Adjusted denominator for new scoring


def assess_credibility(vuln):
    """
    Assess the credibility of the vulnerability report.
    Factors: source reputation, detail level, references quality.
    """
    credibility_score = 0.5  # Base credibility

    # Load trusted sources from config
    risk_scoring_config = RISK_CONFIG.get('risk_scoring', {})
    trusted_sources = risk_scoring_config.get('trusted_sources', ['nvd', 'mitre', 'cve', 'github', 'snyk'])

    # Check source reputation - handle different data types
    source_data = vuln.get('source', '')
    if isinstance(source_data, set):
        # Convert set to string for searching
        source = ' '.join(str(s) for s in source_data).lower()
    elif isinstance(source_data, list):
        # Convert list to string for searching
        source = ' '.join(str(s) for s in source_data).lower()
    else:
        # Assume it's a string or can be converted to string
        source = str(source_data).lower()

    if any(trusted in source for trusted in trusted_sources):
        credibility_score += 0.3

    # Check detail level
    summary = vuln.get('summary', '')
    details = vuln.get('details', '')
    description_length = len(str(summary) + str(details))
    if description_length > 200:
        credibility_score += 0.2

    # Check references
    references = vuln.get('references', [])
    if isinstance(references, (list, set)) and len(references) >= 2:
        credibility_score += 0.1

    return min(1.0, credibility_score)


def calculate_exposure_context(package_name, ecosystem):
    """
    Calculate exposure/context score using pattern analysis from config.
    Analyzes package name characteristics to determine likely exposure level.
    IMPROVED: More balanced scoring to properly differentiate packages.
    """
    # Get base exposure from config (reduced to allow LOW scores)
    exposure_config = RISK_CONFIG.get('exposure_context', {})
    base_exposure = exposure_config.get('base_exposure', 0.1)  # Reduced from 0.2 to 0.1

    if not package_name:
        return base_exposure

    name_lower = package_name.lower()

    # Load exposure terms from config
    risk_scoring_config = RISK_CONFIG.get('risk_scoring', {})
    exposure_terms = risk_scoring_config.get('exposure_terms', {})

    # Category risk weights from config
    category_weights = {
        'network_communication': exposure_config.get('network_communication', 0.8),
        'web_frameworks': exposure_config.get('web_frameworks', 0.7),
        'data_processing': exposure_config.get('data_processing', 0.6),
        'security_crypto': exposure_config.get('security_crypto', 0.6),
        'database_access': exposure_config.get('database_access', 0.4)
    }

    # Check each category and accumulate exposure (packages can match multiple)
    exposure_scores = []

    for category, weight in category_weights.items():
        terms = exposure_terms.get(category, [])
        if any(term in name_lower for term in terms):
            exposure_scores.append(weight)

    # Use highest exposure category, or combine if multiple matches
    if exposure_scores:
        max_exposure = max(exposure_scores)
        # If multiple categories match, slightly boost exposure
        if len(exposure_scores) > 1:
            max_exposure = min(1.0, max_exposure + 0.1)
        return max_exposure

    # For popular well-known packages without specific category match, use higher baseline
    # This ensures critical packages like 'requests', 'django', etc. get proper scoring
    well_known_indicators = ['http', 'web', 'api', 'request', 'server', 'client',
                             'flask', 'django', 'express', 'react', 'vue', 'angular',
                             'sql', 'db', 'auth', 'crypto', 'ssl', 'json', 'xml']

    if any(ind in name_lower for ind in well_known_indicators):
        return 0.5  # Medium exposure for general infrastructure packages

    return base_exposure


def calculate_volume_score(vuln_count, language):
    """
    Calculate volume score with more aggressive scaling for vulnerability counts.
    Clear differentiation between different vulnerability counts is crucial.
    """
    if vuln_count == 0:
        return 0.0

    import math

    # Adjusted volume scoring to allow LOW scores for single vulnerabilities
    if vuln_count == 1:
        base_volume = 0.2  # Single vuln baseline (reduced from 0.4 to allow LOW scores)
    elif vuln_count == 2:
        base_volume = 0.35  # Clear step up
    elif vuln_count == 3:
        base_volume = 0.55   # Moderate increase
    elif vuln_count <= 5:
        base_volume = 0.55 + (vuln_count - 3) * 0.10  # 5 vulns = 0.75
    elif vuln_count <= 10:
        base_volume = 0.75 + (vuln_count - 5) * 0.03  # 10 vulns = 0.90
    else:
        # Cap near 1.0 for very high counts
        base_volume = 0.90 + (math.log(vuln_count - 9) * 0.02)

    # Less aggressive ecosystem normalization to preserve differences
    ecosystem_modifiers = {
        'python': 1.0,     # Baseline
        'java': 0.95,      # Very slight normalization
        'javascript': 0.98,  # Minimal normalization
        'default': 1.0
    }

    modifier = ecosystem_modifiers.get(language, ecosystem_modifiers['default'])
    normalized_score = base_volume * modifier

    return min(1.0, normalized_score)


def calculate_patch_gap(vulnerabilities):
    """
    Calculate patch gap score - fraction of vulnerabilities with known fix not applied.
    """
    if not vulnerabilities:
        return 0.0

    vulns_with_patches = 0
    total_vulns = len(vulnerabilities)

    for vuln in vulnerabilities:
        patch_available = check_patch_availability(vuln)
        if patch_available >= 0.5:  # Threshold for "patch available"
            vulns_with_patches += 1

    # Return fraction of vulnerabilities that have patches available (higher = more risk)
    patch_gap_ratio = vulns_with_patches / total_vulns if total_vulns > 0 else 0
    return patch_gap_ratio


def calculate_temporal_decay(vulnerabilities, max_exploit_pressure):
    """
    Apply temporal decay for old vulnerabilities not in KEV/high EPSS.
    """
    if not vulnerabilities:
        return 1.0

    now = datetime.now(timezone.utc)
    oldest_vuln_years = 0

    for vuln in vulnerabilities:
        published_str = vuln.get('published')
        if published_str:
            try:
                published_date = datetime.fromisoformat(published_str.replace('Z', '+00:00'))
                age_years = (now - published_date).days / 365.25
                if age_years > oldest_vuln_years:
                    oldest_vuln_years = age_years
            except (ValueError, TypeError):
                continue

    # Apply decay if oldest vuln > 5 years AND not high exploit pressure
    if oldest_vuln_years > 5 and max_exploit_pressure < 0.7:
        if oldest_vuln_years > 10:
            return 0.8  # -20% for very old
        else:
            return 0.9  # -10% for moderately old

    return 1.0  # No decay


def calculate_risk_score(vulnerabilities, package_info=None):
    """
    Calculates risk score using the configurable 6-component methodology:

    Components (configurable weights, default 0-100 total):
    1. Base severity – severity distribution + age boost, normalized
    2. Exploit pressure – CISA KEV + EPSS + attack vector (max wins)
    3. Exposure/context – service exposure and context factors
    4. Volume – log-scaled vuln count, normalized by ecosystem
    5. Patch gap – fraction of vulns with known fix not applied
    6. Credibility – reference density and source quality

    Plus temporal decay for old vulnerabilities not in KEV.

    Improvements:
    - EPSS integration for exploit prediction
    - Vulnerability age boost (recent vulns = higher risk)
    - Severity distribution analysis (not just max CVSS)
    - Attack vector exploitability from CVSS
    - Critical vulnerability amplification for high CVSS scores
    """
    if not vulnerabilities:
        return 0, "NONE"

    # Step 1: Preprocess vulnerabilities
    unique_vulns = deduplicate_vulnerabilities(vulnerabilities)

    if not unique_vulns:
        return 0, "NONE"

    # Extract package information
    package_name = package_info.get('name', '') if package_info else ''
    ecosystem = package_info.get('ecosystem', '') if package_info else ''
    language = detect_language_from_package(package_name, ecosystem)

    vulnerabilities = unique_vulns  # Use deduplicated vulnerabilities

    # Get configurable weights
    weights = RISK_CONFIG.get('risk_weights', {})
    base_severity_weight = weights.get('base_severity', 35)
    exploit_pressure_weight = weights.get('exploit_pressure', 25)
    exposure_context_weight = weights.get('exposure_context', 15)
    volume_weight = weights.get('volume', 10)
    patch_gap_weight = weights.get('patch_gap', 10)
    credibility_weight = weights.get('credibility', 5)

    # --- IMPROVEMENT 1: Fetch EPSS scores in batch for all CVEs ---
    cve_ids = [vuln.get('id', '') for vuln in vulnerabilities if vuln.get('id', '').startswith('CVE-')]
    epss_scores_map = {}
    if cve_ids:
        epss_scores_map = get_epss_scores(cve_ids)

    # --- 1. Base Severity Component (IMPROVED) ---
    cvss_scores = [get_cvss_score(vuln) for vuln in vulnerabilities]
    max_cvss = max(cvss_scores) if cvss_scores else 0

    # If no CVSS scores available, use a baseline score for known vulnerability presence
    if max_cvss == 0 and len(vulnerabilities) > 0:
        max_cvss = 5.0  # Baseline medium severity when CVSS is missing

    # IMPROVEMENT 2: Severity distribution analysis (not just max)
    severity_distribution_score = calculate_severity_distribution_score(vulnerabilities)

    # Combine max CVSS (70%) with severity distribution (30%) - increased max weight
    combined_severity = (max_cvss / 10.0) * 0.7 + severity_distribution_score * 0.3

    # NEW IMPROVEMENT: Critical vulnerability amplification
    # CVSS 9.0+ gets significant boost to ensure it can reach CRITICAL
    cvss_amplifier = 1.0
    if max_cvss >= 9.5:
        cvss_amplifier = 1.35  # 35% boost for CVSS 9.5-10.0
    elif max_cvss >= 9.0:
        cvss_amplifier = 1.25  # 25% boost for CVSS 9.0-9.4
    elif max_cvss >= 8.0:
        cvss_amplifier = 1.15  # 15% boost for CVSS 8.0-8.9

    combined_severity = min(1.0, combined_severity * cvss_amplifier)

    # IMPROVEMENT 3: Vulnerability age boost (recent vulns = higher risk)
    age_boost = 0.0
    risk_scoring_config = RISK_CONFIG.get('risk_scoring', {})
    very_recent_days = risk_scoring_config.get('very_recent_vuln_days', 30)
    recent_days = risk_scoring_config.get('recent_vuln_days', 90)
    very_recent_boost = risk_scoring_config.get('very_recent_boost', 0.2)
    recent_boost = risk_scoring_config.get('recent_boost', 0.1)

    for vuln in vulnerabilities:
        age_days = get_vulnerability_age_days(vuln)
        if age_days is not None:
            if age_days <= very_recent_days:
                age_boost = max(age_boost, very_recent_boost)
            elif age_days <= recent_days:
                age_boost = max(age_boost, recent_boost)

    # Apply age boost to severity
    base_severity_score = combined_severity * base_severity_weight * (1 + age_boost)
    base_severity_score = min(base_severity_weight, base_severity_score)

    # --- 2. Exploit Pressure Component (IMPROVED with EPSS + Attack Vector) ---
    exploit_pressure_scores = []
    exploit_indicators = []
    for vuln in vulnerabilities:
        # Get EPSS score for this CVE
        cve_id = vuln.get('id', '')
        epss_score = epss_scores_map.get(cve_id)

        # Check KEV status with EPSS integration
        kev_score, indicators = check_kev_status(vuln, epss_score)

        # IMPROVEMENT 4: Attack vector exploitability analysis
        attack_vector_result = parse_attack_vector(vuln)
        exploitability_score = attack_vector_result.get('exploitability_score', 0.5)

        # Combine KEV/EPSS (primary) with attack vector (secondary)
        # KEV/EPSS = 80%, attack vector = 20%
        exploit_score = kev_score * 0.8 + exploitability_score * 0.2

        exploit_pressure_scores.append(exploit_score)
        if indicators:
            exploit_indicators.extend([(vuln.get('id', 'Unknown'), ind) for ind in indicators])

    max_exploit_pressure = max(exploit_pressure_scores) if exploit_pressure_scores else 0
    exploit_pressure_component = max_exploit_pressure * exploit_pressure_weight

    # --- 3. Exposure/Context Component ---
    exposure_score = calculate_exposure_context(package_name, ecosystem)
    exposure_component = exposure_score * exposure_context_weight

    # --- 4. Volume Component ---
    volume_score = calculate_volume_score(len(vulnerabilities), language)
    volume_component = volume_score * volume_weight

    # --- 5. Patch Gap Component ---
    patch_gap_score = calculate_patch_gap(vulnerabilities)
    patch_gap_component = patch_gap_score * patch_gap_weight

    # --- 6. Credibility Component ---
    credibility_scores = [assess_credibility(vuln) for vuln in vulnerabilities]
    avg_credibility = sum(credibility_scores) / len(credibility_scores) if credibility_scores else 0
    credibility_component = avg_credibility * credibility_weight

    # --- Calculate Base Score ---
    base_total = (base_severity_score + exploit_pressure_component + exposure_component +
                  volume_component + patch_gap_component + credibility_component)

    # NEW: Critical Risk Amplifier - When multiple severe factors align, amplify risk
    # This ensures genuinely critical situations (high CVSS + exploited + popular package) reach CRITICAL
    critical_factors = []

    # Factor 1: High CVSS score
    if max_cvss >= 9.0:
        critical_factors.append(('High CVSS', 1.0))
    elif max_cvss >= 8.0:
        critical_factors.append(('High CVSS', 0.7))

    # Factor 2: Active exploitation
    if max_exploit_pressure >= 0.8:
        critical_factors.append(('Active Exploitation', 1.0))
    elif max_exploit_pressure >= 0.5:
        critical_factors.append(('Likely Exploitation', 0.7))

    # Factor 3: High exposure package
    if exposure_score >= 0.7:
        critical_factors.append(('High Exposure', 0.8))
    elif exposure_score >= 0.5:
        critical_factors.append(('Medium Exposure', 0.5))

    # Factor 4: Multiple vulnerabilities
    if len(vulnerabilities) >= 5:
        critical_factors.append(('Multiple Vulns', 0.6))
    elif len(vulnerabilities) >= 3:
        critical_factors.append(('Multiple Vulns', 0.4))

    # Apply critical amplifier if multiple factors present
    if len(critical_factors) >= 2:
        # Calculate amplifier strength based on factor scores
        factor_scores = [score for _, score in critical_factors]
        avg_factor_score = sum(factor_scores) / len(factor_scores)

        # Amplifier ranges from 1.05 (2 weak factors) to 1.30 (4+ strong factors)
        # Increased from 1.25 to ensure KEV+CVSS10.0 reaches CRITICAL
        amplifier = 1.0 + (len(critical_factors) * 0.06) + (avg_factor_score * 0.12)
        amplifier = min(1.30, amplifier)

        base_total = base_total * amplifier

    # --- Apply Temporal Decay ---
    temporal_decay_factor = calculate_temporal_decay(vulnerabilities, max_exploit_pressure)

    # Final score with temporal decay
    final_score = base_total * temporal_decay_factor
    final_score = max(0, min(100, int(final_score)))

    severity_label = get_severity_label(final_score)

    return final_score, severity_label


def get_risk_config():
    """Get the current risk configuration."""
    return RISK_CONFIG


def _deep_merge(base: dict, override: dict) -> None:
    """Recursively merge override into base in-place."""
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value


def apply_config(cfg: dict) -> None:
    """Deep-merge cfg over a copy of the default RISK_CONFIG for the current process."""
    global RISK_CONFIG
    import copy
    merged = copy.deepcopy(RISK_CONFIG)
    _deep_merge(merged, cfg)
    RISK_CONFIG = merged


def print_risk_methodology():
    """
    Print explanation of risk scoring methodology.
    """
    methodology = """
🔬 Risk Scoring Methodology

This scanner uses a 6-component risk scoring system (0-100 scale):

📊 Component Breakdown:
┌─────────────────────────┬─────────┬─────────────────────────────────────────┐
│ Component               │ Weight  │ Description                             │
├─────────────────────────┼─────────┼─────────────────────────────────────────┤
│ Base Severity           │   35%   │ Maximum CVSS score across all CVEs     │
│ Exploit Pressure        │   25%   │ CISA KEV status, exploit availability   │
│ Exposure/Context        │   15%   │ Package type & exposure analysis        │
│ Volume                  │   10%   │ Number of vulnerabilities (normalized)  │
│ Patch Gap               │   10%   │ Availability of fixes/patches           │
│ Credibility             │    5%   │ Source reputation & detail quality      │
└─────────────────────────┴─────────┴─────────────────────────────────────────┘

🔍 Exploit Pressure Indicators:
┌─────────────────────────┬─────────┬─────────────────────────────────────────┐
│ Indicator               │ Score   │ Description                             │
├─────────────────────────┼─────────┼─────────────────────────────────────────┤
│ CISA KEV Listed         │  1.0    │ CVE in Known Exploited Vulnerabilities │
│ High Confidence Exploit │  0.8    │ "in the wild", "active exploitation"   │
│ Medium Confidence       │  0.6    │ "exploited", "actively exploited"      │
│ Exploit Code Available  │  0.4    │ PoC, Metasploit modules available      │
│ Exploit DB Reference    │  0.3    │ References to exploit databases         │
└─────────────────────────┴─────────┴─────────────────────────────────────────┘

📈 Final Score Interpretation:
• 85-100: CRITICAL - Immediate action required
• 65-84:  HIGH - High priority remediation
• 35-64:  MEDIUM - Moderate risk, plan remediation
• 1-34:   LOW - Monitor for updates
• 0:      NONE - No known vulnerabilities
"""
    return methodology


def format_risk_breakdown(breakdown, compact=False):
    """
    Format risk breakdown for display.

    Args:
        breakdown: Result from calculate_detailed_risk_breakdown()
        compact: If True, use single-line format

    Returns:
        Formatted string representation
    """
    if compact:
        components = breakdown['components']
        return (f"[Severity:{components['base_severity']:.0f} | "
                f"Exploit:{components['exploit_pressure']:.0f} | "
                f"Exposure:{components['exposure_context']:.0f} | "
                f"Volume:{components['volume']:.0f} | "
                f"Patch Gap:{components['patch_gap']:.0f} | "
                f"Credibility:{components['credibility']:.0f}]")

    # Verbose format
    lines = []
    lines.append("📊 Risk Breakdown:")

    components = breakdown['components']
    weights = breakdown['weights']

    lines.append(f"   - Base Severity (CVSS): {components['base_severity']:.1f}/{weights['base_severity']}")

    exploit_line = f"   - Exploit Pressure: {components['exploit_pressure']:.1f}/{weights['exploit_pressure']}"
    if breakdown['exploit_indicators']:
        indicators_text = ", ".join(
            [f"{vuln_id}: {indicator}" for vuln_id, indicator in breakdown['exploit_indicators'][:3]]
        )
        if len(breakdown['exploit_indicators']) > 3:
            indicators_text += f" (+{len(breakdown['exploit_indicators'])-3} more)"
        exploit_line += f" ({indicators_text})"
    lines.append(exploit_line)

    lines.append(f"   - Exposure/Context: {components['exposure_context']:.1f}/{weights['exposure_context']}")
    lines.append(f"   - Volume: {components['volume']:.1f}/{weights['volume']}")
    lines.append(f"   - Patch Gap: {components['patch_gap']:.1f}/{weights['patch_gap']}")
    lines.append(f"   - Credibility: {components['credibility']:.1f}/{weights['credibility']}")

    if breakdown['temporal_decay_factor'] < 1.0:
        lines.append(f"   - Temporal Decay: ×{breakdown['temporal_decay_factor']:.2f}")

    lines.append("   -------------------------")
    lines.append(f"   Total Risk Score: {breakdown['total_score']}/100")

    return "\n".join(lines)


def calculate_detailed_risk_breakdown(vulnerabilities, package_info=None):
    """
    Returns a detailed breakdown of the new 6-component risk score for transparency.
    """
    if not vulnerabilities:
        return {
            'total_score': 0,
            'severity_label': 'NONE',
            'components': {
                'base_severity': 0,
                'exploit_pressure': 0,
                'exposure_context': 0,
                'volume': 0,
                'patch_gap': 0,
                'credibility': 0
            },
            'temporal_decay_factor': 1.0,
            'details': {}
        }

    # Extract package information
    package_name = package_info.get('name', '') if package_info else ''
    ecosystem = package_info.get('ecosystem', '') if package_info else ''
    language = detect_language_from_package(package_name, ecosystem)

    # Deduplicate vulnerabilities
    unique_vulns = deduplicate_vulnerabilities(vulnerabilities)

    # Get configurable weights
    weights = RISK_CONFIG.get('risk_weights', {})
    base_severity_weight = weights.get('base_severity', 35)
    exploit_pressure_weight = weights.get('exploit_pressure', 25)
    exposure_context_weight = weights.get('exposure_context', 15)
    volume_weight = weights.get('volume', 10)
    patch_gap_weight = weights.get('patch_gap', 10)
    credibility_weight = weights.get('credibility', 5)

    # Calculate each component
    cvss_scores = [get_cvss_score(vuln) for vuln in unique_vulns]
    max_cvss = max(cvss_scores) if cvss_scores else 0
    base_severity_score = (max_cvss / 10.0) * base_severity_weight

    # Exploit pressure
    exploit_pressure_scores = []
    exploit_indicators = []
    for vuln in unique_vulns:
        score, indicators = check_kev_status(vuln)
        exploit_pressure_scores.append(score)
        if indicators:
            exploit_indicators.extend([(vuln.get('id', 'Unknown'), ind) for ind in indicators])
    max_exploit_pressure = max(exploit_pressure_scores) if exploit_pressure_scores else 0
    exploit_pressure_component = max_exploit_pressure * exploit_pressure_weight

    # Exposure/context
    exposure_score = calculate_exposure_context(package_name, ecosystem)
    exposure_component = exposure_score * exposure_context_weight

    # Volume
    volume_score = calculate_volume_score(len(unique_vulns), language)
    volume_component = volume_score * volume_weight

    # Patch gap
    patch_gap_score = calculate_patch_gap(unique_vulns)
    patch_gap_component = patch_gap_score * patch_gap_weight

    # Credibility
    credibility_scores = [assess_credibility(vuln) for vuln in unique_vulns]
    avg_credibility = sum(credibility_scores) / len(credibility_scores) if credibility_scores else 0
    credibility_component = avg_credibility * credibility_weight

    # Temporal decay
    temporal_decay_factor = calculate_temporal_decay(unique_vulns, max_exploit_pressure)

    # Calculate total
    base_total = (base_severity_score + exploit_pressure_component + exposure_component +
                  volume_component + patch_gap_component + credibility_component)
    total_score = int(base_total * temporal_decay_factor)

    return {
        'total_score': total_score,
        'severity_label': get_severity_label(total_score),
        'components': {
            'base_severity': round(base_severity_score, 2),
            'exploit_pressure': round(exploit_pressure_component, 2),
            'exposure_context': round(exposure_component, 2),
            'volume': round(volume_component, 2),
            'patch_gap': round(patch_gap_component, 2),
            'credibility': round(credibility_component, 2)
        },
        'weights': {
            'base_severity': base_severity_weight,
            'exploit_pressure': exploit_pressure_weight,
            'exposure_context': exposure_context_weight,
            'volume': volume_weight,
            'patch_gap': patch_gap_weight,
            'credibility': credibility_weight
        },
        'temporal_decay_factor': round(temporal_decay_factor, 2),
        'exploit_indicators': exploit_indicators,
        'details': {
            'max_cvss': max_cvss,
            'language': language,
            'vulnerability_count': len(unique_vulns),
            'max_exploit_pressure': round(max_exploit_pressure, 2),
            'exposure_score': round(exposure_score, 2),
            'volume_score': round(volume_score, 2),
            'patch_gap_score': round(patch_gap_score, 2),
            'avg_credibility': round(avg_credibility, 2)
        }
    }
