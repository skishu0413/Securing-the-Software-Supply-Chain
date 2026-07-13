"""
Main entry point for the scanner.
"""
import argparse
import json
import csv
import os
import sys
import time
import threading
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
import requests
import yaml
import packaging.version
from collections import defaultdict

from config import get_config
from dependency_parser import npm_parser, pypi_parser, maven_parser
from vulnerability_checker import osv_checker, nvd_checker
from risk_scorer import scorer
from suspicious_package_detector import detector


class Colors:
    RED = '\033[91m'
    ORANGE = '\033[38;5;208m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def colorize_severity(severity):
    """Add color to severity labels."""
    if severity == 'CRITICAL':
        return f"{Colors.RED}{Colors.BOLD}{severity}{Colors.RESET}"
    elif severity == 'HIGH':
        return f"{Colors.ORANGE}{Colors.BOLD}{severity}{Colors.RESET}"
    elif severity == 'MEDIUM':
        return f"{Colors.YELLOW}{Colors.BOLD}{severity}{Colors.RESET}"
    elif severity == 'LOW':
        return f"{Colors.GREEN}{Colors.BOLD}{severity}{Colors.RESET}"
    else:
        return severity


def colorize_risk_score(score):
    """Add color to risk scores based on their value."""
    if score >= 85:
        return f"{Colors.RED}{Colors.BOLD}{score}/100{Colors.RESET}"
    elif score >= 65:
        return f"{Colors.ORANGE}{Colors.BOLD}{score}/100{Colors.RESET}"
    elif score >= 35:
        return f"{Colors.YELLOW}{Colors.BOLD}{score}/100{Colors.RESET}"
    elif score > 0:  # Low range
        return f"{Colors.GREEN}{Colors.BOLD}{score}/100{Colors.RESET}"
    else:  # No risk
        return f"{score}/100"


def show_loading_spinner(message, stop_event):
    """Show a loading spinner with rotating animation."""
    spinner_chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
    i = 0
    while not stop_event.is_set():
        sys.stdout.write(f'\r{spinner_chars[i % len(spinner_chars)]} {message}')
        sys.stdout.flush()
        time.sleep(0.1)
        i += 1
    # Clear the line completely when done
    sys.stdout.write('\r' + ' ' * (len(message) + 3) + '\r')
    sys.stdout.flush()


def main():
    """
    Main function to run the scanner.
    """

    parser = argparse.ArgumentParser(description="Dependency Security Scanner")
    parser.add_argument("file", nargs='?',
                        help="Path to the dependency file (e.g., package-lock.json, requirements.txt, pom.xml)")
    parser.add_argument("--type", choices=['pypi', 'npm', 'maven'], help="Type of project")
    parser.add_argument('--format', default='terminal', choices=['terminal', 'json', 'csv'], help='Output format.')
    parser.add_argument('--output', help='Output file path. If not provided, prints to stdout.')
    parser.add_argument('--verbose-risk', action='store_true', help='Show detailed risk score breakdown')
    parser.add_argument('--compact-risk', action='store_true', help='Show compact risk score breakdown')
    parser.add_argument('--risk-config',
                        help='Path to custom configuration YAML file (uses src/config.yaml by default)')
    parser.add_argument('--show-methodology', action='store_true', help='Display risk scoring methodology and exit')

    args = parser.parse_args()

    # Handle methodology display
    if args.show_methodology:
        print(scorer.print_risk_methodology())
        return

    # Now validate required arguments for normal operation
    if not args.file:
        parser.error("file is required unless using --show-methodology")
    if not args.type:
        parser.error("--type is required unless using --show-methodology")

    if not os.path.exists(args.file):
        print(f"Error: The file '{args.file}' was not found.")
        return

    # Load risk configuration if custom path provided
    if args.risk_config:
        if not os.path.exists(args.risk_config):
            print(f"Error: risk config file '{args.risk_config}' not found.", file=sys.stderr)
            sys.exit(1)
        try:
            with open(args.risk_config) as f:
                custom_config = yaml.safe_load(f)
            scorer.apply_config(custom_config)
            print(f"⚙️  Loaded custom risk configuration from {args.risk_config}")
        except yaml.YAMLError as e:
            print(f"Error: invalid YAML in '{args.risk_config}': {e}", file=sys.stderr)
            sys.exit(1)

    config = get_config()

    # 1. Parse dependencies
    print("\n")
    print(f"Parsing dependencies from {args.file}...")
    dependencies = []
    try:
        if args.type == 'npm':
            dependencies = npm_parser.parse_npm(args.file)
        elif args.type == 'pypi':
            dependencies = pypi_parser.parse_pypi(args.file)
        elif args.type == 'maven':
            dependencies = maven_parser.parse_maven(args.file)
    except FileNotFoundError:
        print(f"Error: The file '{args.file}' was not found.")
        return

    if not dependencies:
        print("No dependencies found.")
        return

    print(f"✅ Found {len(dependencies)} dependencies.")

    # 2. Check for suspicious packages
    packages_not_in_ecosystem = set()
    all_suspicious_findings = {}

    print("\n🕵️  Checking for suspicious packages...")
    all_suspicious_findings = detector.run_all_checks(dependencies, args.type)

    # Identify packages with dependency confusion (don't exist in target ecosystem)
    for package, findings in all_suspicious_findings.items():
        for finding in findings:
            if finding['type'] == 'Dependency Confusion':
                packages_not_in_ecosystem.add(package)
                break

    # Display suspicious package report immediately (will filter out packages with CVEs later)
    if args.format == 'terminal':
        if all_suspicious_findings:
            total_suspicious = len(all_suspicious_findings)
            print("\n--- 🕵️  Suspicious Package Report 🕵️  ---")

            # Group findings by type for better organization
            grouped_findings = group_suspicious_findings_by_type(all_suspicious_findings)

            # Display findings grouped by type
            for finding_type, packages in grouped_findings.items():
                print(f"\n - {finding_type} ({len(packages)} package{'s' if len(packages) != 1 else ''}):")
                for pkg_info in packages:
                    package_name = pkg_info['package_name']
                    finding = pkg_info['finding']

                    # Highlight package name with bold formatting
                    highlighted_name = f"{Colors.BOLD}{package_name}{Colors.RESET}"

                    if finding_type == 'Typosquatting':
                        details = finding['details']
                        print(f"   📦 {highlighted_name}: {details['similarity']}% similar to '{details['similar_to']}'")
                    else:
                        message = finding.get('message', 'No details available')
                        print(f"   📦 {highlighted_name}: {message}")
            print("\n")
            print(f"Total suspicious dependencies found: {total_suspicious}")

            print("\n--- End of Suspicious Package Report ---")
            print("\n")

        else:
            print("✅ No suspicious packages found.")

    # Filter out dependencies that don't exist in the target ecosystem before vulnerability check
    valid_dependencies = [dep for dep in dependencies if dep['name'].lower() not in packages_not_in_ecosystem]

    # 3. Check for vulnerabilities from multiple sources with loading spinner
    # OPTIMIZED: Run OSV and NVD in parallel to reduce total scan time
    stop_spinner = threading.Event()
    spinner_thread = threading.Thread(
        target=show_loading_spinner,
        args=("Checking for vulnerabilities with OSV, NVD, and KEV...", stop_spinner)
    )
    spinner_thread.start()

    try:
        # Process dependencies with parallel OSV and NVD execution
        osv_url = config.get('osv_api_url', "https://api.osv.dev/v1/querybatch")

        # Create thread pool for parallel execution

        vulnerabilities = []
        nvd_vulnerabilities = []

        # Run OSV, NVD, and KEV in parallel for comprehensive coverage
        with ThreadPoolExecutor(max_workers=3) as executor:
            osv_future = executor.submit(osv_checker.check_osv, valid_dependencies, osv_url, args.type)
            nvd_future = executor.submit(
                nvd_checker.check_nvd_for_missing_vulnerabilities, valid_dependencies, args.type)
            kev_future = executor.submit(scorer.get_kev_database)

            vulnerabilities = osv_future.result()
            # NVD is rate-limited; cap total wait so the scan doesn't hang indefinitely.
            # Without an API key: 5 req/30s ≈ 6s/req. With key: ~0.6s/req.
            has_api_key = bool(os.getenv('NVD_API_KEY'))
            per_dep_secs = 1 if has_api_key else 7
            nvd_timeout = 30 + len(valid_dependencies) * per_dep_secs
            try:
                nvd_vulnerabilities = nvd_future.result(timeout=nvd_timeout)
            except concurrent.futures.TimeoutError:
                print(
                    f"\nWARNING: NVD check timed out after {nvd_timeout}s. "
                    f"Results shown are OSV-only. Set NVD_API_KEY for faster full-coverage scans.",
                    file=sys.stderr
                )
                nvd_vulnerabilities = []
            try:
                kev_future.result(timeout=30)
            except Exception as e:
                print(f"WARNING: KEV pre-fetch failed: {e}", file=sys.stderr)

    except (requests.exceptions.RequestException, OSError) as e:
        stop_spinner.set()
        spinner_thread.join()
        raise e
    except Exception as e:
        # Re-raise unexpected errors after cleaning up the spinner
        stop_spinner.set()
        spinner_thread.join()
        raise e

    # 3.2. Merge NVD vulnerabilities with OSV results
    nvd_by_package_name = {}
    for nvd_vuln in nvd_vulnerabilities:
        affected = nvd_vuln.get('affected', [])
        if affected:
            package_name = affected[0].get('package', {}).get('name', '')
            if package_name:
                if package_name not in nvd_by_package_name:
                    nvd_by_package_name[package_name] = []
                nvd_by_package_name[package_name].append(nvd_vuln)

    # Merge NVD with OSV results by package name
    merged_vulnerabilities = {f"{v['dependency']['name']}@{v['dependency']['version']}": v for v in vulnerabilities}

    for dep_key, vuln_info in merged_vulnerabilities.items():
        package_name = vuln_info['dependency']['name']

        if package_name in nvd_by_package_name:
            # Avoid duplicates by checking CVE IDs and aliases
            existing_cve_ids = set()
            for existing_vuln in vuln_info['vulnerabilities']:
                if existing_vuln['id'].startswith('CVE-'):
                    existing_cve_ids.add(existing_vuln['id'])
                for alias in existing_vuln.get('aliases', []):
                    if alias.startswith('CVE-'):
                        existing_cve_ids.add(alias)

            for nvd_vuln in nvd_by_package_name[package_name]:
                if nvd_vuln['id'] not in existing_cve_ids:
                    vuln_info['vulnerabilities'].append(nvd_vuln)

    # Add NVD-only packages
    for package_name, nvd_vulns in nvd_by_package_name.items():
        if not any(v['dependency']['name'] == package_name for v in merged_vulnerabilities.values()):
            dep_key = f"{package_name}@*"
            merged_vulnerabilities[dep_key] = {
                'dependency': {'name': package_name, 'version': '*'},
                'vulnerabilities': nvd_vulns
            }

    vulnerabilities = list(merged_vulnerabilities.values())

    # Selective alias fetching for cross-source deduplication
    packages_needing_aliases = {}
    for vuln_info in vulnerabilities:
        pkg_name = vuln_info['dependency']['name']
        has_osv = False
        has_nvd = False

        for vuln in vuln_info.get('vulnerabilities', []):
            source = vuln.get('source', '')
            if source == 'OSV':
                has_osv = True
            elif source == 'NVD':
                has_nvd = True

        if has_osv and has_nvd:
            packages_needing_aliases[pkg_name] = vuln_info

    if packages_needing_aliases:
        osv_ids_to_enrich = []
        for vuln_info in packages_needing_aliases.values():
            for vuln in vuln_info.get('vulnerabilities', []):
                if vuln.get('source') == 'OSV':
                    osv_ids_to_enrich.append(vuln['id'])

        if osv_ids_to_enrich:
            aliases_map = osv_checker.get_vulnerability_aliases(osv_ids_to_enrich)
            for vuln_info in vulnerabilities:
                for vuln in vuln_info.get('vulnerabilities', []):
                    if vuln['id'] in aliases_map:
                        vuln['aliases'] = aliases_map[vuln['id']]

    # Collect unique CVE IDs for detailed fetching
    cve_ids_to_fetch = set()
    for vuln_info in vulnerabilities:
        for vuln in vuln_info.get('vulnerabilities', []):
            cve_id = vuln['id'] if vuln['id'].startswith('CVE-') else next(
                (alias for alias in vuln.get('aliases', []) if alias.startswith('CVE-')), None
            )
            if cve_id:
                cve_ids_to_fetch.add(cve_id)

    # Fetch NVD details for CVE enrichment
    nvd_details_map = {}
    if cve_ids_to_fetch:
        cve_list = list(cve_ids_to_fetch)

        if os.getenv('NVD_API_KEY'):
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                future_to_cve = {executor.submit(nvd_checker.get_cve_details, cve_id): cve_id for cve_id in cve_list}
                for future in concurrent.futures.as_completed(future_to_cve):
                    cve_id = future_to_cve[future]
                    try:
                        details = future.result()
                        if details:
                            nvd_details_map[cve_id] = details
                    except Exception as e:
                        # NVD detail fetch failed for this CVE; skip enrichment and continue
                        print(f"WARNING: Could not fetch NVD details for {cve_id}: {e}", file=sys.stderr)
        else:
            for cve_id in cve_list:
                details = nvd_checker.get_cve_details(cve_id)
                if details:
                    nvd_details_map[cve_id] = details

    # Enrich vulnerabilities with NVD metrics
    for vuln_info in vulnerabilities:
        for vuln in vuln_info.get('vulnerabilities', []):
            # Ensure source is a set for merging
            if isinstance(vuln.get('source'), str):
                vuln['source'] = {vuln['source']}
            elif not vuln.get('source'):
                vuln['source'] = set()

            # Find corresponding CVE ID and enrich with NVD data
            cve_id = vuln['id'] if vuln['id'].startswith('CVE-') else next(
                (alias for alias in vuln.get('aliases', []) if alias.startswith('CVE-')), None
            )

            if cve_id in nvd_details_map:
                vuln['metrics'] = nvd_details_map[cve_id].get('metrics', {})
                vuln['source'].add('NVD')

    # Deduplicate vulnerabilities using aliases
    merged_vulns = {}
    for vuln_info in vulnerabilities:
        dep_name = vuln_info['dependency']['name']
        if dep_name not in merged_vulns:
            merged_vulns[dep_name] = {
                'dependency': vuln_info['dependency'],
                'vulnerabilities': []
            }
        merged_vulns[dep_name]['vulnerabilities'].extend(vuln_info['vulnerabilities'])

    for dep_name, vuln_data in merged_vulns.items():
        canonical_vulns = {}
        alias_to_canonical = {}

        for vuln in vuln_data['vulnerabilities']:
            all_ids = [vuln['id']] + vuln.get('aliases', [])

            existing_canonical_id = next((alias_to_canonical[id] for id in all_ids if id in alias_to_canonical), None)

            if existing_canonical_id:
                canonical_vuln = canonical_vulns[existing_canonical_id]
                canonical_vuln['source'] = canonical_vuln.get('source', set()).union(vuln.get('source', set()))
                if vuln.get('metrics'):
                    canonical_vuln['metrics'] = vuln['metrics']
            else:
                canonical_id = next((id for id in all_ids if id.startswith('CVE-')), vuln['id'])
                canonical_vulns[canonical_id] = vuln
                for id in all_ids:
                    alias_to_canonical[id] = canonical_id

        merged_vulns[dep_name]['vulnerabilities'] = list(canonical_vulns.values())

    vulnerabilities = list(merged_vulns.values())

    # Filter suspicious findings to exclude packages with confirmed vulnerabilities
    packages_with_vulnerabilities = {vuln_info['dependency'].get('name', '') for vuln_info in vulnerabilities}
    suspicious_findings = {
        pkg: findings for pkg, findings in all_suspicious_findings.items()
        if pkg not in packages_with_vulnerabilities
    }

    # Stop the spinner now that processing is complete
    stop_spinner.set()
    spinner_thread.join()

    if not vulnerabilities and not all_suspicious_findings:
        print("\n✅ No issues found in any dependencies.")
        return

    if not vulnerabilities:
        report_items = []
        # fall through to the export block; suspicious findings are already populated

    # Calculate risk scores
    report_items = []
    for vuln_info in vulnerabilities:
        dep = vuln_info['dependency']
        vulns = vuln_info.get('vulnerabilities', [])

        if not vulns:
            continue

        package_info = {
            'name': dep.get('name', ''),
            'version': dep.get('version', ''),
            'ecosystem': args.type
        }
        score, severity = scorer.calculate_risk_score(vulns, package_info)
        risk_breakdown = scorer.calculate_detailed_risk_breakdown(vulns, package_info)

        # Extract remediation info
        highest_fixed_version = None
        for v in vulns:
            fixed_version_str = v.get('fixed_version')
            if fixed_version_str:
                try:
                    current_fixed = packaging.version.parse(fixed_version_str)
                    if not highest_fixed_version or current_fixed > highest_fixed_version:
                        highest_fixed_version = current_fixed
                except packaging.version.InvalidVersion:
                    if fixed_version_str.startswith('v'):
                        try:
                            current_fixed = packaging.version.parse(fixed_version_str[1:])
                            if not highest_fixed_version or current_fixed > highest_fixed_version:
                                highest_fixed_version = current_fixed
                        except packaging.version.InvalidVersion:
                            continue

        recommendation_msg = (
            f"Upgrade to version {highest_fixed_version} or later"
            if highest_fixed_version
            else "Check advisories for patched versions"
        )

        report_items.append({
            'dependency': dep,
            'score': score,
            'severity': severity,
            'vulnerabilities': vulns,
            'remediation': {
                'upgrade_to': str(highest_fixed_version) if highest_fixed_version else None,
                'message': recommendation_msg
            },
            'risk_breakdown': risk_breakdown
        })

    # Sort by risk score
    report_items.sort(key=lambda x: x['score'], reverse=True)

    # Generate reports
    if args.format == 'terminal':
        print_terminal_reports(report_items, args)
    elif args.format == 'json':
        export_json(report_items, suspicious_findings, args.output)
    elif args.format == 'csv':
        export_csv(report_items, suspicious_findings, args.output)


def print_terminal_reports(report_items, args=None):
    """Prints the vulnerability report to the terminal."""
    print("\n--- 🛡️ Vulnerability Report 🛡️ ---")

    # Display risk model configuration
    risk_config = scorer.get_risk_config()
    risk_weights = risk_config.get('risk_weights', {})

    if args.format == 'terminal' and (
        args.verbose_risk or risk_config.get('display', {}).get('verbose_risk_breakdown', True)
    ):
        print(f"⚙️  Risk Model Config Loaded: "
              f"[Severity={risk_weights.get('base_severity', 35)}%, "
              f"Exploit={risk_weights.get('exploit_pressure', 25)}%, "
              f"Exposure={risk_weights.get('exposure_context', 15)}%, "
              f"Volume={risk_weights.get('volume', 10)}%, "
              f"Patch Gap={risk_weights.get('patch_gap', 10)}%, "
              f"Credibility={risk_weights.get('credibility', 5)}%]")
        print()

    if not report_items:
        print("✅ No vulnerabilities found.")
    else:
        # Count severity levels for summary
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'NONE': 0}

        for item in report_items:
            dep = item['dependency']
            version_str = f"@{dep.get('version', '')}" if dep.get('version') else ""
            print(f"\n📦 Dependency: {dep['name']}{version_str}")
            colored_severity = colorize_severity(item['severity'])
            colored_score = colorize_risk_score(item['score'])
            print(f"   Overall Severity: {colored_severity} | Risk Score: {colored_score}")

            # Show risk breakdown if requested or configured
            risk_breakdown = item.get('risk_breakdown')
            verbose_risk = getattr(args, 'verbose_risk', False) if args else False
            compact_risk = getattr(args, 'compact_risk', False) if args else False
            config_verbose = scorer.get_risk_config().get('display', {}).get('verbose_risk_breakdown', False)

            if risk_breakdown and (verbose_risk or compact_risk or config_verbose):
                # Default to compact format unless explicitly requesting verbose
                if verbose_risk and not compact_risk:
                    breakdown_text = scorer.format_risk_breakdown(risk_breakdown, compact=False)
                    print(f"\n{breakdown_text}")
                else:
                    breakdown_text = scorer.format_risk_breakdown(risk_breakdown, compact=True)
                    print(f"   📈 Risk Breakdown → {breakdown_text}")

            # Count this severity level
            severity = item.get('severity', 'NONE')
            if severity in severity_counts:
                severity_counts[severity] += 1

            remediation = item.get('remediation')
            if remediation and remediation.get('message'):
                print(f"   💡 Recommendation: {remediation['message']}")

            print("   Vulnerabilities:")
            for vuln in item['vulnerabilities']:
                source = vuln.get('source', 'N/A')
                # Convert set to comma-separated string for display
                if isinstance(source, set):
                    source = ', '.join(sorted(list(source)))

                advisory_url = vuln.get('url', 'No advisory link available')
                print(f"     - ID: {vuln['id']} | SOURCE: {source} | Advisory: {advisory_url}")

        # Print summary
        print("\n📊 Risk Summary:")
        crit_s = 's' if severity_counts['CRITICAL'] != 1 else ''
        high_s = 's' if severity_counts['HIGH'] != 1 else ''
        med_s = 's' if severity_counts['MEDIUM'] != 1 else ''
        low_s = 's' if severity_counts['LOW'] != 1 else ''
        print(f"   🔴 Critical : {severity_counts['CRITICAL']} package{crit_s} (Score ≥ 85)")
        print(f"   🟠 High     : {severity_counts['HIGH']} package{high_s} (Score 65–84)")
        print(f"   🟡 Medium   : {severity_counts['MEDIUM']} package{med_s} (Score 35–64)")
        print(f"   🟢 Low      : {severity_counts['LOW']} package{low_s} (Score < 35)")

        total_vulnerable = sum(severity_counts.values())
        print(f"   📈 Total vulnerable dependencies: {total_vulnerable}")

    print("\n--- End of Vulnerability Report ---")
    print("\n")


def format_results(report_items, suspicious_findings):
    """Formats the raw findings into a structured dictionary for export."""
    results = {
        'vulnerabilities': [],
        'suspicious_packages': [],
        'vulnerability_summary': {},
        'suspicious_summary': {}
    }

    # Count vulnerability severity levels for summary
    vulnerability_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}

    for item in report_items:
        dep = item['dependency']
        vuln_list = []
        for v in item['vulnerabilities']:
            source = v.get('source', 'N/A')
            # Convert set to comma-separated string
            if isinstance(source, set):
                source = ', '.join(sorted(list(source)))
            vuln_list.append({
                'id': v.get('id', 'N/A'),
                'source': source,
                'url': v.get('url', 'N/A'),
                'aliases': v.get('aliases', [])
            })

        # Count severity
        severity = item.get('severity', 'LOW')
        if severity in vulnerability_counts:
            vulnerability_counts[severity] += 1

        # Include risk breakdown if available
        vulnerability_entry = {
            'dependency_name': dep['name'],
            'dependency_version': dep.get('version', 'N/A'),
            'overall_severity': item['severity'],
            'risk_score': item['score'],
            'remediation': item.get('remediation', {}),
            'vulnerabilities': vuln_list
        }

        # Add risk breakdown if available
        if 'risk_breakdown' in item and item['risk_breakdown']:
            vulnerability_entry['risk_breakdown'] = item['risk_breakdown']

        results['vulnerabilities'].append(vulnerability_entry)

    # Add vulnerability summary
    results['vulnerability_summary'] = {
        'total_packages_with_vulnerabilities': len(report_items),
        'packages_by_severity': vulnerability_counts
    }

    for pkg, findings in suspicious_findings.items():
        # The structure of findings is now a list of dictionaries
        results['suspicious_packages'].append({
            'package_name': pkg,
            'findings': findings
        })

    # Add suspicious package summary by type
    if suspicious_findings:
        grouped_findings = group_suspicious_findings_by_type(suspicious_findings)
        results['suspicious_summary'] = {
            'total_packages': len(suspicious_findings),
            'total_findings': sum(len(findings) for findings in suspicious_findings.values()),
            'findings_by_type': {
                finding_type: len(packages)
                for finding_type, packages in grouped_findings.items()
            }
        }

    return results


def group_suspicious_findings_by_type(suspicious_findings):
    """
    Group suspicious findings by finding type for better reporting.
    Returns a dictionary where keys are finding types and values are lists of packages.
    """
    grouped = defaultdict(list)

    for package_name, findings in suspicious_findings.items():
        for finding in findings:
            finding_type = finding['type']
            package_info = {
                'package_name': package_name,
                'finding': finding
            }
            grouped[finding_type].append(package_info)

    return dict(grouped)


def export_json(report_items, suspicious_findings, output_file):
    """Exports the results to a JSON file or stdout."""
    results = format_results(report_items, suspicious_findings)
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"✅ JSON report written to {output_file}")
    else:
        print(json.dumps(results, indent=2))


def export_csv(report_items, suspicious_findings, output_file):
    """Exports the results to CSV files or stdout."""
    results = format_results(report_items, suspicious_findings)

    vuln_output = None
    suspicious_output = None

    # Determine output targets (files or stdout)
    if output_file:
        base, _ = os.path.splitext(output_file)
        vuln_filename = f"{base}_vulnerabilities.csv"
        suspicious_filename = f"{base}_suspicious.csv"

        if results['vulnerabilities']:
            vuln_output = open(vuln_filename, 'w', newline='')
            print(f"✅ Vulnerability CSV report written to {vuln_filename}")
        if results['suspicious_packages']:
            suspicious_output = open(suspicious_filename, 'w', newline='')
            print(f"✅ Suspicious package CSV report written to {suspicious_filename}")
    else:
        import sys
        if results['vulnerabilities']:
            vuln_output = sys.stdout
            print("\n--- Vulnerabilities (CSV) ---")
        if results['suspicious_packages']:
            # Add a separator for stdout mode
            if results['vulnerabilities']:
                print()
            suspicious_output = sys.stdout
            print("--- Suspicious Packages (CSV) ---")

    # Write vulnerabilities CSV
    if vuln_output and results['vulnerabilities']:
        vuln_fieldnames = [
            'dependency_name', 'dependency_version', 'overall_severity', 'risk_score', 'recommended_upgrade',
            'base_severity_score', 'exploit_pressure_score', 'exposure_context_score',
            'volume_score', 'patch_gap_score', 'credibility_score',
            'max_cvss', 'vulnerability_count', 'exploit_indicators',
            'vulnerability_id', 'source', 'advisory_url'
        ]
        vuln_writer = csv.DictWriter(vuln_output, fieldnames=vuln_fieldnames)
        vuln_writer.writeheader()
        for item in results['vulnerabilities']:
            # Get risk breakdown data
            risk_breakdown = item.get('risk_breakdown', {})
            components = risk_breakdown.get('components', {})
            details = risk_breakdown.get('details', {})
            exploit_indicators = risk_breakdown.get('exploit_indicators', [])

            # Format exploit indicators as string
            exploit_str = (
                '; '.join([f"{ind[0]}:{ind[1]}" for ind in exploit_indicators])
                if exploit_indicators else 'None'
            )

            for vuln in item['vulnerabilities']:
                vuln_writer.writerow({
                    'dependency_name': item['dependency_name'],
                    'dependency_version': item['dependency_version'],
                    'overall_severity': item['overall_severity'],
                    'risk_score': item['risk_score'],
                    'recommended_upgrade': item.get('remediation', {}).get('upgrade_to'),
                    'base_severity_score': components.get('base_severity', 0),
                    'exploit_pressure_score': components.get('exploit_pressure', 0),
                    'exposure_context_score': components.get('exposure_context', 0),
                    'volume_score': components.get('volume', 0),
                    'patch_gap_score': components.get('patch_gap', 0),
                    'credibility_score': components.get('credibility', 0),
                    'max_cvss': details.get('max_cvss', 0),
                    'vulnerability_count': details.get('vulnerability_count', 0),
                    'exploit_indicators': exploit_str,
                    'vulnerability_id': vuln['id'],
                    'source': vuln['source'],
                    'advisory_url': vuln.get('url', 'N/A')
                })

    # Write suspicious packages CSV
    if suspicious_output and results['suspicious_packages']:
        suspicious_fieldnames = ['package_name', 'finding_type', 'details']
        suspicious_writer = csv.DictWriter(suspicious_output, fieldnames=suspicious_fieldnames)
        suspicious_writer.writeheader()
        for item in results['suspicious_packages']:
            for finding in item['findings']:
                details_str = ''
                if finding['type'] == 'Typosquatting':
                    details = finding['details']
                    details_str = f"Similar to '{details['similar_to']}' ({details['similarity']}%)"
                else:
                    details_str = finding.get('message', '')

                suspicious_writer.writerow({
                    'package_name': item['package_name'],
                    'finding_type': finding['type'],
                    'details': details_str
                })

    # Close files if they were opened
    if output_file:
        if vuln_output:
            vuln_output.close()
        if suspicious_output:
            suspicious_output.close()


if __name__ == '__main__':
    main()
