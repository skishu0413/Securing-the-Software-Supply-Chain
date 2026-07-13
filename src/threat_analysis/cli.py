#!/usr/bin/env python3
"""
Threat Analysis CLI

Command line interface for viewing, managing, and tuning the threat analysis system
that automatically discovers threat patterns and optimizes detection capabilities.
"""

import argparse
import json
import sys
import os

from .threat_processor import get_threat_processor


def show_stats(args):
    """Show threat analysis system statistics."""
    threat_processor = get_threat_processor()
    stats = threat_processor.get_learning_stats()

    print("=== Learning System Statistics ===")
    print(f"Total packages learned from: {stats['total_packages_learned']}")
    print(f"Last updated: {stats['last_updated']}")
    print()

    print("Popular packages discovered:")
    for ecosystem, count in stats['popular_packages_discovered'].items():
        print(f"  {ecosystem}: {count} packages")
    print()

    print("Ecosystem popularity averages:")
    for ecosystem, avg in stats['ecosystem_averages'].items():
        print(f"  {ecosystem}: {avg:.1f}")
    print()

    print(f"False positives reported: {stats['false_positives_reported']}")
    print(f"Confirmed typosquats: {stats['confirmed_typosquats']}")


def show_popular_packages(args):
    """Show discovered popular packages."""
    threat_processor = get_threat_processor()

    ecosystem = args.ecosystem
    if ecosystem == 'all':
        ecosystems = ['pypi', 'npm', 'maven']
    else:
        ecosystems = [ecosystem]

    for eco in ecosystems:
        packages = threat_processor.get_dynamic_popular_packages(eco)
        print(f"\n=== Popular {eco.upper()} packages ===")

        if args.limit:
            packages = packages[:args.limit]

        for i, package in enumerate(packages, 1):
            print(f"{i:3d}. {package}")

        print(f"\nTotal: {len(packages)} packages")


def show_thresholds(args):
    """Show current learned thresholds."""
    threat_processor = get_threat_processor()

    print("=== Current Learned Thresholds ===")

    for ecosystem in ['pypi', 'npm', 'maven']:
        print(f"\n{ecosystem.upper()}:")
        existing_threshold = threat_processor.get_dynamic_similarity_threshold(ecosystem, True)
        missing_threshold = threat_processor.get_dynamic_similarity_threshold(ecosystem, False)
        print(f"  Existing packages: {existing_threshold}%")
        print(f"  Missing packages:  {missing_threshold}%")


def report_false_positive(args):
    """Report a false positive detection."""
    threat_processor = get_threat_processor()

    threat_processor.report_false_positive(
        package_name=args.package,
        claimed_target=args.target,
        project_type=args.ecosystem
    )

    print(f"Reported false positive: {args.package} claimed to typosquat {args.target}")
    threat_processor.save_all_learning_data()


def report_confirmed_typosquat(args):
    """Report a confirmed typosquatting case."""
    threat_processor = get_threat_processor()

    threat_processor.report_confirmed_typosquat(
        package_name=args.package,
        target=args.target,
        project_type=args.ecosystem
    )

    print(f"Confirmed typosquat: {args.package} typosquats {args.target}")
    threat_processor.save_all_learning_data()


def export_learning_data(args):
    """Export learning data to JSON file."""
    threat_processor = get_threat_processor()

    data = {
        'stats': threat_processor.get_learning_stats(),
        'popular_packages': {
            eco: threat_processor.get_dynamic_popular_packages(eco)
            for eco in ['pypi', 'npm', 'maven']
        },
        'thresholds': {
            eco: {
                'existing': threat_processor.get_dynamic_similarity_threshold(eco, True),
                'missing': threat_processor.get_dynamic_similarity_threshold(eco, False)
            }
            for eco in ['pypi', 'npm', 'maven']
        },
        'common_targets': {
            eco: threat_processor.get_learned_common_targets(eco)
            for eco in ['pypi', 'npm', 'maven']
        }
    }

    with open(args.output, 'w') as f:
        json.dump(data, f, indent=2, default=str)

    print(f"Learning data exported to {args.output}")


def reset_learning_data(args):
    """Reset learning data (with confirmation)."""
    if not args.force:
        response = input("Are you sure you want to reset all learning data? This cannot be undone. (yes/no): ")
        if response.lower() != 'yes':
            print("Reset cancelled.")
            return

    threat_processor = get_threat_processor()

    # Clear cache files
    cache_files = [
        threat_processor.learning_data_file,
        threat_processor.popular_packages_file,
        threat_processor.patterns_file
    ]

    for cache_file in cache_files:
        if os.path.exists(cache_file):
            os.remove(cache_file)
            print(f"Removed {cache_file}")

    print("Learning data has been reset.")


def tune_thresholds(args):
    """Manually tune similarity thresholds."""
    threat_processor = get_threat_processor()

    # Update thresholds
    threat_processor.learned_patterns['similarity_thresholds'][args.ecosystem] = {
        'existing': args.existing,
        'missing': args.missing
    }

    threat_processor.save_all_learning_data()

    print(f"Updated {args.ecosystem} thresholds:")
    print(f"  Existing packages: {args.existing}%")
    print(f"  Missing packages: {args.missing}%")


def main():
    parser = argparse.ArgumentParser(description="Manage the dynamic learning system")
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Stats command
    stats_parser = subparsers.add_parser('stats', help='Show learning system statistics')
    stats_parser.set_defaults(func=show_stats)

    # Popular packages command
    popular_parser = subparsers.add_parser('popular', help='Show discovered popular packages')
    popular_parser.add_argument('--ecosystem', choices=['pypi', 'npm', 'maven', 'all'],
                                default='all', help='Package ecosystem')
    popular_parser.add_argument('--limit', type=int, help='Limit number of packages shown')
    popular_parser.set_defaults(func=show_popular_packages)

    # Thresholds command
    thresh_parser = subparsers.add_parser('thresholds', help='Show current learned thresholds')
    thresh_parser.set_defaults(func=show_thresholds)

    # Report false positive
    fp_parser = subparsers.add_parser('report-fp', help='Report a false positive detection')
    fp_parser.add_argument('package', help='Package name that was incorrectly flagged')
    fp_parser.add_argument('target', help='Target package it was claimed to typosquat')
    fp_parser.add_argument('ecosystem', choices=['pypi', 'npm', 'maven'], help='Package ecosystem')
    fp_parser.set_defaults(func=report_false_positive)

    # Report confirmed typosquat
    ct_parser = subparsers.add_parser('report-typosquat', help='Report a confirmed typosquatting case')
    ct_parser.add_argument('package', help='Typosquatting package name')
    ct_parser.add_argument('target', help='Target package being typosquatted')
    ct_parser.add_argument('ecosystem', choices=['pypi', 'npm', 'maven'], help='Package ecosystem')
    ct_parser.set_defaults(func=report_confirmed_typosquat)

    # Export command
    export_parser = subparsers.add_parser('export', help='Export learning data to JSON')
    export_parser.add_argument('output', help='Output JSON file path')
    export_parser.set_defaults(func=export_learning_data)

    # Reset command
    reset_parser = subparsers.add_parser('reset', help='Reset all learning data')
    reset_parser.add_argument('--force', action='store_true', help='Skip confirmation prompt')
    reset_parser.set_defaults(func=reset_learning_data)

    # Tune command
    tune_parser = subparsers.add_parser('tune', help='Manually tune similarity thresholds')
    tune_parser.add_argument('ecosystem', choices=['pypi', 'npm', 'maven'], help='Package ecosystem')
    tune_parser.add_argument('--existing', type=int, required=True,
                             help='Threshold for existing packages (60-95)')
    tune_parser.add_argument('--missing', type=int, required=True,
                             help='Threshold for missing packages (60-90)')
    tune_parser.set_defaults(func=tune_thresholds)

    args = parser.parse_args()

    if not hasattr(args, 'func'):
        parser.print_help()
        return

    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\nOperation cancelled.")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
