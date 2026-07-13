#!/usr/bin/env python3
"""
Threat Intelligence Trainer

Processes large datasets of packages to train the threat analysis system.
Can fetch threat intelligence from PyPI, npm, and Maven Central APIs.
"""

import asyncio
import aiohttp
import json
import sys
import argparse
import time
from typing import List, Dict

from .threat_processor import get_threat_processor


class BatchLearner:
    """Batch processes packages for learning."""

    def __init__(self, max_concurrent=10):
        self.threat_processor = get_threat_processor()
        self.max_concurrent = max_concurrent
        self.session = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            connector=aiohttp.TCPConnector(limit=self.max_concurrent)
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def fetch_pypi_popular_packages(self, limit: int = 1000) -> List[str]:
        """Fetch popular PyPI packages."""
        print(f"Fetching top {limit} PyPI packages...")

        # Use PyPI's "top packages" API or search API
        try:
            async with self.session.get(
                "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    packages = [row['project'] for row in data['rows'][:limit]]
                    print(f"Found {len(packages)} popular PyPI packages")
                    return packages
        except aiohttp.ClientError as e:
            print(f"Could not fetch PyPI popular packages: {e}", file=sys.stderr)

        # Return empty list - system will learn from actual scanned packages
        return []

    async def fetch_npm_popular_packages(self, limit: int = 1000) -> List[str]:
        """Fetch popular npm packages."""
        print(f"Fetching top {limit} npm packages...")

        # npm has a downloads API
        _packages = []  # noqa: F841
        try:
            # Get most downloaded packages
            async with self.session.get("https://api.npmjs.org/downloads/range/last-month") as response:
                if response.status == 200:
                    # This endpoint might not work, so we'll use a fallback
                    pass
        except aiohttp.ClientError:
            # Network failure fetching npm packages; return empty — scan continues
            pass

        # Return empty list - system will learn from actual scanned packages
        return []

    async def fetch_maven_popular_packages(self, limit: int = 500) -> List[str]:
        """Fetch popular Maven packages."""
        print(f"Fetching top {limit} Maven packages...")

        # Maven Central doesn't have a "most popular" API, return empty list
        # System will learn from actual scanned packages
        return []

    async def fetch_package_metadata(self, package_name: str, project_type: str) -> Dict:
        """Fetch metadata for a single package."""
        try:
            if project_type == 'pypi':
                url = f"https://pypi.org/pypi/{package_name}/json"
            elif project_type == 'npm':
                url = f"https://registry.npmjs.org/{package_name}"
            elif project_type == 'maven':
                if ':' in package_name:
                    group_id, artifact_id = package_name.split(':', 1)
                    url = (
                        f"https://search.maven.org/solrsearch/select"
                        f"?q=g:\"{group_id}\"+AND+a:\"{artifact_id}\"&rows=1&wt=json"
                    )
                else:
                    return None
            else:
                return None

            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    if project_type == 'maven' and 'response' in data:
                        docs = data['response']['docs']
                        return docs[0] if docs else None
                    return data
        except aiohttp.ClientError as e:
            print(f"Error fetching {package_name}: {e}", file=sys.stderr)

        return None

    async def process_package_batch(self, packages: List[str], project_type: str):
        """Process a batch of packages concurrently."""
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def process_single_package(package_name: str):
            async with semaphore:
                metadata = await self.fetch_package_metadata(package_name, project_type)
                if metadata:
                    self.threat_processor.learn_from_package(package_name, metadata, project_type)
                    return package_name
                return None

        tasks = [process_single_package(pkg) for pkg in packages]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        successful = [r for r in results if isinstance(r, str)]
        print(f"Successfully processed {len(successful)}/{len(packages)} {project_type} packages")

        return successful

    async def learn_from_ecosystem(self, project_type: str, limit: int):
        """Learn from an entire ecosystem."""
        print(f"\n=== Learning from {project_type.upper()} ecosystem ===")

        # Fetch popular packages
        if project_type == 'pypi':
            packages = await self.fetch_pypi_popular_packages(limit)
        elif project_type == 'npm':
            packages = await self.fetch_npm_popular_packages(limit)
        elif project_type == 'maven':
            packages = await self.fetch_maven_popular_packages(limit)
        else:
            print(f"Unknown project type: {project_type}")
            return

        if not packages:
            print(f"No packages found for {project_type}")
            return

        # Process in batches
        batch_size = 50
        total_processed = 0

        for i in range(0, len(packages), batch_size):
            batch = packages[i:i + batch_size]
            print(f"Processing batch {i//batch_size + 1}/{(len(packages) + batch_size - 1)//batch_size}...")

            processed = await self.process_package_batch(batch, project_type)
            total_processed += len(processed)

            # Save progress periodically
            if i % (batch_size * 5) == 0:
                self.threat_processor.save_all_learning_data()
                print(f"Progress saved. Total processed: {total_processed}")

            # Small delay to be nice to APIs
            await asyncio.sleep(1)

        print(f"Completed learning from {total_processed} {project_type} packages")


async def main():
    parser = argparse.ArgumentParser(description="Threat intelligence training from package ecosystems")
    parser.add_argument('--ecosystems', nargs='+',
                        choices=['pypi', 'npm', 'maven', 'all'],
                        default=['all'], help='Ecosystems to learn from')
    parser.add_argument('--limit', type=int, default=500,
                        help='Maximum packages per ecosystem')
    parser.add_argument('--concurrent', type=int, default=10,
                        help='Maximum concurrent requests')
    parser.add_argument('--custom-packages', type=str,
                        help='JSON file with custom package list')

    args = parser.parse_args()

    # Determine ecosystems to process
    if 'all' in args.ecosystems:
        ecosystems = ['pypi', 'npm', 'maven']
    else:
        ecosystems = args.ecosystems

    start_time = time.time()

    async with BatchLearner(max_concurrent=args.concurrent) as learner:
        # Process custom packages if provided
        if args.custom_packages:
            try:
                with open(args.custom_packages, 'r') as f:
                    custom_data = json.load(f)

                for project_type, packages in custom_data.items():
                    if project_type in ecosystems:
                        print(f"\nProcessing {len(packages)} custom {project_type} packages...")
                        await learner.process_package_batch(packages, project_type)
            except (OSError, json.JSONDecodeError, ValueError) as e:
                print(f"Error processing custom packages: {e}", file=sys.stderr)

        # Process each ecosystem
        for ecosystem in ecosystems:
            await learner.learn_from_ecosystem(ecosystem, args.limit)

        # Save final results
        learner.threat_processor.save_all_learning_data()

    elapsed = time.time() - start_time
    print(f"\n=== Batch learning completed in {elapsed:.1f} seconds ===")

    # Show final stats
    stats = get_threat_processor().get_learning_stats()
    print(f"Total packages learned: {stats['total_packages_learned']}")
    for eco, count in stats['popular_packages_discovered'].items():
        print(f"  {eco}: {count} popular packages discovered")

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nBatch learning interrupted.")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
