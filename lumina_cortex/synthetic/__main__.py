"""
CLI for synthetic data generation.

Usage:
    python -m lumina_cortex.synthetic --scenario attack_bruteforce --events 10000 > log.jsonl
"""

import argparse
import sys

from lumina_cortex.synthetic.generator import generate


def main():
    parser = argparse.ArgumentParser(
        description="Generate synthetic event logs for testing"
    )
    parser.add_argument(
        "--scenario",
        required=True,
        choices=[
            "benign_baseline",
            "attack_bruteforce",
            "drift_only",
            "score_only",
            "benign_rich",
            "benign_netflow",
            "attack_beacon",
            "benign_cloudtrail",
            "attack_cloud",
        ],
        help="Scenario to generate",
    )
    parser.add_argument(
        "--format",
        default="jsonl",
        choices=["jsonl", "csv"],
        help="Output format (default: jsonl)",
    )
    parser.add_argument(
        "--events",
        type=int,
        default=5000,
        help="Number of events to generate (default: 5000)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=0,
        help="Random seed for deterministic generation (default: 0)",
    )
    
    args = parser.parse_args()
    
    output = generate(
        scenario=args.scenario,
        fmt=args.format,
        seed=args.seed,
        events=args.events,
    )
    
    sys.stdout.buffer.write(output)


if __name__ == "__main__":
    main()
