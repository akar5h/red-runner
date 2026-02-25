"""CLI entrypoint — red-runner."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

from .runner import load_catalog, run_catalog
from .scorer import Scorer
from .target import Target


def main(argv: list[str] | None = None):
    p = argparse.ArgumentParser(
        prog="red-runner",
        description="Run guardrail recon scenarios from an attack catalog.",
    )
    p.add_argument("catalog", help="Path to attack catalog JSON")
    p.add_argument("-c", "--config", default="config.yaml", help="Config YAML (default: config.yaml)")
    p.add_argument("--ids", nargs="*", help="Only run these scenario IDs")
    p.add_argument("--pass", dest="pass_filter", choices=["A", "B", "C"], help="Only run scenarios from this pass")
    p.add_argument("-o", "--output", help="Output results JSON path (default: results/<run_id>.json)")
    p.add_argument("-q", "--quiet", action="store_true", help="Suppress per-turn output")
    args = p.parse_args(argv)

    cfg_path = Path(args.config)
    if not cfg_path.exists():
        print(f"Config not found: {cfg_path}")
        print("Copy config.example.yaml → config.yaml and fill in your target details.")
        sys.exit(1)

    with open(cfg_path) as f:
        cfg = yaml.safe_load(f)

    catalog = load_catalog(args.catalog)
    target = Target(cfg["target"])
    scorer = Scorer(cfg.get("scoring", {}))

    try:
        results = run_catalog(
            catalog,
            target,
            scorer,
            ids=args.ids,
            pass_filter=args.pass_filter,
            verbose=not args.quiet,
        )
    finally:
        target.close()

    # Write results
    results_dir = Path("results")
    results_dir.mkdir(exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = Path(args.output) if args.output else results_dir / f"{ts}_{results['run_id']}.json"

    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nResults written to {out_path}")


if __name__ == "__main__":
    main()
