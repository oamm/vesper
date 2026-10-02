import argparse
import sys
from pathlib import Path

from security_runner.baseline import BaselineError, create_baseline


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create a Vesper baseline from a completed schema-v2 scan.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create", help="Create a baseline artifact from a completed scan directory")
    create.add_argument("scan_result_dir", type=Path)
    create.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)

    try:
        baseline = create_baseline(args.scan_result_dir, args.output)
    except BaselineError as exc:
        print(f"[baseline] {exc}", file=sys.stderr)
        return 2
    print(f"Baseline {baseline['baselineId']} created at {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
