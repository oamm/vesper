import argparse
import os
import sys
from pathlib import Path

from security_runner.runner import (
    EXIT_CONFIG_ERROR,
    EXIT_INTERNAL_ERROR,
    EXIT_RUNNER_FAILED,
    ConfigurationError,
    load_config,
    run_scan,
)


def main() -> int:
    if os.name != "nt":
        os.umask(0o077)
    parser = argparse.ArgumentParser(description="Run local source security scanners")
    parser.add_argument("--workspace", default="/workspace", type=Path)
    parser.add_argument("--output", default="/output", type=Path)
    parser.add_argument("--config", default=None, type=Path)
    args = parser.parse_args()
    config_path = args.config or (Path("/config/security.yaml") if Path("/config/security.yaml").exists() else None)
    try:
        config = load_config(config_path)
    except ConfigurationError as exc:
        print(f"[config] {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR
    try:
        exit_code, _ = run_scan(args.workspace, args.output, config)
        return exit_code
    except RuntimeError as exc:
        print(f"[runner] {exc}", file=sys.stderr)
        return EXIT_RUNNER_FAILED
    except Exception as exc:
        print(f"[runner] Unexpected error: {exc}", file=sys.stderr)
        return EXIT_INTERNAL_ERROR


if __name__ == "__main__":
    raise SystemExit(main())