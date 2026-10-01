#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec dotnet run --project "$SCRIPT_DIR/launcher/SecurityScan.Cli/SecurityScan.Cli.csproj" -- "$@"