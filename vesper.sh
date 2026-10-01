#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
case "$(uname -s):$(uname -m)" in
    Linux:x86_64) RID=linux-x64 ;;
    Linux:aarch64|Linux:arm64) RID=linux-arm64 ;;
    Darwin:arm64) RID=osx-arm64 ;;
    *) RID= ;;
esac
if [ -n "$RID" ] && [ -x "$SCRIPT_DIR/artifacts/cli/$RID/vesper" ]; then
    exec "$SCRIPT_DIR/artifacts/cli/$RID/vesper" "$@"
fi
exec dotnet run --project "$SCRIPT_DIR/launcher/SecurityScan.Cli/SecurityScan.Cli.csproj" -- "$@"