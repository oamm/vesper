#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
RUNTIME_IDENTIFIER=${1:-linux-x64}
case "$RUNTIME_IDENTIFIER" in
    win-x64|linux-x64|linux-arm64|osx-arm64) ;;
    *) echo "Unsupported runtime identifier: $RUNTIME_IDENTIFIER" >&2; exit 3 ;;
esac

dotnet publish "$SCRIPT_DIR/launcher/SecurityScan.Cli/SecurityScan.Cli.csproj" \
    --configuration Release \
    --runtime "$RUNTIME_IDENTIFIER" \
    -p:PublishAot=true \
    -p:StripSymbols=true \
    -p:TreatWarningsAsErrors=true \
    --output "$SCRIPT_DIR/artifacts/cli/$RUNTIME_IDENTIFIER"