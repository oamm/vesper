$ErrorActionPreference = 'Stop'
$binary = Join-Path $PSScriptRoot 'artifacts/cli/win-x64/vesper.exe'
if (Test-Path $binary) {
    & $binary @args
    exit $LASTEXITCODE
}
$project = Join-Path $PSScriptRoot 'launcher/SecurityScan.Cli/SecurityScan.Cli.csproj'
dotnet run --project $project -- @args
exit $LASTEXITCODE