$ErrorActionPreference = 'Stop'
$project = Join-Path $PSScriptRoot 'launcher/SecurityScan.Cli/SecurityScan.Cli.csproj'
dotnet run --project $project -- @args
exit $LASTEXITCODE