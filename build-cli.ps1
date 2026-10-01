param(
    [ValidateSet('win-x64', 'linux-x64', 'linux-arm64', 'osx-arm64')]
    [string]$RuntimeIdentifier = 'win-x64'
)

$ErrorActionPreference = 'Stop'
$project = Join-Path $PSScriptRoot 'launcher/SecurityScan.Cli/SecurityScan.Cli.csproj'
$output = Join-Path $PSScriptRoot "artifacts/cli/$RuntimeIdentifier"

dotnet publish $project `
    --configuration Release `
    --runtime $RuntimeIdentifier `
    -p:PublishAot=true `
    -p:StripSymbols=true `
    -p:TreatWarningsAsErrors=true `
    --output $output
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
Write-Output "Published Vesper Native AOT CLI: $output"