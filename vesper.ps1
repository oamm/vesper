$ErrorActionPreference = 'Stop'
$binary = Join-Path $PSScriptRoot 'artifacts/cli/win-x64/vesper.exe'
$project = Join-Path $PSScriptRoot 'launcher/SecurityScan.Cli/SecurityScan.Cli.csproj'
$projectDirectory = Split-Path $project
$buildInputs = @(
    Get-ChildItem $projectDirectory -Recurse -File |
        Where-Object {
            $_.FullName -notmatch '[\\/](bin|obj)[\\/]' -and
            $_.Extension -in '.cs', '.csproj', '.props', '.targets'
        }
)
$buildPropertyNames = @('Directory.Build.props', 'Directory.Build.targets', 'Directory.Packages.props', 'global.json')
$buildPropertyDirectories = @()
$directory = $projectDirectory
while ($directory) {
    $buildPropertyDirectories += $directory
    $parentDirectory = Split-Path $directory -Parent
    if (-not $parentDirectory -or $parentDirectory -eq $directory) {
        break
    }
    $directory = $parentDirectory
}
$buildInputs += @(
    foreach ($directory in $buildPropertyDirectories) {
        Get-ChildItem $directory -File |
            Where-Object { $_.Name -in $buildPropertyNames }
    }
)

$binaryIsFresh = $false
if (Test-Path $binary) {
    $binaryTimestamp = (Get-Item $binary).LastWriteTimeUtc
    $newestInput = $buildInputs | Measure-Object -Property LastWriteTimeUtc -Maximum
    $binaryIsFresh = $null -eq $newestInput.Maximum -or $newestInput.Maximum -le $binaryTimestamp
}

if ($binaryIsFresh) {
    & $binary @args
    exit $LASTEXITCODE
}

dotnet run --project $project -- @args
exit $LASTEXITCODE