param(
    [Parameter(Mandatory = $true)]
    [string]$CliPath,
    [Parameter(Mandatory = $true)]
    [string]$Workspace,
    [string]$WorkspaceB,
    [Parameter(Mandatory = $true)]
    [string]$PassConfig
)

$ErrorActionPreference = 'Stop'
$cli = (Resolve-Path $CliPath).Path
$workspacePath = (Resolve-Path $Workspace).Path
$workspacePathB = if ([string]::IsNullOrWhiteSpace($WorkspaceB)) { $workspacePath } else { (Resolve-Path $WorkspaceB).Path }
$configPath = (Resolve-Path $PassConfig).Path
$outputRoot = Join-Path ([System.IO.Path]::GetTempPath()) "securityscan-concurrency-$([guid]::NewGuid().ToString('N'))"
$logA = Join-Path ([System.IO.Path]::GetTempPath()) "vesper-concurrency-a-$([guid]::NewGuid().ToString('N')).log"
$logB = Join-Path ([System.IO.Path]::GetTempPath()) "vesper-concurrency-b-$([guid]::NewGuid().ToString('N')).log"
$null = New-Item -ItemType Directory -Force -Path $outputRoot

function Get-ManagedRunnerLabels {
    $names = @(& docker ps --filter 'label=securityscan.managed=true' --filter 'label=securityscan.resource=runner' --format '{{.Names}}')
    if ($LASTEXITCODE -ne 0 -or $names.Count -eq 0) {
        return @()
    }
    $labels = @()
    foreach ($name in $names) {
        $json = & docker inspect --format '{{json .Config.Labels}}' $name
        if ($LASTEXITCODE -eq 0 -and $json) {
            $labels += ,($json | ConvertFrom-Json)
        }
    }
    return $labels
}

function Assert-True([bool]$condition, [string]$message) {
    if (-not $condition) {
        throw $message
    }
}

$scanA = Start-Job -ArgumentList $cli, $workspacePath, $outputRoot, $logA -ScriptBlock {
    param($exePath, $sourcePath, $outputPath, $logPath)
    & $exePath $sourcePath --output $outputPath --cpus 1 --memory 2g --pids-limit 256 --verbose *> $logPath
    $LASTEXITCODE
}
$scanB = Start-Job -ArgumentList $cli, $workspacePathB, $outputRoot, $configPath, $logB -ScriptBlock {
    param($exePath, $sourcePath, $outputPath, $configFile, $logPath)
    & $exePath $sourcePath --output $outputPath --config $configFile --cpus 1 --memory 2g --pids-limit 256 --verbose *> $logPath
    $LASTEXITCODE
}

$observedRunnerLabels = @()
$observedVolumeLabels = @()
$testPassed = $false
$deadline = [DateTime]::UtcNow.AddMinutes(2)
while ([DateTime]::UtcNow -lt $deadline -and ($scanA.State -eq 'Running' -or $scanB.State -eq 'Running')) {
    $observedRunnerLabels = @(Get-ManagedRunnerLabels)
    if ($observedRunnerLabels.Count -ge 2) {
        $volumeNames = @(& docker volume ls --filter 'label=securityscan.managed=true' --format '{{.Name}}')
        foreach ($volumeName in $volumeNames) {
            $volumeJson = & docker volume inspect --format '{{json .Labels}}' $volumeName
            if ($LASTEXITCODE -eq 0 -and $volumeJson) {
                $observedVolumeLabels += ,($volumeJson | ConvertFrom-Json)
            }
        }
        break
    }
}

$null = Wait-Job $scanA, $scanB
$exitA = [int](@(Receive-Job $scanA)[-1])
$exitB = [int](@(Receive-Job $scanB)[-1])
Remove-Job $scanA, $scanB

try {
    Assert-True ($observedRunnerLabels.Count -ge 2) 'Expected two simultaneously active runner containers.'
    $activeIds = @($observedRunnerLabels | ForEach-Object { $_.'securityscan.scan-id' } | Where-Object { $_ })
    Assert-True ($activeIds.Count -ge 2 -and (@($activeIds | Select-Object -Unique).Count -eq $activeIds.Count)) 'Active runners did not have distinct scan IDs.'
    foreach ($id in $activeIds) {
        $resourceLabels = @($observedVolumeLabels | Where-Object { $_.'securityscan.scan-id' -eq $id } | ForEach-Object { $_.'securityscan.resource' })
        Assert-True ($resourceLabels -contains 'source' -and $resourceLabels -contains 'output') "Scan $id did not have isolated source/output volumes."
    }

    Assert-True (($exitA -eq 1 -and $exitB -eq 0) -or ($exitA -eq 0 -and $exitB -eq 1)) "Expected independent gate exits 1 and 0, got $exitA and $exitB."

    $reports = @(Get-ChildItem $outputRoot -Directory)
    Assert-True ($reports.Count -eq 2) 'Expected two separate scan-ID output directories.'
    $reportIds = @()
    $gateStatuses = @()
    foreach ($directory in $reports) {
        $scan = Get-Content (Join-Path $directory.FullName 'scan.json') -Raw | ConvertFrom-Json
        $summary = Get-Content (Join-Path $directory.FullName 'summary.json') -Raw | ConvertFrom-Json
        $reportIds += $scan.scanId
        $gateStatuses += $summary.gate.status
        Assert-True ($directory.Name -eq $scan.scanId.Replace('-', '')) 'Report directory must be named from its full scan ID.'
    }
    Assert-True (@($reportIds | Select-Object -Unique).Count -eq 2) 'Reports did not preserve distinct scan IDs.'
    Assert-True (@($gateStatuses | Select-Object -Unique).Count -eq 2) 'The separate test policies should produce independent gate states.'

    $scenario = if ($workspacePath -eq $workspacePathB) { 'same-project' } else { 'different-project' }
    Write-Output "PASS: two concurrent $scenario scans used distinct labeled containers, volumes, scan IDs, and output directories."
    Write-Output "Gate exits: $exitA, $exitB"
    Write-Output "Scan IDs: $($reportIds -join ', ')"
    $testPassed = $true
}
catch {
    Write-Error $_
    Write-Output "Scan A log: $logA"
    Write-Output "Scan B log: $logB"
    exit 1
}
finally {
    if ($scanA.State -eq 'Running') { Stop-Job $scanA; Remove-Job $scanA }
    if ($scanB.State -eq 'Running') { Stop-Job $scanB; Remove-Job $scanB }
    Remove-Item -LiteralPath $outputRoot -Recurse -Force -ErrorAction SilentlyContinue
    if ($testPassed) {
        Remove-Item -LiteralPath $logA, $logB -Force -ErrorAction SilentlyContinue
    }
}