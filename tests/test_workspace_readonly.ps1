param(
    [string]$Image = 'vesper-runner:0.2.0'
)

$ErrorActionPreference = 'Stop'
$scanId = [guid]::NewGuid().ToString('D')
$volume = "vesper-readonly-probe-$($scanId.Replace('-', '').Substring(0, 12))"
$volumeCreated = $false

try {
    $null = & docker volume create --label "securityscan.managed=true" --label "securityscan.scan-id=$scanId" --label "securityscan.resource=readonly-probe" $volume
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not create the temporary read-only probe volume.'
    }
    $volumeCreated = $true

    $pythonSource = @'
from pathlib import Path
try:
    Path('/workspace/should-fail').write_text('x')
except OSError:
    print('WORKSPACE_READ_ONLY')
else:
    raise SystemExit(42)
'@
    $encodedProbe = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($pythonSource))
    $probe = "import base64;exec(base64.b64decode('$encodedProbe'))"
    & docker run --rm --read-only --tmpfs /tmp:size=64m,noexec,nosuid,nodev `
        --security-opt=no-new-privileges --cap-drop=ALL --network=none `
        --cpus=0.25 --memory=256m --pids-limit=64 `
        --mount "type=volume,source=$volume,target=/workspace,readonly" `
        --entrypoint python $Image -c $probe
    if ($LASTEXITCODE -ne 0) {
        throw "/workspace write probe failed unexpectedly with exit code $LASTEXITCODE."
    }
    Write-Output 'PASS: runner could not write to its read-only /workspace mount.'
}
finally {
    if ($volumeCreated) {
        $null = & docker volume rm --force $volume
    }
}