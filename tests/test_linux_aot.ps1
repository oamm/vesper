param(
    [string]$SdkImage = 'mcr.microsoft.com/dotnet/sdk:10.0'
)

$ErrorActionPreference = 'Stop'
$container = "vesper-linux-aot-$([guid]::NewGuid().ToString('N').Substring(0, 12))"
$created = $false

try {
    & docker run --detach --name $container --volume /var/run/docker.sock:/var/run/docker.sock $SdkImage sh -c 'sleep 1800' | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not start the Linux AOT test container.'
    }
    $created = $true

    & docker exec $container sh -c 'apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends clang zlib1g-dev docker.io ca-certificates'
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not install the Linux AOT native toolchain and Docker CLI.'
    }
    & docker exec $container mkdir -p /src /tmp/vesper-test
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not prepare the Linux AOT workspace.'
    }
    & docker cp launcher "$($container):/src/"
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not transfer launcher sources.'
    }
    & docker cp tests/fixtures/vulnerable-app "$($container):/tmp/vesper-test/"
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not transfer the vulnerable integration fixture.'
    }
    & docker cp tests/linux_signal_integration.sh "$($container):/tmp/linux_signal_integration.sh"
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not transfer the Linux signal integration test.'
    }
    & docker exec $container sh -c 'find /src/launcher -type d \( -name bin -o -name obj \) -prune -exec rm -rf {} +'
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not remove Windows build outputs before Linux publishing.'
    }

    & docker exec $container dotnet publish /src/launcher/SecurityScan.Cli/SecurityScan.Cli.csproj --configuration Release --runtime linux-x64 --self-contained true -p:PublishAot=true --output /tmp/vesper-aot
    if ($LASTEXITCODE -ne 0) {
        throw 'Linux x64 Native AOT publish failed.'
    }
    & docker exec $container /tmp/vesper-aot/vesper version
    if ($LASTEXITCODE -ne 0) {
        throw 'Linux Native AOT version smoke test failed.'
    }
    & docker exec $container /tmp/vesper-aot/vesper inspect
    if ($LASTEXITCODE -ne 0) {
        throw 'Linux Native AOT Docker inspect smoke test failed.'
    }

    & docker exec $container sh -c 'set +e; /tmp/vesper-aot/vesper scan /tmp/vesper-test/vulnerable-app --workspace-mode volume --output /tmp/vesper-aot-scan; result=$?; test "$result" -eq 1'
    if ($LASTEXITCODE -ne 0) {
        throw 'Linux Native AOT real remote-Docker scan did not return the expected vulnerable-fixture gate exit 1.'
    }

    & docker exec $container sh /tmp/linux_signal_integration.sh /tmp/vesper-aot/vesper /tmp/vesper-test/vulnerable-app /src/launcher/SecurityScan.Tests/SecurityScan.Tests.csproj
    if ($LASTEXITCODE -ne 0) {
        throw 'Linux SIGTERM/cancellation-isolation integration test failed.'
    }

    Write-Output 'PASS: linux-x64 AOT publish, direct version/inspect/scan, SIGTERM cleanup, and cancellation isolation.'
}
finally {
    if ($created) {
        & docker rm --force $container | Out-Null
    }
}
