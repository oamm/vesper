param(
    [string]$SdkImage = 'mcr.microsoft.com/dotnet/sdk:10.0'
)

$ErrorActionPreference = 'Stop'
$container = "vesper-linux-tests-$([guid]::NewGuid().ToString('N').Substring(0, 12))"
$created = $false

try {
    & docker run --detach --name $container $SdkImage sh -c 'sleep 900' | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not start the Linux .NET SDK test container.'
    }
    $created = $true

    & docker exec $container mkdir -p /src
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not prepare the Linux test workspace.'
    }
    & docker cp launcher "$($container):/src/"
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not transfer launcher sources to the Linux test host.'
    }
    & docker exec $container sh -c 'find /src/launcher -type d \( -name bin -o -name obj \) -prune -exec rm -rf {} +'
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not remove host-specific build outputs from the Linux test workspace.'
    }
    & docker exec $container dotnet run --project /src/launcher/SecurityScan.Tests/SecurityScan.Tests.csproj --configuration Release
    if ($LASTEXITCODE -ne 0) {
        throw "Linux launcher tests failed with exit code $LASTEXITCODE."
    }

    Write-Output 'PASS: launcher tests executed on the remote Linux Docker host.'
}
finally {
    if ($created) {
        & docker rm --force $container | Out-Null
    }
}