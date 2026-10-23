# Install rr from its GitHub release, for Windows x86_64 and aarch64:
#
#     irm https://raw.githubusercontent.com/iivankin/rr/main/install.ps1 | iex
#
# By default the distribution goes to %LOCALAPPDATA%\Programs\rr, which is
# added to the user's PATH. RR_INSTALL names another directory for the
# distribution and changes no PATH: rr is then RR_INSTALL\rr.exe. RR_VERSION
# picks a release tag instead of the latest.

& {
    $ErrorActionPreference = 'Stop'
    # Windows PowerShell draws progress so slowly that it slows downloads.
    $ProgressPreference = 'SilentlyContinue'
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    $repo = 'iivankin/rr'
    try {
        $arch = [string][Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    } catch {
        $arch = $env:PROCESSOR_ARCHITECTURE
    }
    switch ($arch) {
        { $_ -in 'X64', 'AMD64' } { $name = 'rr-windows-x86_64' }
        { $_ -eq 'Arm64' } { $name = 'rr-windows-aarch64' }
        default { throw "rr install: no rr for Windows $arch" }
    }

    if ($env:RR_VERSION) {
        $url = "https://github.com/$repo/releases/download/$env:RR_VERSION"
    } else {
        $url = "https://github.com/$repo/releases/latest/download"
    }
    $custom = [bool]$env:RR_INSTALL
    if ($custom) {
        $dest = [IO.Path]::GetFullPath($env:RR_INSTALL)
    } else {
        $dest = Join-Path $env:LOCALAPPDATA 'Programs\rr'
    }

    # Replace only a directory that holds rr, never someone's other files.
    if ((Test-Path -LiteralPath $dest) -and
        -not ((Test-Path -LiteralPath (Join-Path $dest 'rr.exe') -PathType Leaf) -and
            (Test-Path -LiteralPath (Join-Path $dest 'lib\rustlib') -PathType Container))) {
        if ((Test-Path -LiteralPath $dest -PathType Leaf) -or
            (Get-ChildItem -LiteralPath $dest -Force | Select-Object -First 1)) {
            throw "rr install: $dest exists and is not an rr distribution"
        }
    }

    # The new distribution is unpacked beside its destination, so that it
    # replaces the old one by a rename on the same volume.
    $parent = Split-Path -Parent $dest
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    $tmp = Join-Path $parent ('.rr-install.' + [IO.Path]::GetRandomFileName())
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        Write-Host "Downloading $name from $url"
        $zip = Join-Path $tmp "$name.zip"
        $sums = Join-Path $tmp 'SHA256SUMS'
        Invoke-WebRequest -UseBasicParsing -Uri "$url/$name.zip" -OutFile $zip
        Invoke-WebRequest -UseBasicParsing -Uri "$url/SHA256SUMS" -OutFile $sums
        $want = Get-Content -LiteralPath $sums |
            ForEach-Object { $f = -split $_; if ($f[1] -in "$name.zip", "*$name.zip") { $f[0] } } |
            Select-Object -First 1
        if (-not $want) { throw "rr install: SHA256SUMS has no $name.zip" }
        if ((Get-FileHash -Algorithm SHA256 -LiteralPath $zip).Hash -ne $want) {
            throw "rr install: $name.zip: checksum mismatch"
        }
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::ExtractToDirectory($zip, $tmp)
        & (Join-Path $tmp "$name\rr.exe") --version | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'rr install: the downloaded rr does not run' }

        if (Test-Path -LiteralPath $dest) {
            Move-Item -LiteralPath $dest -Destination (Join-Path $tmp 'old')
        }
        Move-Item -LiteralPath (Join-Path $tmp $name) -Destination $dest
    } finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Host "Installed $(& (Join-Path $dest 'rr.exe') --version) in $dest"

    if ($custom) {
        Write-Host "Run it as $(Join-Path $dest 'rr.exe'), or add $dest to PATH."
        return
    }
    $path = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not (($path -split ';') -contains $dest)) {
        [Environment]::SetEnvironmentVariable('Path', (@($dest) + ($path -split ';' | Where-Object { $_ }) -join ';'), 'User')
        Write-Host "Added $dest to the user's PATH; new terminals find rr."
    }
    if (-not (($env:Path -split ';') -contains $dest)) {
        $env:Path = "$dest;$env:Path"
    }
}
