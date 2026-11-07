# Install rr from its GitHub release, for Windows x86_64 and aarch64:
#
#     irm https://raw.githubusercontent.com/iivankin/rr/main/install.ps1 | iex
#
# rr is a Clippy-like tool on the official Rust release it is built on:
# rustup installs that toolchain, rr goes into its bin\ beside rustc, as
# clippy-driver does, with what is its own in lib\rustlib\rr\, and that
# bin\ goes at the end of the user's PATH, after rustup's own tools, so
# that rustc and cargo stay rustup's. RR_VERSION picks a release tag
# instead of the latest.

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
    # rustup, also where its installer leaves it when PATH does not have it yet.
    $rustup = (Get-Command rustup -ErrorAction SilentlyContinue).Source
    if (-not $rustup) {
        $home_cargo = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $env:USERPROFILE '.cargo' }
        $rustup = Join-Path $home_cargo 'bin\rustup.exe'
        if (-not (Test-Path -LiteralPath $rustup -PathType Leaf)) {
            throw 'rr install: needs rustup, which installs Rust: https://rustup.rs'
        }
    }

    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('rr-install.' + [IO.Path]::GetRandomFileName())
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
        $unpacked = Join-Path $tmp 'rr'
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::ExtractToDirectory($zip, $unpacked)
        $release = (Get-Content -LiteralPath (Join-Path $unpacked 'lib\rustlib\rr\rust-version') -Raw).Trim()
        if (-not $release) { throw 'rr install: the archive names no Rust release' }

        Write-Host "Installing Rust $release with rustup"
        & $rustup toolchain install $release --profile minimal --no-self-update
        if ($LASTEXITCODE -ne 0) { throw "rr install: rustup could not install Rust $release" }
        $toolchain = (& $rustup run $release rustc --print sysroot).Trim()
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath (Join-Path $toolchain 'bin'))) {
            throw "rr install: no toolchain for Rust $release"
        }
        # rr's own files are replaced whole; the toolchain's are not touched.
        $own = Join-Path $toolchain 'lib\rustlib\rr'
        if (Test-Path -LiteralPath $own) { Remove-Item -LiteralPath $own -Recurse -Force }
        Copy-Item -Path (Join-Path $unpacked '*') -Destination $toolchain -Recurse -Force
    } finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
    $bin = Join-Path $toolchain 'bin'
    $rr = Join-Path $bin 'rr.exe'
    & $rr --version | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'rr install: the installed rr does not run' }
    Write-Host "Installed $(& $rr --version) in $toolchain"

    $path = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not (($path -split ';') -contains $bin)) {
        [Environment]::SetEnvironmentVariable('Path', ((@($path -split ';' | Where-Object { $_ }) + @($bin)) -join ';'), 'User')
        Write-Host "Added $bin to the end of the user's PATH; new terminals find rr."
    }
    if (-not (($env:Path -split ';') -contains $bin)) {
        $env:Path = "$env:Path;$bin"
    }
}
