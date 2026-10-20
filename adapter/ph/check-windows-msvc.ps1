$ErrorActionPreference = 'Stop'

function Stop-Gate {
    param([Parameter(Mandatory = $true)][string]$Message)

    [Console]::Error.WriteLine("Windows MSVC gate: $Message")
    exit 1
}

function Invoke-GateCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    Write-Host ("+ {0} {1}" -f $Command, ($Arguments -join ' '))
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        Stop-Gate ("'{0} {1}' failed with exit code {2}." -f `
            $Command, ($Arguments -join ' '), $LASTEXITCODE)
    }
}

if ($env:OS -ne 'Windows_NT') {
    Stop-Gate 'This gate must run in native Windows PowerShell with an MSVC developer environment.'
}

foreach ($tool in @('cargo', 'rustup')) {
    if (-not (Get-Command $tool -CommandType Application -ErrorAction SilentlyContinue)) {
        Stop-Gate "Required command '$tool' was not found on PATH."
    }
}

if (-not (Get-Command 'cl.exe' -CommandType Application -ErrorAction SilentlyContinue)) {
    Stop-Gate 'MSVC cl.exe was not found on PATH. Run from a Visual Studio Developer PowerShell with C++ build tools installed.'
}
if (-not (Get-Command 'link.exe' -CommandType Application -ErrorAction SilentlyContinue)) {
    Stop-Gate 'MSVC link.exe was not found on PATH. The Windows MSVC linker is required to run the tests.'
}

$includeDirectories = @()
if ($env:INCLUDE) {
    $includeDirectories = @($env:INCLUDE -split ';' | ForEach-Object {
        $_.Trim().Trim('"')
    } | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Container) })
}
foreach ($header in @('windows.h', 'stdlib.h')) {
    $headerFound = $false
    foreach ($directory in $includeDirectories) {
        if (Test-Path -LiteralPath (Join-Path $directory $header) -PathType Leaf) {
            $headerFound = $true
            break
        }
    }
    if (-not $headerFound) {
        Stop-Gate "Could not find '$header' in INCLUDE. Initialize the Windows SDK and MSVC CRT environment before running this gate."
    }
}

$libraryDirectories = @()
if ($env:LIB) {
    $libraryDirectories = @($env:LIB -split ';' | ForEach-Object {
        $_.Trim().Trim('"')
    } | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Container) })
}
$kernelLibraryFound = $false
foreach ($directory in $libraryDirectories) {
    if (Test-Path -LiteralPath (Join-Path $directory 'kernel32.lib') -PathType Leaf) {
        $kernelLibraryFound = $true
        break
    }
}
if (-not $kernelLibraryFound) {
    Stop-Gate "Could not find 'kernel32.lib' in LIB. Initialize the Windows SDK library environment before running this gate."
}

$installedTargets = & rustup target list --installed
if ($LASTEXITCODE -ne 0) {
    Stop-Gate "'rustup target list --installed' failed with exit code $LASTEXITCODE."
}
if ($installedTargets -notcontains 'x86_64-pc-windows-msvc') {
    Stop-Gate "Rust target x86_64-pc-windows-msvc is not installed for the active toolchain. Install it separately, then rerun this gate."
}

Write-Host 'Wintun DLL is not required for this gate; fake API tests do not load a native DLL.'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Push-Location $repositoryRoot
try {
    Invoke-GateCommand 'cargo' @('check', '-p', 'ph', '--target', 'x86_64-pc-windows-msvc')
    Invoke-GateCommand 'cargo' @(
        'test',
        '-p', 'ph',
        '--lib',
        '--target', 'x86_64-pc-windows-msvc',
        'sys::windows_wintun::tests'
    )
}
finally {
    Pop-Location
}

Write-Host 'Windows MSVC compile and fake-backend test checks passed.'
