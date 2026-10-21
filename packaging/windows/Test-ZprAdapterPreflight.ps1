[CmdletBinding()]
param(
    [string]$WintunDllPath,
    [string]$WintunDllSha256,
    [string]$AdapterName,
    [string]$ProfilePath,
    [string]$ProfileCheckerPath,
    [string]$CaFile,
    [string]$CertificateFile,
    [string]$PrivateKeyFile,
    [switch]$Help
)

function New-ZprPreflightCheck {
    param(
        [string]$Name,
        [ValidateSet('PASS', 'FAIL', 'BLOCKED', 'INFO')][string]$Status,
        [string]$Message
    )

    [pscustomobject]@{
        Name    = $Name
        Status  = $Status
        Message = $Message
    }
}

function Test-ZprLocalRegularFile {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return [pscustomobject]@{ Valid = $false; FullPath = $null; Reason = 'path was not supplied' }
    }
    if ($Path -notmatch '^[A-Za-z]:\\') {
        return [pscustomobject]@{ Valid = $false; FullPath = $null; Reason = 'use an absolute local drive path; UNC and provider paths are not accepted' }
    }

    try {
        $fullPath = [System.IO.Path]::GetFullPath($Path)
    }
    catch [System.ArgumentException] {
        return [pscustomobject]@{ Valid = $false; FullPath = $null; Reason = 'path syntax is invalid' }
    }
    catch [System.IO.PathTooLongException] {
        return [pscustomobject]@{ Valid = $false; FullPath = $null; Reason = 'path is too long' }
    }
    catch [System.NotSupportedException] {
        return [pscustomobject]@{ Valid = $false; FullPath = $null; Reason = 'path syntax is not supported' }
    }

    $driveRoot = [System.IO.Path]::GetPathRoot($fullPath)
    try {
        $drive = New-Object -TypeName System.IO.DriveInfo -ArgumentList $driveRoot
    }
    catch [System.ArgumentException] {
        return [pscustomobject]@{ Valid = $false; FullPath = $fullPath; Reason = 'path drive is invalid' }
    }
    if ($drive.DriveType -ne [System.IO.DriveType]::Fixed) {
        return [pscustomobject]@{ Valid = $false; FullPath = $fullPath; Reason = 'path must reside on a local fixed drive' }
    }
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ Valid = $false; FullPath = $fullPath; Reason = 'file is missing or inaccessible' }
    }

    $currentPath = $fullPath
    $rootPath = [System.IO.Path]::GetPathRoot($fullPath)
    while ($true) {
        try {
            $item = Get-Item -LiteralPath $currentPath -Force -ErrorAction Stop
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            return [pscustomobject]@{ Valid = $false; FullPath = $fullPath; Reason = 'a path component is missing or inaccessible' }
        }
        catch [System.UnauthorizedAccessException] {
            return [pscustomobject]@{ Valid = $false; FullPath = $fullPath; Reason = 'a path component is not readable' }
        }
        catch [System.IO.IOException] {
            return [pscustomobject]@{ Valid = $false; FullPath = $fullPath; Reason = 'a path component could not be inspected' }
        }

        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            return [pscustomobject]@{ Valid = $false; FullPath = $fullPath; Reason = 'file or parent path contains a reparse point' }
        }
        if ([string]::Equals($currentPath, $rootPath, [System.StringComparison]::OrdinalIgnoreCase)) {
            break
        }

        $parent = [System.IO.Directory]::GetParent($currentPath)
        if ($null -eq $parent) {
            return [pscustomobject]@{ Valid = $false; FullPath = $fullPath; Reason = 'path could not be resolved to a local drive root' }
        }
        $currentPath = $parent.FullName
    }

    $file = Get-Item -LiteralPath $fullPath -Force
    if ($file.PSIsContainer) {
        return [pscustomobject]@{ Valid = $false; FullPath = $fullPath; Reason = 'path is not a regular file' }
    }
    return [pscustomobject]@{ Valid = $true; FullPath = $fullPath; Reason = $null }
}

function Get-ZprAuthenticodeSignature {
    param([string]$Path)

    Get-AuthenticodeSignature -LiteralPath $Path
}

function Get-ZprAdapterInventory {
    param([string]$Name)

    if ($null -eq (Get-Command Get-NetAdapter -ErrorAction SilentlyContinue)) {
        return $null
    }
    $matches = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ceq $Name -and $_.InterfaceDescription -match 'Wintun' })
    if ($matches.Count -ne 1) {
        return $null
    }
    $matches[0]
}

function Test-ZprElevatedToken {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList $identity
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-ZprProfileChecker {
    param(
        [string]$CheckerPath,
        [string]$Path
    )

    & $CheckerPath $Path *> $null
    [int]$LASTEXITCODE
}

function Test-ZprAdapterPreflight {
    [CmdletBinding()]
    param(
        [string]$WintunDllPath,
        [string]$WintunDllSha256,
        [string]$AdapterName,
        [string]$ProfilePath,
        [string]$ProfileCheckerPath,
        [string]$CaFile,
        [string]$CertificateFile,
        [string]$PrivateKeyFile
    )

    $checks = New-Object 'System.Collections.Generic.List[object]'

    $dllPathCheck = Test-ZprLocalRegularFile -Path $WintunDllPath
    if (-not $dllPathCheck.Valid) {
        $checks.Add((New-ZprPreflightCheck 'wintun_dll' 'FAIL' "Wintun DLL path: $($dllPathCheck.Reason)"))
    }
    elseif ([System.IO.Path]::GetExtension($dllPathCheck.FullPath) -ine '.dll') {
        $checks.Add((New-ZprPreflightCheck 'wintun_dll' 'FAIL' 'Wintun path must identify a .dll file.'))
    }
    else {
        $checks.Add((New-ZprPreflightCheck 'wintun_dll' 'PASS' "Local regular DLL found: $($dllPathCheck.FullPath)"))
    }

    $hashFormatValid = $WintunDllSha256 -cmatch '^[0-9A-Fa-f]{64}$'
    if (-not $hashFormatValid) {
        $checks.Add((New-ZprPreflightCheck 'wintun_sha256_format' 'FAIL' 'Supply an explicit 64-character hexadecimal Wintun DLL SHA-256; no default pin is used.'))
    }
    elseif ($dllPathCheck.Valid -and [System.IO.Path]::GetExtension($dllPathCheck.FullPath) -ieq '.dll') {
        try {
            $actualHash = (Get-FileHash -LiteralPath $dllPathCheck.FullPath -Algorithm SHA256 -ErrorAction Stop).Hash
            if ([string]::Equals($actualHash, $WintunDllSha256, [System.StringComparison]::OrdinalIgnoreCase)) {
                $checks.Add((New-ZprPreflightCheck 'wintun_sha256' 'PASS' "SHA-256 matches the explicit pin: $actualHash"))
            }
            else {
                $checks.Add((New-ZprPreflightCheck 'wintun_sha256' 'FAIL' "DLL bytes do not match the supplied SHA-256 pin; actual hash: $actualHash"))
            }
        }
        catch [System.UnauthorizedAccessException] {
            $checks.Add((New-ZprPreflightCheck 'wintun_sha256' 'FAIL' 'Wintun DLL cannot be read to verify its bytes.'))
        }
        catch [System.IO.IOException] {
            $checks.Add((New-ZprPreflightCheck 'wintun_sha256' 'FAIL' 'Wintun DLL could not be hashed.'))
        }
        catch [System.Management.Automation.RuntimeException] {
            $checks.Add((New-ZprPreflightCheck 'wintun_sha256' 'FAIL' 'Wintun DLL could not be hashed.'))
        }
    }
    else {
        $checks.Add((New-ZprPreflightCheck 'wintun_sha256' 'FAIL' 'A valid local Wintun DLL is required before its bytes can be checked.'))
    }

    if ($dllPathCheck.Valid -and [System.IO.Path]::GetExtension($dllPathCheck.FullPath) -ieq '.dll') {
        try {
            $signature = Get-ZprAuthenticodeSignature -Path $dllPathCheck.FullPath
            $signerSubject = $null
            if ($null -ne $signature.SignerCertificate) {
                $signerSubject = $signature.SignerCertificate.Subject
            }
            if ($signature.Status -eq 'Valid' -and $signerSubject -match '(^|,\s*)CN=WireGuard LLC(,|$)') {
                $checks.Add((New-ZprPreflightCheck 'wintun_signature' 'PASS' 'Authenticode signature is valid and the signer is WireGuard LLC; the DLL was not loaded.'))
            }
            else {
                $checks.Add((New-ZprPreflightCheck 'wintun_signature' 'FAIL' "Expected a valid WireGuard LLC Authenticode signature; status was $($signature.Status)."))
            }
        }
        catch [System.Management.Automation.RuntimeException] {
            $checks.Add((New-ZprPreflightCheck 'wintun_signature' 'FAIL' 'Authenticode signature could not be verified; the DLL was not loaded.'))
        }
    }
    else {
        $checks.Add((New-ZprPreflightCheck 'wintun_signature' 'FAIL' 'A valid local Wintun DLL is required before its signature can be checked.'))
    }

    $profilePathCheck = Test-ZprLocalRegularFile -Path $ProfilePath
    if (-not $profilePathCheck.Valid) {
        $checks.Add((New-ZprPreflightCheck 'profile_path' 'FAIL' "Preflight profile path: $($profilePathCheck.Reason)"))
    }
    else {
        $checks.Add((New-ZprPreflightCheck 'profile_path' 'PASS' "Local profile found: $($profilePathCheck.FullPath)"))
    }

    $checkerPathCheck = Test-ZprLocalRegularFile -Path $ProfileCheckerPath
    if (-not $checkerPathCheck.Valid) {
        $checks.Add((New-ZprPreflightCheck 'profile_checker' 'FAIL' "Profile checker path: $($checkerPathCheck.Reason) Build ph-windows-profile-check.exe from the Core source before running this preflight."))
    }
    elseif ([System.IO.Path]::GetFileName($checkerPathCheck.FullPath) -ine 'ph-windows-profile-check.exe') {
        $checks.Add((New-ZprPreflightCheck 'profile_checker' 'FAIL' 'The checker must be the Core ph-windows-profile-check.exe binary.'))
    }
    elseif (-not $profilePathCheck.Valid) {
        $checks.Add((New-ZprPreflightCheck 'profile_schema' 'FAIL' 'Profile schema was not checked because the profile file is unavailable.'))
    }
    else {
        try {
            $profileExitCode = Invoke-ZprProfileChecker -CheckerPath $checkerPathCheck.FullPath -Path $profilePathCheck.FullPath
            if ($profileExitCode -eq 0) {
                $checks.Add((New-ZprPreflightCheck 'profile_schema' 'PASS' 'The existing Core profile checker accepted the versioned Windows preflight schema.'))
            }
            else {
                $checks.Add((New-ZprPreflightCheck 'profile_schema' 'FAIL' "Core profile checker rejected the profile (exit code $profileExitCode); checker output was suppressed to avoid disclosing profile contents."))
            }
        }
        catch [System.Management.Automation.CommandNotFoundException] {
            $checks.Add((New-ZprPreflightCheck 'profile_schema' 'FAIL' 'Core profile checker could not be started.'))
        }
        catch [System.Management.Automation.ApplicationFailedException] {
            $checks.Add((New-ZprPreflightCheck 'profile_schema' 'FAIL' 'Core profile checker could not be started.'))
        }
        catch [System.Management.Automation.RuntimeException] {
            $checks.Add((New-ZprPreflightCheck 'profile_schema' 'FAIL' 'Core profile checker could not be started.'))
        }
    }

    foreach ($credential in @(
        @{ Name = 'ca_file'; Path = $CaFile },
        @{ Name = 'certificate_file'; Path = $CertificateFile },
        @{ Name = 'private_key_file'; Path = $PrivateKeyFile }
    )) {
        $credentialPathCheck = Test-ZprLocalRegularFile -Path $credential.Path
        if ($credentialPathCheck.Valid) {
            $checks.Add((New-ZprPreflightCheck $credential.Name 'PASS' 'Operator-supplied local file reference exists; file contents were not read.'))
        }
        else {
            $checks.Add((New-ZprPreflightCheck $credential.Name 'FAIL' "Required $($credential.Name) reference: $($credentialPathCheck.Reason)"))
        }
    }

    if ([string]::IsNullOrWhiteSpace($AdapterName)) {
        $checks.Add((New-ZprPreflightCheck 'adapter_name' 'FAIL' 'Supply the intended existing Wintun adapter name; no default is used.'))
    }
    else {
        $checks.Add((New-ZprPreflightCheck 'adapter_name' 'INFO' "Checking the explicitly supplied adapter name: $AdapterName"))
        $adapter = Get-ZprAdapterInventory -Name $AdapterName
        if ($null -eq $adapter) {
            $checks.Add((New-ZprPreflightCheck 'adapter_exists' 'FAIL' "No existing Wintun adapter exactly named '$AdapterName' was found. This check does not create one."))
        }
        else {
            $checks.Add((New-ZprPreflightCheck 'adapter_exists' 'PASS' "Existing Wintun adapter found: $AdapterName"))
        }
    }

    if (Test-ZprElevatedToken) {
        $checks.Add((New-ZprPreflightCheck 'elevation' 'PASS' 'Current process has an elevated administrator token; no elevation was requested by this read-only script.'))
    }
    else {
        $checks.Add((New-ZprPreflightCheck 'elevation' 'BLOCKED' 'Creating/installing a Wintun adapter requires elevation. This script will not self-elevate.'))
    }

    $checks.Add((New-ZprPreflightCheck 'profile_field_linkage' 'BLOCKED' 'Credential paths are explicit inputs named after Core fields global.ca_file, global.certificate_file, and global.private_key_file; this checker validates paths individually but does not reconcile a separate runtime config. AdapterName is checked against host inventory but is not compared with profile global.tun_if; verify they match before use.'))
    $checks.Add((New-ZprPreflightCheck 'identity_handoff' 'BLOCKED' 'Windows DPAPI enrollment-to-runtime key handoff is unsupported. File existence does not prove protected key use; do not export or copy private keys.'))
    $checks.Add((New-ZprPreflightCheck 'adapter_lifecycle' 'BLOCKED' 'Current Core Windows backend opens an existing Wintun adapter; driver installation and WintunCreateAdapter lifecycle are not implemented.'))
    $checks.Add((New-ZprPreflightCheck 'network_lifecycle' 'BLOCKED' 'Windows address, route, DNS, firewall, and service lifecycle are unsupported. This validator makes no network or service changes.'))
    $checks.Add((New-ZprPreflightCheck 'mutation' 'INFO' 'No DLL load, adapter creation, enrollment, route/DNS/firewall/service change, or network traffic was attempted.'))

    $failureCount = @($checks | Where-Object { $_.Status -eq 'FAIL' }).Count
    $blockerCount = @($checks | Where-Object { $_.Status -eq 'BLOCKED' }).Count
    $exitCode = 0
    if ($blockerCount -gt 0) {
        $exitCode = 2
    }
    elseif ($failureCount -gt 0) {
        $exitCode = 1
    }

    [pscustomobject]@{
        ExitCode     = $exitCode
        FailureCount = $failureCount
        BlockerCount = $blockerCount
        Checks       = @($checks.ToArray())
    }
}

function Get-ZprPreflightUsage {
    @'
Usage:
  .\Test-ZprAdapterPreflight.ps1 `
    -WintunDllPath <local-signed-wintun.dll> `
    -WintunDllSha256 <64-hex-character-pin> `
    -AdapterName <existing-Wintun-adapter-name> `
    -ProfilePath <version-1-preflight.toml> `
    -ProfileCheckerPath <ph-windows-profile-check.exe> `
    -CaFile <global.ca_file-path> `
    -CertificateFile <global.certificate_file-path> `
    -PrivateKeyFile <global.private_key_file-path>

All paths and the SHA-256 pin are explicit; no DLL/hash defaults are provided.
Credential file contents are never read or printed. This read-only validator
does not install a driver, create an adapter, enroll an identity, or change
routes, DNS, firewall, services, or host configuration.
'@
}

if ($MyInvocation.InvocationName -ne '.') {
    if ($Help) {
        Get-ZprPreflightUsage
        exit 0
    }

    $report = Test-ZprAdapterPreflight `
        -WintunDllPath $WintunDllPath `
        -WintunDllSha256 $WintunDllSha256 `
        -AdapterName $AdapterName `
        -ProfilePath $ProfilePath `
        -ProfileCheckerPath $ProfileCheckerPath `
        -CaFile $CaFile `
        -CertificateFile $CertificateFile `
        -PrivateKeyFile $PrivateKeyFile

    foreach ($check in $report.Checks) {
        Write-Output ("{0} [{1}] {2}" -f $check.Status, $check.Name, $check.Message)
    }
    if ($report.ExitCode -eq 0) {
        Write-Output 'RESULT: preflight inputs passed.'
    }
    elseif ($report.ExitCode -eq 1) {
        Write-Output ("RESULT: NOT READY ({0} failed check(s))." -f $report.FailureCount)
    }
    else {
        Write-Output ("RESULT: BLOCKED ({0} unsupported or authorization blocker(s), {1} failed check(s))." -f $report.BlockerCount, $report.FailureCount)
    }
    exit $report.ExitCode
}
