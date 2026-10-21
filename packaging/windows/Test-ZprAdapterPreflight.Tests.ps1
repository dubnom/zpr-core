$script:PreflightScript = Join-Path $PSScriptRoot 'Test-ZprAdapterPreflight.ps1'
. $script:PreflightScript

$script:TestRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("zpr-preflight-tests-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $script:TestRoot | Out-Null

$script:FixturePaths = @{
    Dll         = Join-Path $script:TestRoot 'synthetic.dll'
    Profile     = Join-Path $script:TestRoot 'profile.toml'
    Checker     = Join-Path $script:TestRoot 'ph-windows-profile-check.exe'
    Ca          = Join-Path $script:TestRoot 'ca.pem'
    Certificate = Join-Path $script:TestRoot 'certificate.pem'
    PrivateKey  = Join-Path $script:TestRoot 'private-key-placeholder.pem'
}

Set-Content -LiteralPath $script:FixturePaths.Dll -Value 'synthetic non-secret DLL fixture bytes' -Encoding ASCII
Set-Content -LiteralPath $script:FixturePaths.Profile -Value @'
profile_version = 1

[global]
tun_if = "ZPR Test"
zpr_addr = ["fd00::10"]

[adapter]
node_addr = "192.0.2.10:5000"
name = "test-endpoint"
'@ -Encoding ASCII
Set-Content -LiteralPath $script:FixturePaths.Checker -Value 'synthetic non-secret checker placeholder' -Encoding ASCII
Set-Content -LiteralPath $script:FixturePaths.Ca -Value 'synthetic non-secret CA placeholder' -Encoding ASCII
Set-Content -LiteralPath $script:FixturePaths.Certificate -Value 'synthetic non-secret certificate placeholder' -Encoding ASCII
Set-Content -LiteralPath $script:FixturePaths.PrivateKey -Value 'synthetic non-secret key-path placeholder' -Encoding ASCII

function Get-ZprTestParameters {
    @{
        WintunDllPath     = $script:FixturePaths.Dll
        WintunDllSha256   = (Get-FileHash -LiteralPath $script:FixturePaths.Dll -Algorithm SHA256).Hash
        AdapterName       = 'ZPR Test'
        ProfilePath       = $script:FixturePaths.Profile
        ProfileCheckerPath = $script:FixturePaths.Checker
        CaFile            = $script:FixturePaths.Ca
        CertificateFile   = $script:FixturePaths.Certificate
        PrivateKeyFile    = $script:FixturePaths.PrivateKey
    }
}

Describe 'Test-ZprAdapterPreflight' {
    BeforeEach {
        $script:TestAdapterPresent = $true
        $script:TestProfileCheckerExitCode = 0

        Mock Get-ZprAdapterInventory {
            if ($script:TestAdapterPresent) {
                return [pscustomobject]@{
                    Name = 'ZPR Test'
                    InterfaceDescription = 'Wintun Userspace Tunnel'
                }
            }
            return $null
        }
        Mock Test-ZprElevatedToken { return $true }
        Mock Get-ZprAuthenticodeSignature {
            [pscustomobject]@{
                Status = 'Valid'
                SignerCertificate = [pscustomobject]@{ Subject = 'CN=WireGuard LLC, O=WireGuard LLC' }
            }
        }
        Mock Invoke-ZprProfileChecker { return $script:TestProfileCheckerExitCode }
    }

    It 'fails when the DLL path and explicit hash are missing' {
        $parameters = Get-ZprTestParameters
        $parameters.WintunDllPath = ''
        $parameters.WintunDllSha256 = ''

        $report = Test-ZprAdapterPreflight @parameters

        $report.ExitCode | Should Be 2
        ($report.Checks | Where-Object { $_.Name -eq 'wintun_dll' }).Status | Should Be 'FAIL'
        ($report.Checks | Where-Object { $_.Name -eq 'wintun_sha256_format' }).Status | Should Be 'FAIL'
    }

    It 'fails when the supplied DLL SHA-256 does not match exact file bytes' {
        $parameters = Get-ZprTestParameters
        $parameters.WintunDllSha256 = '0' * 64

        $report = Test-ZprAdapterPreflight @parameters

        $report.ExitCode | Should Be 2
        ($report.Checks | Where-Object { $_.Name -eq 'wintun_sha256' }).Status | Should Be 'FAIL'
    }

    It 'fails when the explicitly named adapter is absent from inventory' {
        $script:TestAdapterPresent = $false
        $parameters = Get-ZprTestParameters
        $report = Test-ZprAdapterPreflight @parameters

        $report.ExitCode | Should Be 2
        ($report.Checks | Where-Object { $_.Name -eq 'adapter_exists' }).Status | Should Be 'FAIL'
    }

    It 'fails when the operator profile file is missing' {
        $parameters = Get-ZprTestParameters
        $parameters.ProfilePath = Join-Path $script:TestRoot 'missing-profile.toml'

        $report = Test-ZprAdapterPreflight @parameters

        $report.ExitCode | Should Be 2
        ($report.Checks | Where-Object { $_.Name -eq 'profile_path' }).Status | Should Be 'FAIL'
        ($report.Checks | Where-Object { $_.Name -eq 'profile_schema' }).Status | Should Be 'FAIL'
    }

    It 'fails when a required credential file reference is missing' {
        $parameters = Get-ZprTestParameters
        $parameters.PrivateKeyFile = ''

        $report = Test-ZprAdapterPreflight @parameters

        $report.ExitCode | Should Be 2
        ($report.Checks | Where-Object { $_.Name -eq 'private_key_file' }).Status | Should Be 'FAIL'
    }

    It 'fails when the existing Core profile checker rejects the profile' {
        $script:TestProfileCheckerExitCode = 1
        $parameters = Get-ZprTestParameters
        $report = Test-ZprAdapterPreflight @parameters

        $report.ExitCode | Should Be 2
        ($report.Checks | Where-Object { $_.Name -eq 'profile_schema' }).Status | Should Be 'FAIL'
    }

    It 'reports unsupported runtime handoff and network lifecycle as blockers' {
        $report = Test-ZprAdapterPreflight (Get-ZprTestParameters)

        $report.ExitCode | Should Be 2
        ($report.Checks | Where-Object { $_.Name -eq 'profile_field_linkage' }).Status | Should Be 'BLOCKED'
        ($report.Checks | Where-Object { $_.Name -eq 'profile_field_linkage' }).Message | Should Match 'global\.tun_if'
        ($report.Checks | Where-Object { $_.Name -eq 'identity_handoff' }).Status | Should Be 'BLOCKED'
        ($report.Checks | Where-Object { $_.Name -eq 'network_lifecycle' }).Status | Should Be 'BLOCKED'
    }
}

Remove-Item -LiteralPath $script:FixturePaths.Dll
Remove-Item -LiteralPath $script:FixturePaths.Profile
Remove-Item -LiteralPath $script:FixturePaths.Checker
Remove-Item -LiteralPath $script:FixturePaths.Ca
Remove-Item -LiteralPath $script:FixturePaths.Certificate
Remove-Item -LiteralPath $script:FixturePaths.PrivateKey
Remove-Item -LiteralPath $script:TestRoot
