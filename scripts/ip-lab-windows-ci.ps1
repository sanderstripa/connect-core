$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'Native Wintun harness is restricted to a disposable GitHub Windows VM' }
$labPrincipal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $labPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Disposable runner must be elevated' }
$labRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$labBin = Join-Path $labRoot 'bin'
$labScratch = Join-Path $labRoot 'ip-lab-artifacts'
New-Item -ItemType Directory -Force $labBin,$labScratch | Out-Null
$labArchive = Join-Path $labScratch 'wintun-0.14.1.zip'
Invoke-WebRequest -Uri 'https://www.wintun.net/builds/wintun-0.14.1.zip' -OutFile $labArchive -TimeoutSec 60
$labExpected = '07C256185D6EE3652E09FA55C0B673E2624B565E02C4B9091C79CA7D2F24EF51'
if ((Get-FileHash -LiteralPath $labArchive -Algorithm SHA256).Hash -ne $labExpected) { throw 'Official Wintun archive checksum mismatch' }
Expand-Archive -LiteralPath $labArchive -DestinationPath $labScratch -Force
$labDLL = Join-Path $labScratch 'wintun/bin/amd64/wintun.dll'
$labSignature = Get-AuthenticodeSignature -LiteralPath $labDLL
if ($labSignature.Status -ne 'Valid' -or $labSignature.SignerCertificate.Subject -notmatch 'O=WireGuard LLC') { throw 'Wintun publisher signature rejected' }
Copy-Item -LiteralPath $labDLL -Destination (Join-Path $labBin 'wintun.dll')
Push-Location $labRoot
try {
    go test -race -c -o bin/ipvpn-native.test.exe ./internal/ipvpn
    if ($LASTEXITCODE -ne 0) { throw 'Native test build failed' }
    $env:CONNECT_IP_LAB_NATIVE_TEST = '1'
    & (Join-Path $labBin 'ipvpn-native.test.exe') '-test.v' '-test.run=^TestWindowsNativeTUNQUICDNS$' '-test.timeout=90s'
    if ($LASTEXITCODE -ne 0) { throw 'Native Windows TUN/DNS test failed' }
} finally {
    Remove-Item Env:CONNECT_IP_LAB_NATIVE_TEST -ErrorAction SilentlyContinue
    Pop-Location
}
# No vendor DLL/archive is uploaded or committed; its prebuilt license is separate.
