# setup-kdc.ps1 - Run as Administrator on the Domain Controller
# Usage: .\setup-kdc.ps1 -AdcertPath C:\adcert\output
param(
    [string]$AdcertPath = "C:\adcert\output"
)

$ErrorActionPreference = "Stop"

function Step { Write-Host "`n[$($args[0])] $($args[1])" -ForegroundColor Cyan }
function OK   { Write-Host "    OK: $($args[0])" -ForegroundColor Green }
function Warn { Write-Host "    WARN: $($args[0])" -ForegroundColor Yellow }
function Fail { Write-Host "    FAIL: $($args[0])" -ForegroundColor Red; exit 1 }
function Info { Write-Host "    $($args[0])" }

# --- Paths -------------------------------------------------------------------
$caDer  = "$AdcertPath\ca\ca.der"
$kdcPfx = "$AdcertPath\kdc\kdc.pfx"
foreach ($f in $caDer, $kdcPfx) {
    if (-not (Test-Path $f)) { Fail "File not found: $f" }
}

# --- 1. CA thumbprint --------------------------------------------------------
Step 1 "Reading CA cert"
$caCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $caDer
$caThumb = $caCert.Thumbprint
Info "CA thumbprint: $caThumb"
Info "CA subject   : $($caCert.Subject)"

# --- 2. Local Trusted Root ---------------------------------------------------
Step 2 "Adding CA to LocalMachine\Root (system)"
$rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root","LocalMachine")
$rootStore.Open("ReadWrite")
$rootStore.Add($caCert)
$rootStore.Close()
$inRoot = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq $caThumb }
if ($inRoot) { OK "CA in LocalMachine\Root" } else { Fail "CA not in LocalMachine\Root" }

# --- 3. Publish CA to AD (Root + NTAuth) ------------------------------------
Step 3 "Publishing CA to AD Root CA and NTAuth"
& certutil -dspublish -f $caDer RootCA   2>&1 | ForEach-Object { Info $_ }
& certutil -dspublish -f $caDer NTAuthCA 2>&1 | ForEach-Object { Info $_ }

# --- 4. Write CA to system NTAuth then copy blob to enterprise stores --------
# certutil -dcinfo uses enterprise stores (HKLM\SOFTWARE\Microsoft\EnterpriseCertificates\)
# for its chain/NTAuth checks. Group Policy sync is not working on this DC so we
# write directly to the enterprise registry using the correctly-formatted blob
# that certutil produces when adding to the system store.
Step 4 "Populating system and enterprise certificate stores"

# 4a: system NTAuth (needed as blob source) - use -f to create store if it doesn't exist
& certutil -addstore -f NTAuth $caDer 2>&1 | ForEach-Object { Info $_ }

# 4b: system Root (blob source for enterprise Root)
& certutil -addstore -f Root $caDer 2>&1 | ForEach-Object { Info $_ }

# 4c: copy correctly-formatted blobs to enterprise store paths
# certutil -dcinfo reads enterprise stores (EnterpriseCertificates), not system stores.
# The enterprise Root write is known to work (certutil -dcinfo shows it).
# The enterprise NTAuth write uses the same approach.
$sysNTAuthBlob  = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\SystemCertificates\NTAuth\Certificates\$caThumb" -EA Stop).Blob
$sysRootBlob    = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates\$caThumb" -EA Stop).Blob

foreach ($store in "Root", "NTAuth") {
    $blob    = if ($store -eq "Root") { $sysRootBlob } else { $sysNTAuthBlob }
    $entPath = "HKLM:\SOFTWARE\Microsoft\EnterpriseCertificates\$store\Certificates\$caThumb"
    New-Item $entPath -Force | Out-Null
    Set-ItemProperty $entPath Blob $blob -Type Binary
    Info "Enterprise $store written ($($blob.Length) bytes)"
}

# Also write system NTAuth blob to Policy NTAuth (belt + suspenders)
$polNTAuth = "HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\NTAuth\Certificates\$caThumb"
New-Item $polNTAuth -Force | Out-Null
Set-ItemProperty $polNTAuth Blob $sysNTAuthBlob -Type Binary
Info "Policy NTAuth written"

OK "Enterprise and policy stores populated"

# --- 5. Add CA CRL to LocalMachine\CA store ---------------------------------
# Without a CRL, the KDC service hard-fails on CERT_TRUST_REVOCATION_STATUS_UNKNOWN
# and logs Events 19/29, refusing to use the KDC cert for PKINIT.
# Adding the CRL to the local CA store lets Windows complete the revocation check.
Step 5 "Adding CA CRL to LocalMachine\CA store"
$crlPath = "$AdcertPath\ca\ca.crl.der"
if (Test-Path $crlPath) {
    & certutil -addstore -f CA $crlPath 2>&1 | ForEach-Object { Info $_ }
    OK "CRL added to CA store"
} else {
    Warn "ca.crl.der not found at $crlPath - regenerate with updated generate.sh"
}

# --- 6. Remove stale KDC certs ----------------------------------------------
Step 6 "Removing stale KDC certs from LocalMachine\My"
$old = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Issuer -like '*EXAMPLE*' }
if ($old) {
    $old | ForEach-Object { Info "Removing: $($_.Thumbprint)  $($_.Subject)"; $_ | Remove-Item -Force }
    OK "Removed $($old.Count) old cert(s)"
} else {
    Info "No stale certs to remove"
}

# --- 7. Import KDC cert with legacy RSA SChannel CSP ------------------------
# Legacy CSP (not CNG) is required for certutil -dcinfo KDC cert discovery.
Step 7 "Importing KDC cert (kdc.pfx) with legacy RSA SChannel CSP (Press enter to continue)"
$importOut = & certutil -importpfx -csp "Microsoft RSA SChannel Cryptographic Provider" $kdcPfx NoExport 2>&1
$importOut | ForEach-Object { Info $_ }
if ($LASTEXITCODE -ne 0) { Fail "certutil -importpfx failed (exit $LASTEXITCODE)" }

$kdcCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.HasPrivateKey -and $_.Issuer -like '*EXAMPLE*' }
if (-not $kdcCert) { Fail "KDC cert not found in MY after import" }
OK "Imported: $($kdcCert.Thumbprint)  $($kdcCert.Subject)"
Info "Issuer : $($kdcCert.Issuer)"
Info "CSP    : $(& certutil -store My $kdcCert.Thumbprint 2>&1 | Select-String 'Provider =' | Select-Object -First 1)"

# --- 8. Confirm KDC EKU (inside EKU extension, not as top-level OID) --------
Step 8 "Confirming KDC EKU (1.3.6.1.5.2.3.5)"
$ekuExt = $kdcCert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' }
if ($ekuExt) {
    $ekuTyped = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]$ekuExt
    $ekuTyped.EnhancedKeyUsages | ForEach-Object { Info "EKU: $($_.Value)  $($_.FriendlyName)" }
    $hasKdcEku = $ekuTyped.EnhancedKeyUsages | Where-Object { $_.Value -eq '1.3.6.1.5.2.3.5' }
    if ($hasKdcEku) { OK "KDC EKU present" }
    else            { Fail "KDC EKU missing - regenerate with generate.sh" }
} else {
    Fail "No EKU extension at all - cert was signed without extensions"
}

# --- 9. Verify chain (no revocation check) ----------------------------------
Step 9 "Verifying certificate chain"
$chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
$chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
$chainOk = $chain.Build($kdcCert)
if ($chainOk) { OK "Chain valid" }
else { $chain.ChainStatus | ForEach-Object { Warn "Chain: $($_.StatusInformation.Trim())" } }

# --- 10. Grant NTDS and SYSTEM read access to private key -------------------
Step 10 "Granting NTDS and SYSTEM read access to private key"
$privKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($kdcCert)
if (-not $privKey) { Fail "No RSA private key found" }

$keyName = $privKey.Key.UniqueName
$keyFile  = "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys\$keyName"
if (-not (Test-Path $keyFile)) {
    $keyFile = "$env:ProgramData\Microsoft\Crypto\Keys\$keyName"
}
if (-not (Test-Path $keyFile)) { Fail "Key file not found: $keyFile" }
Info "Key file: $keyFile"

$acl = Get-Acl $keyFile
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule('NT SERVICE\NTDS','Read','Allow')))
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule('NT AUTHORITY\SYSTEM','Read','Allow')))
Set-Acl $keyFile $acl
OK "ACL set"

# --- 11. Restart KDC ---------------------------------------------------------
Step 11 "Restarting KDC service"
Restart-Service KDC -Force
OK "KDC restarted"

# --- 12. Summary and verify --------------------------------------------------
Step 12 "State summary"
$myKdc = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.HasPrivateKey -and $_.Issuer -like '*EXAMPLE*' }
Info "KDC certs in MY: $($myKdc.Count)"
$myKdc | ForEach-Object { Info "  $($_.Thumbprint) $($_.Subject)" }

$entNTAuthCount = (Get-ChildItem "HKLM:\SOFTWARE\Microsoft\EnterpriseCertificates\NTAuth\Certificates" -EA SilentlyContinue).Count
$entRootCount   = (Get-ChildItem "HKLM:\SOFTWARE\Microsoft\EnterpriseCertificates\Root\Certificates" -EA SilentlyContinue).Count
Info "Enterprise Root certs: $entRootCount"
Info "Enterprise NTAuth certs: $entNTAuthCount"

Write-Host ""
Write-Host "certutil -dcinfo verify:" -ForegroundColor Yellow
& certutil -dcinfo verify
