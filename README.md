# adcert

Generates Active Directory-compatible PKI certificates using OpenSSL — no AD CS required. Produces a Root CA, KDC cert (RFC 4556 PKINIT), LDAPS cert, and smart card user certs, all signed by the same CA.

## Requirements

- `openssl` 1.1.1 or later (OpenSSL 3.x supported)
- `bash` 4+

## Quick start

```bash
REALM=CORP.EXAMPLE.COM \
DOMAIN_LOWER=corp.example.com \
DC_FQDN=dc1.corp.example.com \
DC_NETBIOS=DC1 \
USERS="alice bob" \
./generate.sh
```

Output lands in `./output/` by default.

## Configuration

All settings are environment variables with sensible defaults.

| Variable | Default | Description |
|---|---|---|
| `REALM` | `EXAMPLE.COM` | Kerberos realm — must match the AD domain in uppercase |
| `DOMAIN_LOWER` | `example.com` | DNS domain in lowercase — used for UPN SANs |
| `DC_FQDN` | `dc1.example.com` | Fully-qualified DC hostname — goes into DNS SANs |
| `DC_NETBIOS` | `DC1` | DC short / NetBIOS name — also added as a DNS SAN |
| `USERS` | `alice` | Space-separated list of usernames for smart card certs |
| `OUT` | `./output` | Output directory |
| `KEY_BITS` | `2048` | RSA key size |
| `DAYS_CA` | `3650` | CA certificate validity in days (~10 years) |
| `DAYS_CERT` | `825` | Leaf certificate validity in days (~2.25 years) |

## Output

```
output/
  ca/
    ca.key          Root CA private key
    ca.crt          Root CA certificate (PEM)
    ca.pem          Root CA certificate (PEM, copy of ca.crt) — use for Teleport / Linux trust anchors
    ca.der          Root CA certificate (DER) — use for AD NTAuth import
  kdc/
    kdc.key         KDC private key
    kdc.csr         KDC certificate signing request
    kdc.crt         KDC certificate (PEM)
    kdc.pfx         KDC cert + key (PKCS#12, no password) — import to DC Personal store
  ldaps/
    ldaps.key       LDAPS private key
    ldaps.csr       LDAPS CSR
    ldaps.crt       LDAPS certificate (PEM)
    ldaps.pfx       LDAPS cert + key (PKCS#12, no password) — import to DC Personal store
  users/
    <username>/
      user.key      User private key
      user.csr      User CSR
      user.crt      User certificate (PEM)
      user.pfx      User cert + key (PKCS#12, no password) — import to smart card / user store
```

## Certificate details

### Root CA

Self-signed CA with `pathlen:0`. Must be published to the AD **Root CA** store and the **NTAuth** store. NTAuth trust is required for PKINIT and smart card logon — without it, AD will reject authentication even if the cert chain verifies.

### KDC certificate

Enables [RFC 4556](https://www.rfc-editor.org/rfc/rfc4556) PKINIT — passwordless Kerberos authentication using public key cryptography.

| Field | Value |
|---|---|
| Extended Key Usage | `id-pkinit-KPKdc` (1.3.6.1.5.2.3.5), `serverAuth`, `clientAuth`, `Smart Card Logon` (1.3.6.1.4.1.311.20.2.2) |
| Key Usage | `digitalSignature`, `keyEncipherment`, `nonRepudiation` |
| SAN `otherName` | `KRB5PrincipalName` (1.3.6.1.5.2.2) = `krbtgt/REALM@REALM`, name-type 2 (NT-SRV-INST) |
| SAN `DNS` | `DC_FQDN`, `DC_NETBIOS` |
| MS Template Name | `KerberosAuthentication` (1.3.6.1.4.1.311.20.2) |
| MS Application Policies | mirrors all four EKUs (1.3.6.1.4.1.311.21.10) |

The four EKUs match the AD CS `Kerberos Authentication` template exactly — `certutil -dcinfo` on Windows Server uses the Application Policies extension and template name to identify KDC certs, not just the standard EKU extension.

The `KRB5PrincipalName` is encoded as a properly-tagged ASN.1 SEQUENCE using OpenSSL's config mini-language — compatible with MIT krb5, Heimdal, and Windows KDC.

The `serverAuth` EKU means this cert also works for LDAPS, so you can install just this one cert on the DC to cover both PKINIT and port 636.

### LDAPS certificate

Enables LDAP over SSL (port 636). The Windows NTDS service auto-selects any cert in the DC's Personal store that has `serverAuth` EKU and a matching DNS SAN.

| Field | Value |
|---|---|
| Extended Key Usage | `serverAuth` |
| Key Usage | `digitalSignature`, `keyEncipherment` |
| SAN `DNS` | `DC_FQDN`, `DC_NETBIOS`, `DOMAIN_LOWER` |

### Smart card / user certificate

Enables certificate-based Kerberos authentication (PKINIT client) and Windows smart card logon.

| Field | Value |
|---|---|
| Extended Key Usage | `id-pkinit-KPClientAuth` (1.3.6.1.5.2.3.4), `id-ms-kp-sc-logon` (1.3.6.1.4.1.311.20.2.2), `clientAuth` |
| Key Usage | `digitalSignature` |
| SAN `otherName` (msUPN) | `1.3.6.1.4.1.311.20.2.3` = `username@domain` — used by Windows logon |
| SAN `otherName` (KRB5) | `KRB5PrincipalName` (1.3.6.1.5.2.2) = `username@REALM`, name-type 1 (NT-PRINCIPAL) — used by MIT/Heimdal/SSSD |

## Installing into Active Directory

Use `setup-kdc.ps1` to handle the full installation in one step. Run it as Administrator on the DC.

### Automated install (recommended)

Copy the entire `output/` directory to the DC (e.g. `C:\output\`), then:

```powershell
Set-ExecutionPolicy Bypass -Scope Process
.\setup-kdc.ps1 -AdcertPath C:\output
```

The script handles everything automatically and ends with `certutil -dcinfo verify`. A successful run shows `1 KDC certificates for <DC>` and `CertUtil: -DCInfo command completed successfully.`

**What the script does:**

1. Adds the CA to `LocalMachine\Root`
2. Publishes the CA to AD Root CA and NTAuth stores via `certutil -dspublish`
3. Adds the CA to the system NTAuth store with `certutil -addstore -f NTAuth` and copies the correctly-formatted registry blobs to the enterprise and policy NTAuth/Root paths — Group Policy sync of these stores is not reliable without AD CS
4. Installs the CA CRL to `LocalMachine\CA` via `certutil -addstore CA ca.crl.der` — without a CRL, `CERT_TRUST_REVOCATION_STATUS_UNKNOWN` is treated as a hard failure by the KDC service (Events 19/29), preventing PKINIT even when the cert chain is otherwise valid
5. Removes stale KDC certs from `LocalMachine\My`
6. Imports `kdc.pfx` using the legacy `Microsoft RSA SChannel Cryptographic Provider` — this is required; using `Import-PfxCertificate` (CNG) causes `certutil -dcinfo` to not enumerate the cert
7. Grants `NT SERVICE\NTDS` and `SYSTEM` read access to the private key file
8. Restarts the KDC service
9. Runs `certutil -dcinfo verify`

---

### Manual steps (reference)

#### 1. Publish the CA to AD

```bat
certutil -dspublish -f ca.der RootCA
certutil -dspublish -f ca.der NTAuthCA
```

#### 2. Populate local certificate stores

`certutil -dspublish` writes to AD but Group Policy may not sync the local enterprise stores promptly without AD CS. Write to all three NTAuth paths directly:

```bat
certutil -addstore -f NTAuth ca.der
certutil -addstore -f Root   ca.der
```

```powershell
$caThumb = (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 "C:\output\ca\ca.der").Thumbprint
$ntauthBlob = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\SystemCertificates\NTAuth\Certificates\$caThumb").Blob
$rootBlob   = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates\$caThumb").Blob
foreach ($store in "Root","NTAuth") {
    $blob = if ($store -eq "Root") { $rootBlob } else { $ntauthBlob }
    foreach ($hive in "EnterpriseCertificates","Policies\Microsoft\SystemCertificates") {
        $p = "HKLM:\SOFTWARE\Microsoft\$hive\$store\Certificates\$caThumb"
        New-Item $p -Force | Out-Null; Set-ItemProperty $p Blob $blob -Type Binary
    }
}
```

#### 3. Install the CA CRL

Without a CRL, the KDC service treats `CERT_TRUST_REVOCATION_STATUS_UNKNOWN` as a hard failure and logs Events 19/29, refusing to use the KDC cert for PKINIT even when the cert chain is otherwise valid.

```bat
certutil -addstore CA ca.crl.der
```

Verify the CRL is present:

```bat
certutil -store CA
```

#### 5. Install the KDC certificate

Import must use the legacy RSA SChannel CSP. `Import-PfxCertificate` (CNG) prevents `certutil -dcinfo` from enumerating the cert.

```bat
certutil -importpfx -csp "Microsoft RSA SChannel Cryptographic Provider" kdc.pfx NoExport
```

Grant `NTDS` read on the private key, then restart the KDC:

```powershell
$cert    = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.HasPrivateKey }
$privKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
$keyFile = "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys\$($privKey.Key.UniqueName)"
if (-not (Test-Path $keyFile)) { $keyFile = "$env:ProgramData\Microsoft\Crypto\Keys\$($privKey.Key.UniqueName)" }
$acl = Get-Acl $keyFile
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule('NT SERVICE\NTDS','Read','Allow')))
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule('NT AUTHORITY\SYSTEM','Read','Allow')))
Set-Acl $keyFile $acl
Restart-Service KDC -Force
certutil -dcinfo verify
```

#### 6. Install the LDAPS certificate (optional)

The KDC cert already has `serverAuth` so LDAPS works automatically. To use a separate LDAPS cert:

```bat
certutil -importpfx -csp "Microsoft RSA SChannel Cryptographic Provider" ldaps.pfx NoExport
Restart-Service NTDS
```

Verify: open `ldp.exe`, connect to the DC on port 636 with SSL enabled.

#### 7. Map user certificates to AD accounts

```powershell
$serial = (openssl x509 -in output/users/alice/user.crt -noout -serial).Split("=")[1]
$issuer = (openssl x509 -in output/users/alice/user.crt -noout -issuer).Replace("issuer=", "")
Set-ADUser alice -Replace @{ altSecurityIdentities = "X509:<I>$issuer<SR>$serial" }
```

Or by UPN (requires cert UPN SAN to exactly match the AD UPN):

```powershell
Set-ADUser alice -Replace @{ altSecurityIdentities = "X509:<UPN>alice@corp.example.com" }
```

#### 8. Configure PKINIT clients (Linux / SSSD)

`/etc/krb5.conf`:

```ini
[libdefaults]
    pkinit_anchors = FILE:/etc/ssl/certs/ad-ca.crt

[appdefaults]
    pkinit_prompt_for_pin = false
```

Copy `output/ca/ca.crt` to `/etc/ssl/certs/ad-ca.crt` on each Linux host.

## SQL Server (domain-joined) configuration

For Teleport PKINIT authentication to reach SQL Server, the SQL Server machine needs SPNs registered and a Windows login for each AD user. The SQL Server itself never sees the certificate — it only validates the Kerberos service ticket that Teleport obtains after kinit succeeds.

### 1. Register SPNs

SPNs tell Kerberos which service account to use when issuing a ticket for the SQL Server. Without them, authentication falls back to NTLM or fails entirely.

Run on the DC (or any machine with AD admin rights):

```bat
REM Replace SQLSVC with the SQL Server service account and SQLHOST with the machine hostname
setspn -S MSSQLSvc\SQLHOST             DOMAIN\SQLSVC
setspn -S MSSQLSvc\SQLHOST:1433        DOMAIN\SQLSVC
setspn -S MSSQLSvc\SQLHOST.EXAMPLE.COM DOMAIN\SQLSVC
setspn -S MSSQLSvc\SQLHOST.EXAMPLE.COM:1433 DOMAIN\SQLSVC
```

Verify:

```bat
setspn -L DOMAIN\SQLSVC
```

If SQL Server runs as `NT SERVICE\MSSQLSERVER` (the default local service account), use the machine account instead:

```bat
setspn -S MSSQLSvc\SQLHOST             DOMAIN\SQLHOST$
setspn -S MSSQLSvc\SQLHOST:1433        DOMAIN\SQLHOST$
setspn -S MSSQLSvc\SQLHOST.EXAMPLE.COM DOMAIN\SQLHOST$
setspn -S MSSQLSvc\SQLHOST.EXAMPLE.COM:1433 DOMAIN\SQLHOST$
```

### 2. Enable Windows Authentication

In SQL Server Configuration Manager or SSMS, confirm the server authentication mode includes Windows Authentication. Mixed mode (SQL + Windows) is fine.

To check via T-SQL:

```sql
SELECT SERVERPROPERTY('IsIntegratedSecurityOnly');
-- 1 = Windows only, 0 = mixed mode (both are OK)
```

### 3. Create AD logins for each user

Each AD user that will authenticate via PKINIT needs a SQL Server login:

```sql
CREATE LOGIN [EXAMPLE\alice] FROM WINDOWS;

-- Grant access to a specific database
USE mydb;
CREATE USER [EXAMPLE\alice] FOR LOGIN [EXAMPLE\alice];
ALTER ROLE db_datareader ADD MEMBER [EXAMPLE\alice];
```

### 4. Trust the CA on the SQL Server machine

Not required for Kerberos auth itself, but good practice so SSMS and other tools on that machine can validate the CA chain:

```bat
certutil -addstore Root ca.der
```

### Verifying Kerberos is being used (not NTLM)

After a successful connection, check the auth type in SQL Server:

```sql
SELECT auth_scheme FROM sys.dm_exec_connections WHERE session_id = @@SPID;
-- Should return KERBEROS, not NTLM
```

If it returns `NTLM`, SPNs are missing or misconfigured.

## Inspecting generated certificates

```bash
# Check KDC EKU and KRB5PrincipalName SAN
openssl x509 -in output/kdc/kdc.crt -noout -text | grep -A6 "Extended Key\|Subject Alt"

# Check user cert UPN and KRB5PrincipalName SANs
openssl x509 -in output/users/alice/user.crt -noout -text | grep -A8 "Extended Key\|Subject Alt"

# Verify chain
openssl verify -CAfile output/ca/ca.crt output/kdc/kdc.crt
openssl verify -CAfile output/ca/ca.crt output/ldaps/ldaps.crt
openssl verify -CAfile output/ca/ca.crt output/users/alice/user.crt

# Raw ASN.1 dump of KDC cert (shows KRB5PrincipalName encoding)
openssl asn1parse -in output/kdc/kdc.crt
```

## Security notes

- The generated PFX files have **no password**. Set one for production use by removing `-passout pass:` and adding `-passout pass:yourpassword` in `generate.sh`, and protect the `output/` directory accordingly.
- Private keys in `output/` should be treated as secrets. Delete them after importing the PFX files if they are no longer needed.
- The CA key (`output/ca/ca.key`) is especially sensitive — anyone with it can issue trusted certs. Store it offline or in a secrets manager after the initial generation.
- Leaf cert validity is capped at 825 days for compatibility with Apple platform requirements.
