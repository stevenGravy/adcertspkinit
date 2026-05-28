#!/usr/bin/env bash
# Generates AD-compatible PKI certificates without AD CS:
#   - Root CA
#   - KDC cert (RFC 4556 PKINIT, id-pkinit-KPKdc EKU + KRB5PrincipalName SAN)
#   - LDAPS cert (serverAuth, DC DNS SANs)
#   - Smart card / user certs (id-pkinit-KPClientAuth + MS smart card logon EKU)
#
# Usage:
#   REALM=CORP.EXAMPLE.COM \
#   DOMAIN_LOWER=corp.example.com \
#   DC_FQDN=dc1.corp.example.com \
#   DC_NETBIOS=DC1 \
#   USERS="alice bob" \
#   ./generate.sh

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
REALM="${REALM:-EXAMPLE.COM}"
DOMAIN_LOWER="${DOMAIN_LOWER:-example.com}"
DC_FQDN="${DC_FQDN:-dc1.example.com}"
DC_NETBIOS="${DC_NETBIOS:-DC1}"
USERS="${USERS:-alice}"
OUT="${OUT:-./output}"
KEY_BITS="${KEY_BITS:-2048}"
DAYS_CA="${DAYS_CA:-3650}"
DAYS_CERT="${DAYS_CERT:-825}"
# ─────────────────────────────────────────────────────────────────────────────

info() { printf '\033[0;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[0;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[0;31m[✗]\033[0m %s\n' "$*" >&2; exit 1; }

command -v openssl >/dev/null 2>&1 || die "openssl not found in PATH"

mkdir -p "$OUT"/{ca,kdc,ldaps,users}

# ── Root CA ───────────────────────────────────────────────────────────────────
info "Generating Root CA for realm: $REALM"

cat > "$OUT/ca/ca.cnf" <<CNFEOF
[req]
distinguished_name = dn
x509_extensions    = ca_exts
prompt             = no

[dn]
CN = ${REALM} Root CA
O  = ${REALM}

[ca_exts]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always
basicConstraints       = critical,CA:TRUE,pathlen:0
keyUsage               = critical,keyCertSign,cRLSign
CNFEOF

openssl genrsa -out "$OUT/ca/ca.key" "$KEY_BITS" 2>/dev/null
openssl req -new -x509 \
  -key "$OUT/ca/ca.key" \
  -out "$OUT/ca/ca.crt" \
  -days "$DAYS_CA" \
  -config "$OUT/ca/ca.cnf" \
  2>/dev/null
openssl x509 -in "$OUT/ca/ca.crt" -out "$OUT/ca/ca.der" -outform DER 2>/dev/null
cp "$OUT/ca/ca.crt" "$OUT/ca/ca.pem"

# Generate an empty CRL so Windows KDC can complete revocation checks.
# Without a CRL, the KDC treats CERT_TRUST_REVOCATION_STATUS_UNKNOWN as a
# hard failure and refuses to use the KDC cert for PKINIT (Events 19 & 29).
touch "$OUT/ca/index.txt"
echo 01 > "$OUT/ca/crlnumber"
cat > "$OUT/ca/crl.cnf" <<CRLEOF
[ca]
default_ca = CA_default
[CA_default]
database     = ${OUT}/ca/index.txt
crlnumber    = ${OUT}/ca/crlnumber
default_days = 365
default_md   = sha256
[crl_ext]
authorityKeyIdentifier = keyid:always
CRLEOF
openssl ca -config "$OUT/ca/crl.cnf" \
  -keyfile "$OUT/ca/ca.key" \
  -cert "$OUT/ca/ca.crt" \
  -gencrl -crldays 3650 \
  -out "$OUT/ca/ca.crl" 2>/dev/null
openssl crl -in "$OUT/ca/ca.crl" -outform DER -out "$OUT/ca/ca.crl.der" 2>/dev/null

info "  CA cert  : $OUT/ca/ca.crt  (also ca.pem)"
info "  CA (DER) : $OUT/ca/ca.der  ← use this for AD NTAuth import"
info "  CA CRL   : $OUT/ca/ca.crl.der  ← add to DC with: certutil -addstore CA ca.crl.der"

# ── Sign helper ───────────────────────────────────────────────────────────────
sign_cert() {
  local csr="$1" cert="$2" extfile="$3" extsect="$4"
  local err
  err=$(openssl x509 -req \
    -in "$csr" \
    -CA "$OUT/ca/ca.crt" \
    -CAkey "$OUT/ca/ca.key" \
    -CAcreateserial \
    -out "$cert" \
    -days "$DAYS_CERT" \
    -sha256 \
    -extfile "$extfile" \
    -extensions "$extsect" \
    2>&1)
  if [ $? -ne 0 ]; then
    die "openssl x509 failed for $cert:\n$err"
  fi
  # Verify the expected EKU extension actually landed in the cert
  if ! openssl x509 -in "$cert" -noout -text 2>/dev/null | grep -q "Extended Key Usage"; then
    die "Extensions missing from $cert — openssl may not support SEQUENCE:section in SAN on this version.\nopenssl version: $(openssl version)\nSigning error output:\n$err"
  fi
}

export_pfx() {
  local cert="$1" key="$2" pfx="$3"
  # Windows certutil -importpfx hangs on AES-256 encrypted PFX files (OpenSSL 3.x default).
  # Try legacy PBE ciphers in order of preference so the output always works with certutil.
  # PowerShell Import-PfxCertificate accepts any of these formats.
  #
  # Tier 1: OpenSSL 3.x -legacy flag (sets 3DES key + RC2-40 cert PBE, SHA1 MAC)
  openssl pkcs12 -export \
    -in "$cert" -inkey "$key" \
    -certfile "$OUT/ca/ca.crt" \
    -out "$pfx" -passout pass: \
    -legacy 2>/dev/null && return
  # Tier 2: explicit legacy PBE ciphers — works on OpenSSL 1.x and LibreSSL
  openssl pkcs12 -export \
    -in "$cert" -inkey "$key" \
    -certfile "$OUT/ca/ca.crt" \
    -out "$pfx" -passout pass: \
    -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-RC2-40 -macalg SHA1 2>/dev/null && return
  # Tier 3: default encryption — AES-256, certutil -importpfx will hang; use PowerShell
  warn "Legacy PFX export unavailable — import with Import-PfxCertificate in PowerShell, not certutil -importpfx"
  openssl pkcs12 -export \
    -in "$cert" -inkey "$key" \
    -certfile "$OUT/ca/ca.crt" \
    -out "$pfx" -passout pass: 2>/dev/null
}

# ── KDC Certificate ───────────────────────────────────────────────────────────
# RFC 4556 §3.2.4 requires:
#   EKU  : id-pkinit-KPKdc (1.3.6.1.5.2.3.5)
#   SAN  : otherName with KRB5PrincipalName OID (1.3.6.1.5.2.2)
#            krbtgt/<REALM>@<REALM> (name-type=2 NT-SRV-INST)
#          + DNS name of the KDC
info "Generating KDC certificate (PKINIT / id-pkinit-KPKdc)..."

cat > "$OUT/kdc/kdc.cnf" <<CNFEOF
[req]
distinguished_name = dn
req_extensions     = kdc_req_exts
prompt             = no

[dn]
CN = ${DC_FQDN}
O  = ${REALM}

# Referenced by both req_extensions and the signing extensions below.
[kdc_san]
otherName.1 = 1.3.6.1.5.2.2;SEQUENCE:kdc_princ_name
DNS.1       = ${DC_FQDN}
DNS.2       = ${DC_NETBIOS}

# KRB5PrincipalName ::= SEQUENCE {
#   realm         [0] GeneralString,
#   principalName [1] SEQUENCE {
#     name-type   [0] INTEGER,          -- 2 = NT-SRV-INST
#     name-string [1] SEQUENCE OF GeneralString   -- ["krbtgt", "<REALM>"]
#   }
# }
[kdc_princ_name]
realm     = EXP:0,GeneralString:${REALM}
principal = EXP:1,SEQUENCE:kdc_principal_name

[kdc_principal_name]
name_type   = EXP:0,INTEGER:2
name_string = EXP:1,SEQUENCE:kdc_name_components

[kdc_name_components]
part0 = GeneralString:krbtgt
part1 = GeneralString:${REALM}

[kdc_req_exts]
subjectAltName = @kdc_san

[kdc_cert_exts]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
basicConstraints       = critical,CA:FALSE
keyUsage               = critical,digitalSignature,keyEncipherment,nonRepudiation
# Match the Kerberos Authentication AD CS template EKU set exactly:
# clientAuth + Smart Card Logon are required by certutil -dcinfo NT_AUTH chain policy
extendedKeyUsage       = 1.3.6.1.5.2.3.5,serverAuth,clientAuth,1.3.6.1.4.1.311.20.2.2
subjectAltName         = @kdc_san
# Microsoft Certificate Template Name - required by certutil -dcinfo on Windows Server
1.3.6.1.4.1.311.20.2  = ASN1:BMPSTRING:KerberosAuthentication
# Microsoft Application Policies - mirrors EKU, checked by NT_AUTH chain policy
1.3.6.1.4.1.311.21.10 = ASN1:SEQUENCE:ms_app_policies

[ms_app_policies]
policy1 = SEQUENCE:ms_kdc_ap
policy2 = SEQUENCE:ms_sa_ap
policy3 = SEQUENCE:ms_ca_ap
policy4 = SEQUENCE:ms_scl_ap

[ms_kdc_ap]
policyId = OID:1.3.6.1.5.2.3.5

[ms_sa_ap]
policyId = OID:1.3.6.1.5.5.7.3.1

[ms_ca_ap]
policyId = OID:1.3.6.1.5.5.7.3.2

[ms_scl_ap]
policyId = OID:1.3.6.1.4.1.311.20.2.2
CNFEOF

openssl genrsa -out "$OUT/kdc/kdc.key" "$KEY_BITS" 2>/dev/null
openssl req -new \
  -key "$OUT/kdc/kdc.key" \
  -out "$OUT/kdc/kdc.csr" \
  -config "$OUT/kdc/kdc.cnf" 2>/dev/null
sign_cert "$OUT/kdc/kdc.csr" "$OUT/kdc/kdc.crt" "$OUT/kdc/kdc.cnf" "kdc_cert_exts"
export_pfx "$OUT/kdc/kdc.crt" "$OUT/kdc/kdc.key" "$OUT/kdc/kdc.pfx"
info "  KDC cert : $OUT/kdc/kdc.crt"
info "  KDC PFX  : $OUT/kdc/kdc.pfx  ← import into DC's Personal store (no password)"

# ── LDAPS Certificate ─────────────────────────────────────────────────────────
# NTDS service auto-selects a cert from the DC's Personal store that has:
#   EKU  : serverAuth
#   SAN  : DNS matching the DC hostname
info "Generating LDAPS certificate..."

cat > "$OUT/ldaps/ldaps.cnf" <<CNFEOF
[req]
distinguished_name = dn
req_extensions     = ldaps_req_exts
prompt             = no

[dn]
CN = ${DC_FQDN}
O  = ${REALM}

[ldaps_san]
DNS.1 = ${DC_FQDN}
DNS.2 = ${DC_NETBIOS}
DNS.3 = ${DOMAIN_LOWER}

[ldaps_req_exts]
subjectAltName = @ldaps_san

[ldaps_cert_exts]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
basicConstraints       = critical,CA:FALSE
keyUsage               = critical,digitalSignature,keyEncipherment
extendedKeyUsage       = serverAuth
subjectAltName         = @ldaps_san
CNFEOF

openssl genrsa -out "$OUT/ldaps/ldaps.key" "$KEY_BITS" 2>/dev/null
openssl req -new \
  -key "$OUT/ldaps/ldaps.key" \
  -out "$OUT/ldaps/ldaps.csr" \
  -config "$OUT/ldaps/ldaps.cnf" 2>/dev/null
sign_cert "$OUT/ldaps/ldaps.csr" "$OUT/ldaps/ldaps.crt" "$OUT/ldaps/ldaps.cnf" "ldaps_cert_exts"
export_pfx "$OUT/ldaps/ldaps.crt" "$OUT/ldaps/ldaps.key" "$OUT/ldaps/ldaps.pfx"
info "  LDAPS cert : $OUT/ldaps/ldaps.crt"
info "  LDAPS PFX  : $OUT/ldaps/ldaps.pfx  ← import into DC's Personal store (no password)"

# ── Smart Card / User Certificates ───────────────────────────────────────────
# EKU:
#   id-pkinit-KPClientAuth  1.3.6.1.5.2.3.4  (PKINIT client, RFC 4556)
#   id-ms-kp-sc-logon       1.3.6.1.4.1.311.20.2.2  (MS Smart Card Logon)
#   clientAuth              1.3.6.1.5.5.7.3.2
# SAN:
#   otherName: msUPN (1.3.6.1.4.1.311.20.2.3) = user@domain  ← used by AD logon
#   otherName: KRB5PrincipalName (1.3.6.1.5.2.2) = user@REALM  ← used by MIT/Heimdal
for USERNAME in $USERS; do
  info "Generating smart card cert for user: $USERNAME"
  UPN="${USERNAME}@${DOMAIN_LOWER}"
  USERDIR="$OUT/users/$USERNAME"
  mkdir -p "$USERDIR"

  cat > "$USERDIR/user.cnf" <<CNFEOF
[req]
distinguished_name = dn
req_extensions     = user_req_exts
prompt             = no

[dn]
CN = ${USERNAME}
O  = ${REALM}

[user_san]
# Microsoft UPN — primary identifier used by Windows smart card logon
otherName.1 = 1.3.6.1.4.1.311.20.2.3;UTF8:${UPN}
# KRB5PrincipalName — used by MIT/Heimdal/SSSD PKINIT
otherName.2 = 1.3.6.1.5.2.2;SEQUENCE:user_princ_name

# KRB5PrincipalName for user (name-type=1, NT-PRINCIPAL)
[user_princ_name]
realm     = EXP:0,GeneralString:${REALM}
principal = EXP:1,SEQUENCE:user_principal_name

[user_principal_name]
name_type   = EXP:0,INTEGER:1
name_string = EXP:1,SEQUENCE:user_name_components

[user_name_components]
part0 = GeneralString:${USERNAME}

[user_req_exts]
subjectAltName = @user_san

[user_cert_exts]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
basicConstraints       = critical,CA:FALSE
keyUsage               = critical,digitalSignature
extendedKeyUsage       = 1.3.6.1.5.2.3.4,1.3.6.1.4.1.311.20.2.2,clientAuth
subjectAltName         = @user_san
CNFEOF

  openssl genrsa -out "$USERDIR/user.key" "$KEY_BITS" 2>/dev/null
  openssl req -new \
    -key "$USERDIR/user.key" \
    -out "$USERDIR/user.csr" \
    -config "$USERDIR/user.cnf" 2>/dev/null
  sign_cert "$USERDIR/user.csr" "$USERDIR/user.crt" "$USERDIR/user.cnf" "user_cert_exts"
  export_pfx "$USERDIR/user.crt" "$USERDIR/user.key" "$USERDIR/user.pfx"
  info "  User cert : $USERDIR/user.crt  (UPN: $UPN)"
  info "  User PFX  : $USERDIR/user.pfx  ← (no password set)"
done

# ── Chain verification ────────────────────────────────────────────────────────
info ""
info "Verifying certificate chains..."
openssl verify -CAfile "$OUT/ca/ca.crt" "$OUT/kdc/kdc.crt"   2>/dev/null && info "  kdc.crt   OK"
openssl verify -CAfile "$OUT/ca/ca.crt" "$OUT/ldaps/ldaps.crt" 2>/dev/null && info "  ldaps.crt OK"
for USERNAME in $USERS; do
  openssl verify -CAfile "$OUT/ca/ca.crt" "$OUT/users/$USERNAME/user.crt" 2>/dev/null \
    && info "  ${USERNAME}/user.crt OK"
done

# ── Dump SANs for inspection ──────────────────────────────────────────────────
info ""
info "KDC SAN (check for KRB5PrincipalName):"
openssl x509 -in "$OUT/kdc/kdc.crt" -noout -text 2>/dev/null \
  | grep -A5 "Subject Alternative" || true

info ""
info "First user SAN (check for msUPN + KRB5PrincipalName):"
FIRST_USER=$(echo "$USERS" | awk '{print $1}')
openssl x509 -in "$OUT/users/$FIRST_USER/user.crt" -noout -text 2>/dev/null \
  | grep -A8 "Subject Alternative" || true

# ── Installation summary ──────────────────────────────────────────────────────
cat <<'INSTALL'

════════════════════════════════════════════════════════════════════
 AD Installation — run these on the Domain Controller (as Admin)
════════════════════════════════════════════════════════════════════

RECOMMENDED: use setup-kdc.ps1 — handles all steps automatically.
  Copy the output/ directory to the DC (e.g. C:\output\), then:

  Set-ExecutionPolicy Bypass -Scope Process
  .\setup-kdc.ps1 -AdcertPath C:\output

  A successful run ends with:
    1 KDC certificates for <DC>
    CertUtil: -DCInfo command completed successfully.

────────────────────────────────────────────────────────────────────
 Manual steps (reference)
────────────────────────────────────────────────────────────────────

1. TRUST THE ROOT CA
   Publish to AD Root CA store AND the NTAuth store.
   NTAuth is required for PKINIT and smart card logon.

   certutil -dspublish -f ca.der RootCA
   certutil -dspublish -f ca.der NTAuthCA
   certutil -addstore -f NTAuth ca.der
   certutil -addstore -f Root   ca.der

2. INSTALL CA CRL (required for PKINIT)
   Without a CRL the KDC hard-fails on revocation-unknown (Events 19/29).

   certutil -addstore CA ca.crl.der

3. INSTALL KDC CERT ON DC (enables PKINIT)
   Must use the legacy RSA SChannel CSP — CNG (Import-PfxCertificate)
   prevents certutil -dcinfo from enumerating the cert.

   certutil -importpfx -csp "Microsoft RSA SChannel Cryptographic Provider" kdc.pfx NoExport

   Grant NTDS read on the private key, then restart the KDC:
   (see README for the full PowerShell ACL snippet)

   Restart-Service KDC -Force
   certutil -dcinfo verify

4. INSTALL LDAPS CERT ON DC (optional — KDC cert covers serverAuth too)
   certutil -importpfx -csp "Microsoft RSA SChannel Cryptographic Provider" ldaps.pfx NoExport
   Restart-Service NTDS

   Verify: ldp.exe → Connect → host=<DC>, port=636, SSL=true

5. MAP USER SMART CARD CERTS
   Issuer+serial format (most interoperable):
     $serial = (openssl x509 -in alice/user.crt -noout -serial | cut -d= -f2)
     $issuer = (openssl x509 -in alice/user.crt -noout -issuer)
     Set-ADUser alice -Replace @{altSecurityIdentities =
       "X509:<I>${issuer}<SR>${serial}"}

6. PKINIT CLIENT CONFIG (sssd / MIT krb5)
   /etc/krb5.conf:
     [libdefaults]
       pkinit_anchors = FILE:/etc/ssl/certs/ad-ca.pem
     [appdefaults]
       pkinit_prompt_for_pin = false

════════════════════════════════════════════════════════════════════
INSTALL
