# Certification practice — RapidMX ACME CA (draft)

**Status: a draft written from what the software does, not an audited Certification Practice Statement.** It states what this
implementation issues, how it validates, and where it deliberately or knowingly falls short of the CA/Browser Forum S/MIME
Baseline Requirements (BR). An operator of a public instance must review and complete it (physical and personnel controls, key
ceremonies, incident response, governing law) with counsel before offering the service to others. The root of this CA is not in
any operating-system, browser or mail-client trust store; see "What this is not" below.

Structure loosely follows RFC 3647. Numbers marked *(config)* are defaults that the operator can change.

## 1. What this CA is

A single-purpose CA for **mailbox-validated S/MIME certificates**: a certificate binds a public key to one e-mail address whose
control the applicant has just demonstrated. There is no identity vetting of a person or an organization; the certificate says
nothing except "the holder of this key could read and answer mail sent to this address on the date of issuance".

### What this is not

- It is **not publicly trusted.** Nothing here can make a mail client that has not been told to trust the RapidMX root trust it.
- It is **not audited** (WebTrust/ETSI) and makes **no claim of BR compliance**. It asserts none of the CA/B Forum reserved
  certificate policy OIDs (2.23.140.1.5.x) because asserting one is a statement of compliance the CA cannot make.

## 2. Hierarchy and keys

- One **root** (offline in production) and one or more **issuing CAs** (`issuers.json`); exactly one is active. Issuing CAs are
  CA certificates with `pathLenConstraint 0`, `keyCertSign` + `cRLSign`, and an extended key usage of `emailProtection` only, so
  a compromised issuing CA cannot issue TLS or code-signing certificates that a relying party would accept for those purposes.
- Default algorithm ECDSA P-384 with SHA-384; RSA 4096 is available. Private keys are PKCS#8 files (optionally encrypted with
  PBES2/PBKDF2-SHA-256, 600,000 iterations, AES-256-CBC) or live in an OpenBao/Vault Transit key that never enters the process.
- A signature is verified against the signer's own public key before it is used, so a wrong or corrupted key file cannot
  produce a certificate nobody can verify.
- The **root key must be generated and kept offline**; `yarn ca:init` can write a root key to disk for development only.

## 3. Certificates issued

| Field | Value |
| --- | --- |
| Serial number | 20 random octets from the OS CSPRNG, top bit cleared (159 bits of entropy), unique in the database |
| Subject | `CN=<address>`; nothing is copied from the CSR's subject. Addresses over 64 octets get an empty subject and a critical SAN |
| Subject alternative name | one entry for the validated address: an `rfc822Name` (domain as lower-case A-labels, local part as given) when the local part is ASCII; an `SmtpUTF8Mailbox` otherName (RFC 8398, domain as U-labels) when it is not (RFC 8399) |
| Validity | `notBefore` = issuance − 60 min *(config)*, `notAfter` = issuance + 90 days *(config, per type)*, never past the issuing CA's own expiry; at most 825 days is ever signed |
| Key usage (critical) | signing: `digitalSignature`, `nonRepudiation` · encryption: `keyEncipherment` (RSA) or `keyAgreement` (EC) · both: the union |
| Extended key usage | `emailProtection` only |
| Basic constraints | `CA:FALSE` (critical) |
| Identifiers | subject key identifier (SHA-1 of the key), authority key identifier |
| Locations | CRL distribution point `/crl/<issuer>.crl`; AIA `caIssuers` `/ca/<issuer>.crt`, OCSP `/ocsp` |
| Subject keys | RSA 2048–8192 bits (modulus a multiple of 8 bits, odd, exponent odd and ≥ 65537, no prime factor < 752, not a perfect power, not a ROCA-fingerprint modulus); ECDSA P-256, P-384, P-521 with named curves and uncompressed points |

Which type is issued is chosen by the applicant's CSR (RFC 8823 §3.3): a KeyUsage request with only signing bits → signing; only
encryption bits → encryption; both, or none → both. An order's `profile` may constrain that (a profile is a ceiling).

The CA refuses a CSR whose key is the applicant's ACME account key, whose key was **revoked as compromised** (`keyCompromise`)
on any certificate this CA issued, whose signature (proof of possession) does not verify, or whose requested addresses differ
from the order's.

## 4. Validation of the mailbox

1. The applicant (an ACME account) orders a certificate for one address. The domain must be able to receive mail (MX or address
   record; a null MX per RFC 7505 is refused) and its CAA `issuemail` policy (RFC 9495; climbing the DNS tree per RFC 8659) must
   permit this CA. A failed DNS lookup refuses the order rather than guessing.
2. After the applicant fetches the authorization, the CA sends **one** e-mail to the address from `acme.mail.from`, DKIM-signed
   for its own domain, with `Subject: ACME: <token-part1>` (256 random bits) and `Auto-Submitted: auto-generated; type=acme`.
3. The applicant replies to the address in `Reply-To` with a body carrying `SHA-256(token-part1 ‖ token-part2 ‖ "." ‖
   thumbprint of the ACME account key)`, where token-part2 (256 random bits) was delivered over HTTPS.
4. The CA accepts the reply only if it verifies the reply's **DKIM signature itself** with `d=` equal to the domain of the From
   address (RFC 8823 §3.2), the From address is the address being validated, and the digest is right (constant-time compare). A
   wrong digest from a properly signed sender invalidates the authorization; anything else is ignored silently and never
   answered.
5. The authorization becomes valid once both the verified reply and the client's "ready" request exist. It **expires after 7
   days** *(config)* and is **never reused**: every certificate, including a renewal, re-proves control of the mailbox.

Because a verification e-mail goes to an address a stranger names, the CA limits how many it sends: 3/hour per account and address, 12/hour and 40/day per address, 600/hour per domain, 60/hour per
account and 120/hour per source IP *(config)*, and never sends mail in reply to inbound mail. The budgets shared by everybody are
deliberately much larger than the one an individual account can spend alone: otherwise a stranger could use up an address's (or a
large provider's) budget and keep its owner from ever receiving a verification e-mail. The tokens are refunded if the mail does not
go out, and a verification e-mail is only sent once the client has fetched the authorization.

## 5. Revocation and status

- **Who may revoke:** the ACME account that ordered the certificate, or anyone who holds the certificate's private key (the
  request is then signed with that key). The reasons accepted are unspecified, `keyCompromise`, `affiliationChanged`,
  `superseded`, `cessationOfOperation`.
- **Operator revocation:** the operator can revoke on the CA's own initiative through the operator API (`/admin`, a bearer secret,
  reachable from the internal network only): one certificate, or every valid certificate of an address, an account, a public key
  (the response to a compromised key) or a list of serials; the reasons are the above plus `privilegeWithdrawn`. Each revocation
  records that it was the operator, the operator's label and a free-text note, is logged, and republishes the CRL at once. An
  operator can also suspend an account (its open orders and authorizations are cancelled, nothing works for it until reinstated).
- **CRL:** one full CRL per issuing CA, regenerated at once on every revocation and at least every 12 hours *(config)*, valid for
  7 days *(config, at most 10)*; it lists a revoked certificate until it would have expired.
- **OCSP:** responses signed by the issuing CA key, valid for 24 hours *(config)*; a serial the CA never issued is answered
  `unknown`, never `good`.
- **ARI (RFC 9773):** clients are told to renew two thirds of the way through a certificate's life; a revoked certificate's
  window opens immediately.

## 6. Records

Every issued certificate is kept indefinitely (serial, issuer, account, address, type, validity, revocation, key hash). Orders
and authorizations are deleted 30 days after they expire. Logs record issuances, revocations and validation failures without
message contents. The database is the record of what the CA has signed and must be backed up.

## 7. Abuse controls

Let's Encrypt-style token-bucket rate limits per IP address (IPv6 by /48), per account, per address and per domain (see
`/rate-limits` on a running instance), an account key that is never reused as a subject key, and the limits on verification
e-mails in §4. Limits can be raised or lowered for a specific subject by configuration.

## 8. Known gaps against the Baseline Requirements

This list is what the authors know of; it is not a compliance assessment.

- No audit, no CP/CPS approval process, no policy OIDs (§1).
- No hardware-protected root, key ceremony, dual control or personnel controls — operator responsibilities outside the software.
- **CAA is looked up without DNSSEC validation** (Node's resolver cannot validate), and validation is done from one network
  perspective (no multi-perspective corroboration).
- Mailbox control is proven by DKIM-authenticated reply only; there is no second validation method (e.g. a random value the
  mailbox owner types in). A domain owner whose mail provider signs mail on behalf of a user without checking who the user is
  therefore controls the mailboxes' validation.
- The OCSP responder signs with the issuing CA key rather than a delegated responder certificate.
- Weak-key screening is the checks in §3 (including a ROCA fingerprint); there is no Debian weak-key blocklist.
- Certificate Transparency logging is not performed (not required for S/MIME).
