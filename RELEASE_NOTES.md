# Release Notes

## Unreleased

### Added

- **The RapidMX ACME certificate authority: a standalone service that issues S/MIME certificates for e-mail addresses.** Built because the public CA the server's enrollment defaulted to (`acme.castle.cloud`) never finished a request (stuck in "verification" for more than 24 hours on the live test server). It speaks ACME (RFC 8555) with the RFC 8823 `email-reply-00` challenge, so `@rapidmx/restapi`'s `Rfc8823AcmeSigningCertificateEnrollment` can use it by changing `mail:pki:rfc8823:directory_url` to `https://acme.rapidmx.io/directory`; it is also tested against the independent `acme-client` package.
  - **Signing, encryption or combined certificates**, chosen by the key usage in the CSR (RFC 8823 section 3.3) and optionally an order `profile`. 90 days by default, `emailProtection` only, `CN=<address>` with an `rfc822Name` SAN; nothing but the public key is taken from the CSR.
  - **Mailbox validation** by a DKIM-signed reply to a DKIM-signed challenge e-mail. The CA verifies the reply's DKIM signature itself (`d=` must be the From domain), the sender and the digest, sends one e-mail per authorization, never reuses an authorization, checks CAA `issuemail` and that the domain can receive mail, and never answers inbound mail.
  - **Let's Encrypt-style rate limits** (token buckets in Redis, in memory without it) with `Retry-After` and `rateLimited` problem documents that link to `/rate-limits`, renewals exempt via `replaces`, plus limits on the verification e-mails one address, domain or account can cause, so the CA cannot be used to mail-bomb someone.
  - **Endpoints for validating what it issued:** issuer certificates (DER for AIA, PEM), the roots to trust, chains and issuer public keys as JWKs (`/ca`, `/ca/*`), a CRL per issuer, an OCSP responder, certificate look-up by serial, and ARI renewal information.
  - **Key custody:** issuing CA keys in a file (optionally passphrase-encrypted) or in an OpenBao/Vault Transit key; `yarn ca:init` creates the hierarchy (root belongs offline). Not verified against a real OpenBao.
  - **Mail:** outbound through any SMTP relay with DKIM; replies arrive on the CA's own SMTP listener or through an HTTP ingest route behind a mail bridge.
  - **Trust model:** the root is not in any OS, browser or mail-client trust store and the CA is not audited; certificates verify only where the RapidMX root (`/ca/roots.pem`) is trusted. See `docs/CPS.md`.
  - Not implemented yet: external account binding, internationalized (SMTPUTF8) addresses, Ed25519 subject keys, DNSSEC validation of CAA, an operator revocation API. Not verified against a real Redis, a real inbound MTA or a real mail client trust import.
