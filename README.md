# RapidMX ACME CA

A certificate authority for **S/MIME certificates**, spoken to over **ACME** (RFC 8555). A mailbox owner proves control of an
e-mail address by replying to a verification e-mail (the RFC 8823 `email-reply-00` challenge) and receives a **signing**, an
**encryption** or a combined certificate. Renewal is the same flow again, guided by ACME Renewal Information (RFC 9773).

It is a standalone [RapidREST](https://github.com/rapidrest) service (planned host: `acme.rapidmx.io`), independent of the RapidMX
mail server. `@rapidmx/restapi`'s `Rfc8823AcmeSigningCertificateEnrollment` is the client it was built to serve, but any ACME
client that speaks RFC 8823 works (it is tested against the independent [`acme-client`](https://www.npmjs.com/package/acme-client)).

> **Trust model — read this first.** This is a CA run by RapidMX. Its root is **not** in any operating-system, browser or
> mail-client trust store, and becoming a publicly trusted S/MIME issuer takes a CA/Browser Forum S/MIME Baseline Requirements
> audit and the root programs' application processes — a compliance project, not a code one. Until then certificates verify
> **only where the RapidMX root is trusted**: RapidMX clients fetch it from `GET /ca/roots.pem` (and can pin its fingerprint);
> other mail clients need it imported. The code follows the Baseline Requirements' mailbox-validated profile where practical, so a
> later audit is a paperwork gap rather than a rewrite, but it asserts no CA/B Forum policy OIDs and nothing here is an audit
> statement. See [docs/CPS.md](docs/CPS.md).

## What it does

| | |
| --- | --- |
| **Protocol** | RFC 8555 (directory, nonces, accounts, key rollover, orders, authorizations, finalize, download, revocation), RFC 8823 (`email` identifier, `email-reply-00`, signing/encryption/dual selection from the CSR's key usage), RFC 9773 (ARI and `replaces`), `profile` in new-order (draft-aaron-acme-profiles) |
| **Addresses** | ASCII and internationalized (RFC 6531): a non-ASCII local part gets an `SmtpUTF8Mailbox` (RFC 8398), an IDN domain is handled as A-labels |
| **Certificates** | ECDSA P-384 issuing CA by default; subscriber keys RSA 2048–8192 or ECDSA P-256/384/521; `emailProtection` only; `CN=<address>` + `rfc822Name` SAN; 90 days (per type, configurable); nothing copied from the CSR but the public key |
| **Validation** | The CA mails `ACME: <token-part1>` (DKIM-signed); the applicant's DKIM-signed reply carries `SHA-256(token-part1‖token-part2‖"."‖account-key-thumbprint)`; the CA verifies DKIM itself (`d=` = the From domain), the sender, and the digest. CAA `issuemail` (RFC 9495) is honoured, and DNSSEC-validated in-process (a bogus or unprovable answer refuses the order) |
| **Rate limits** | Let's Encrypt-style token buckets (GCRA in Redis, in memory as a fallback) with `Retry-After` and `rateLimited` problems that link to `/rate-limits`; plus limits that protect the *recipients* of verification e-mails |
| **Trust endpoints** | Issuer certificates, trust anchors, chains, JWKs, CRL, OCSP, certificate look-up by serial — see below |
| **Keys** | Local (optionally passphrase-encrypted) PKCS#8 or OpenBao/Vault Transit (the key never enters the process); the root belongs offline |
| **Reminders** | The account's contacts are e-mailed 1 week, 3 days and 1 day before a certificate expires, the day it does, and 1 day and 1 week after if it was not renewed (none once renewed or revoked); one e-mail per contact lists everything due |
| **Mail** | Outbound through any SMTP relay with DKIM; inbound on the CA's own SMTP listener or through an HTTP ingest route behind Postfix/SES |
| **Stack** | RapidREST (uWebSockets), MongoDB, Redis, Node ≥ 24 |

### Endpoints

ACME clients are configured with one URL: **`https://acme.rapidmx.io/directory`**.

| Path | What |
| --- | --- |
| `GET /directory`, `HEAD\|GET /acme/new-nonce` | ACME directory (with `meta.profiles`, terms, CAA identities) and nonces |
| `POST /acme/new-acct`, `/acme/acct/:id[/orders]`, `/acme/key-change` | accounts |
| `POST /acme/new-order`, `/acme/order/:id[/finalize]`, `/acme/authz/:id`, `/acme/chall/:authz/:id`, `/acme/cert/:id` | orders, `email-reply-00`, certificate download |
| `POST /acme/revoke-cert`, `GET /acme/renewal-info/:certId` | revocation (by account or by certificate key), ARI |
| `GET /ca` | JSON: every issuer (subject, validity, fingerprints, PEM, **JWK**) and the roots to trust |
| `GET /ca/<id>.crt\|.cer\|.der\|.pem`, `/ca/roots.pem`, `/ca/chain.pem`, `/ca/<id>/chain.pem`, `/ca/jwks.json` | issuer certificate (DER for AIA), trust anchors, chains, public keys |
| `GET /crl/<id>.crl`, `GET\|POST /ocsp` | revocation status |
| `GET /certs/<serial>` | an issued certificate (PEM chain, or JSON with `Accept: application/json`) and its status |
| `GET /terms`, `GET /rate-limits`, `GET /status` | terms of service, the limits actually enforced, service status |
| `GET /metrics` | Prometheus (only with `acme.metrics_secret`, bearer) |
| `POST /internal/mail/inbound` | reply e-mails from a mail bridge (only with `acme.mail.inbound.http_secret`, bearer) |
| `/admin/certificates`, `/admin/revocations`, `/admin/accounts/:id` | operator API: search what was issued, revoke one certificate or a selection (address, account, key, serials), suspend accounts (only with `acme.admin_secret`, bearer, internal network only) |

## Quick start (development)

```bash
yarn install
yarn ca:init --dir ./data/ca --base-url http://localhost:3000     # a throw-away root + issuing CA (data/ is git-ignored)
acme__ca__manifest=./data/ca/issuers.json yarn dev                 # (bash; on Windows set the variable first)
yarn test                                                          # unit + end-to-end tests; needs no external services
```

`yarn dev` (`rapidrest dev`) starts an in-memory MongoDB and runs with `NODE_ENV=development`, where the challenge mails are kept
in memory instead of sent, nonces and rate limits live in process memory (no Redis needed), and the config guard is relaxed. To see the whole flow
against real mail servers use the Docker Compose stack in [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) (mail sink included).

The **production** process refuses to start without an `https` `acme.external_url`, real `acme.mail.from`/`reply_to`
addresses, an SMTP relay and a DKIM key, and it exits if the issuer manifest cannot be loaded: a CA must never run half
configured. Configuration keys are listed in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#configuration-nconf-env-acme__section__key).

## Using it from RapidMX

Point the server's enrollment at this CA (`mail:pki:rfc8823:directory_url`, env `mail__pki__rfc8823__directory_url`) and
make the RapidMX web client trust the root from `GET /ca/roots.pem`. The client in `@rapidmx/restapi` performs exactly the
sequence this CA is tested with (`createOrder` → `getAuthorizations` → the reply e-mail → `completeChallenge` →
`finalizeOrder` → `getCertificate`). For an *encryption* or combined certificate its CSR must carry a KeyUsage request
(RFC 8823 §3.3), or it can send `profile`; without either it gets a combined certificate.

## Operating it

- **Root key offline.** `yarn ca:init --root-only` on an offline machine, then `--issuer-only --root-cert … --root-key …`
  for the issuing CA whose key/cert (and the root *certificate*) go to the server. Rotation is a new issuer in
  `issuers.json` and flipping `active`.
- **MongoDB is the record of everything issued** (serials, revocations, CRL numbers). Back it up.
- **Redis** makes nonces and rate limits shared across replicas; without it a single replica works and says so at startup.
- Everything else — DNS records, DKIM, TLS for the SMTP listener, Helm values, hardening — is in
  [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Project layout

```
src/
  server.ts, config.ts          entry point, defaults (env: acme__section__key)
  routes/                       one class per endpoint group (thin: they call the services)
  services/                     AcmeContext (wiring) and the protocol logic: accounts, orders, challenges, certificates, CRL, OCSP
  models/                       MongoDB collections: account, order, authorization, certificate, CRL
  jobs/                         housekeeping (expiry, CRL refresh), the built-in SMTP receiver
  lib/acme/                     JWS, nonces, rate limits, DNS/CAA, identifiers, stores  ┐ pure libraries, not scanned
  lib/pki/                      signers, issuers, certificates, CSR policy, CRL, OCSP, ARI ├ by RapidREST's class loader
  lib/mail/                     challenge mailer (SMTP + DKIM), DKIM-verifying reply parser, SMTP receiver ┘
scripts/ca-init.ts              creates the CA hierarchy and issuers.json
docs/                           ARCHITECTURE.md, CPS.md, DEPLOYMENT.md
test/                           unit tests (lib/) and end-to-end tests over real HTTP (acme/)
```

## License

MPL-2.0. See [LICENSE](LICENSE).
