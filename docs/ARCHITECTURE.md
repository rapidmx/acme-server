# RapidMX ACME CA – architecture

`acme` is a standalone RapidREST service (planned host: `acme.rapidmx.io`) that acts as a certificate authority for
**S/MIME certificates**. A mailbox owner (in practice the RapidMX web client through `@rapidmx/restapi`'s
`Rfc8823AcmeSigningCertificateEnrollment`, or any RFC 8555/8823 client) proves control of an e-mail address and receives
a **signing**, **encryption** or **signing + encryption** certificate. Renewal is the same flow again (with ARI hints).

It implements:

| Spec | What |
| --- | --- |
| RFC 8555 | ACME core: directory, nonces, accounts, key rollover, orders, authorizations, finalize, certificate download, revocation |
| RFC 8823 | The `email` identifier and the `email-reply-00` challenge, S/MIME key-usage selection (§3.3) |
| RFC 9773 | ACME Renewal Information (ARI): `renewalInfo` + the `replaces` order field |
| draft-aaron-acme-profiles | `profile` in new-order and `meta.profiles` in the directory |
| RFC 5280 / 6960 / 5019 | X.509 certificates, CRLs, OCSP responder |
| Let's Encrypt/Boulder behaviour | `Retry-After`, `urn:ietf:params:acme:error:rateLimited` with a `Link: rel="help"`, per-IP/per-account/per-identifier token-bucket limits, `Replay-Nonce` on every response, `Link: <directory>;rel="index"` |

## Trust model – read this first

This is a **CA operated by RapidMX**. Its root is **not** in any operating-system, browser or mail-client trust store, and
becoming a publicly trusted S/MIME issuer means passing a CA/Browser Forum S/MIME Baseline Requirements audit and the root
program application processes – a business/compliance project, not a code one. Until then:

* Certificates verify **only where the RapidMX root is trusted**: RapidMX clients fetch it from `GET /ca/roots.pem` (and
  can pin its SHA-256 fingerprint); other mail clients need it imported manually or by policy.
* The code follows the Baseline Requirements' *mailbox-validated* profile where it is practical (random 159-bit serials,
  `emailProtection`-only EKU, SAN `rfc822Name`, CRL + OCSP, CAA `issuemail` checks, RSA ≥ 2048 / P-256+ keys, no CSR-supplied
  subject data) so a later audit is a paperwork gap and not a rewrite – but it does **not** assert the CA/B Forum policy
  OIDs, and nothing here is an audit statement.

## Runtime components

```
                       ┌──────────────────────── acme (RapidREST, uWebSockets) ─────────────────────────┐
 ACME client  ──HTTPS──▶  routes/  Directory Nonce Account Order Authz Challenge Cert Revoke KeyChange ARI │
 (RapidMX server)      │            Ca (trust endpoints) Crl Ocsp Terms InboundMail(HTTP ingest)           │
                       │                                                                                  │
                       │  lib/acme   Jws · Nonces · Problems · RateLimits · Identifiers · Dns · Urls       │
                       │  lib/pki    Signer · Issuer/Registry · CertificateBuilder · CsrValidator · Crl · Ocsp │
                       │  lib/mail   ChallengeMailer(SMTP+DKIM) · parseInboundReply(DKIM verify) · SmtpReceiver │
                       │  jobs       Expiry/Cleanup · CrlRefresh · InboundSmtp(service)                    │
                       └───────┬────────────────────────────────┬───────────────────────────────────────┘
                               │ MongoDB (state, certs, CRLs)    │ Redis (nonces, rate-limit buckets)
        challenge e-mail  ◀────┘ SMTP relay (DKIM-signed)        └ in-memory fallback when no Redis (single node/tests)
        reply e-mail ────▶ SMTP :25 (built-in receiver)  or  POST /internal/mail/inbound (Postfix/SES bridge)
```

Everything is one process; scale out by running replicas against the same MongoDB/Redis. State that must be atomic
(nonce consumption, challenge transitions, serial uniqueness, rate-limit spending) uses atomic Redis/Mongo operations, never
read-modify-write in the process.

## Configuration (nconf, env `acme__section__key`)

```
acme.external_url              https://acme.rapidmx.io      base of every URL handed to clients (no trailing slash)
acme.terms_of_service_url      <external_url>/terms
acme.website                   https://rapidmx.io
acme.caa_identities            ["rapidmx.io"]               what a domain's CAA `issuemail` must name to allow us
acme.order_expiry_hours        168
acme.authorization_expiry_hours 168
acme.nonce_ttl_seconds         3600
acme.ca.manifest               /var/lib/acme/ca/issuers.json  the issuing CA(s), see "Issuers"
acme.ca.backdate_minutes       60
acme.ca.profiles.<type>.validity_days   90   type = signing | encryption | signing-encryption
acme.mail.from                 acme-challenge@acme.rapidmx.io   RFC 8823 challenge `from` and message From
acme.mail.reply_to             acme-response@acme.rapidmx.io    where the client must send its reply
acme.mail.smtp.url             smtp://relay:587             outbound relay (nodemailer URL) – or host/port/secure/auth
acme.mail.dkim.domain|selector|private_key_path             DKIM for the challenge mail (RFC 8823: MUST be signed)
acme.mail.inbound.smtp.enabled|host|port|max_size_bytes|tls_key_path|tls_cert_path
acme.mail.inbound.http_secret  bearer secret for POST /internal/mail/inbound (unset = route answers 404)
acme.mail.dkim_alignment       strict (d= equals From domain, RFC 8823) | relaxed (d= may be a parent of it)
acme.rate_limits.enabled       true
acme.rate_limits.overrides     [{ "limit": "<limit name>", "subject": "<account uid | address | domain | normalized ip>", "count": n, "period_seconds": n, "burst": n }]
acme.max_identifiers           1
acme.metrics_secret            bearer secret of GET /metrics (unset = 404)
acme.admin_secret              bearer secret of the operator API /admin (unset = 404; >= 32 characters outside development)
acme.dns.servers               ["9.9.9.9"]                  resolvers for MX/CAA look-ups (default: the system's); they need only relay DNSSEC records
acme.dns.dnssec                "validate"                   CAA is DNSSEC-validated in-process against the root anchors; "off" is refused outside development
```

Outside `dev`/`development`/`test` the server refuses to start with the default secrets, without `external_url`, or
without a usable issuer manifest.

## Issuers (CA hierarchy and key custody)

`issuers.json` (produced by `yarn ca:init`, hand-editable) lists the issuing CAs; relative paths resolve against the
manifest's directory:

```json
[
  {
    "id": "smime-r1",
    "name": "RapidMX S/MIME CA R1",
    "certificate": "smime-r1/cert.pem",
    "chain": ["root-r1/cert.pem"],
    "key": { "type": "file", "path": "smime-r1/key.pem", "passphrase_env": "ACME_CA_KEY_PASSPHRASE" },
    "active": true
  }
]
```

* `key.type` `file`: PKCS#8 PEM (optionally encrypted). `openbao-transit`: signing is delegated to an OpenBao/Vault Transit
  key (`POST /v1/<mount>/sign/<key_name>/<hash>` with `marshaling_algorithm=asn1`) so the private key never enters the
  process. The signer contract is `sign(tbsBytes) → DER signature` in both cases; everything (certificates, CRLs, OCSP) is
  assembled from ASN.1 structures and signed through that one seam.
* Exactly one issuer is `active` and signs new certificates; older ones stay listed so their CRLs/OCSP keep working and
  their certificates keep being served. Rotation = add a new issuer, flip `active`, restart.
* The **root key belongs offline.** `ca:init` can emit a root only for development; in production create the root on an
  offline machine (`ca:init --root-only`), then create issuers with `ca:init --root-cert … --root-key … --issuer-only` and
  copy just the issuer cert/key + root **certificate** to the server.

## Certificate profile

| Field | Value |
| --- | --- |
| Serial | 20 random bytes, top bit cleared (159 bits), unique index |
| Subject | `CN=<email>` only – nothing from the CSR is copied except the public key |
| SAN | the order's email identifier (exactly the CSR's requested set): an `rfc822Name` with the domain as A-labels for an ASCII local part, an `SmtpUTF8Mailbox` otherName (RFC 8398, domain as U-labels, NFC) for a non-ASCII one (RFC 8399) |
| Validity | `notBefore = now − backdate`, `notAfter` = `now + validity_days(type)` (default 90) |
| KeyUsage (critical) | signing: `digitalSignature`, `nonRepudiation`; encryption: RSA→`keyEncipherment`, EC→`keyAgreement`; both: union (RSA: `digitalSignature`,`nonRepudiation`,`keyEncipherment`; EC: `digitalSignature`,`nonRepudiation`,`keyAgreement`) |
| EKU | `emailProtection` only |
| BasicConstraints | `CA:FALSE` (critical) |
| SKI / AKI | SHA-1 of the subject public key / issuer key id |
| CRLDP / AIA | `/crl/<issuerId>.crl`; `caIssuers` `/ca/<issuerId>.crt`, `ocsp` `/ocsp` |
| Signature | issuer key's algorithm (ECDSA P-384 + SHA-384 by default) |

**Which type?** RFC 8823 §3.3 – the CSR's KeyUsage extension request decides: only `digitalSignature`/`nonRepudiation` →
`signing`; only `keyEncipherment`/`keyAgreement` → `encryption`; both, or no KeyUsage request → `signing-encryption`. If the
order carries a `profile` (`signing`, `encryption`, `signing-encryption`) the CSR's type must not contradict it (a CSR
with no KeyUsage adopts the profile's type).

**Accepted subject keys:** RSA 2048–8192 (modulus a multiple of 8 bits, odd, exponent odd ≥ 65537, no prime factor
< 752), ECDSA P-256/P-384/P-521. The account key and any key previously revoked for `keyCompromise` are refused
(`badPublicKey`). One identifier per order (`acme.max_identifiers`, default 1).

**Internationalized addresses (RFC 6531 / 8398 / 8399).** An `email` identifier may have a non-ASCII local part and a domain in U-labels
or A-labels. The CA canonicalizes it (`lib/pki/mailbox.ts`): local part NFC and otherwise as given, domain as lower-case A-labels
(`local@xn--…`); that is what the order, the authorization, rate limits, DNS/CAA look-ups and the SMTP envelope use. Refused, not
rewritten: a non-NFC local part, control/format (bidi, zero-width)/separator/private-use/unassigned characters, IDNA compatibility
mappings (full-width letters), Punycode that does not decode, local parts over 64 octets. The verification e-mail is addressed in
UTF-8 (nodemailer uses SMTPUTF8 with a relay that offers it), and the applicant's reply may spell the From domain either way: the
sender and the DKIM `d=` are compared as A-labels. In a CSR the address is an `rfc822Name` (ASCII local part) or an
`SmtpUTF8Mailbox` otherName.

## ACME resources and state machines

Collections: `acme_account`, `acme_order`, `acme_authorization`, `acme_certificate`, `acme_crl`. IDs are random,
opaque and URL-safe. A random-id URL is the only handle (no enumeration).

* **order** `pending → ready → valid | invalid`. Issuance is synchronous inside *finalize*: the order passes through `processing`
  only for the instant of the signature (it is claimed with one atomic update, so two finalize calls can never both issue) and the
  client sees `valid`. An order stuck in `processing` because the process died is recovered by the maintenance job after 10
  minutes: `valid` if its certificate was already stored, otherwise back to `ready`.
  Expires after `order_expiry_hours`; `expires` swept to `invalid` by the cleanup job.
* **authorization** (one per identifier, never reused between orders – every issuance re-proves mailbox control)
  `pending → valid | invalid | expired | deactivated`; carries exactly one challenge.
* **challenge** `email-reply-00`: `pending → processing → valid | invalid`.

`email-reply-00` sequence (RFC 8823 §3, implemented as):

1. **new-order** creates the order + authorization + challenge (`token` = *token-part2*, 256 random bits, base64url;
   `from` = `acme.mail.from`). *token-part1* (256 random bits) is generated and stored, not disclosed.
2. The first **POST-as-GET of the authorization** (that is when RFC 8823 says the CA sends the mail) sends the challenge
   e-mail exactly once (`sentAt` is claimed with an atomic update): `To` the identifier, `From: acme.mail.from`,
   `Reply-To: acme.mail.reply_to`, `Subject: ACME: <token-part1>`, `Auto-Submitted: auto-generated; type=acme`, DKIM-signed.
3. The client answers with a DKIM-signed reply e-mail whose body carries `-----BEGIN ACME RESPONSE-----`
   `base64url(SHA-256(token-part1 ‖ token-part2 ‖ "." ‖ base64url(JWK thumbprint of the account key)))`
   `-----END ACME RESPONSE-----`, and POSTs `{}` to the challenge URL.
4. The reply arrives by SMTP or the HTTP ingest route. The inbound handler locates the challenge by the token in the
   Subject, requires **DKIM pass with `d=` = the From domain** (`strict`), `From` = the identifier, and a constant-time
   digest match. It records the proof (`responseVerifiedAt`); a wrong digest, or a reply that is not DKIM-aligned to
   the identifier, does not validate anything (a wrong digest from an aligned sender invalidates the challenge).
5. The challenge becomes `valid` once **both** the proof and the client's POST are present, whichever comes second
   (atomic conditional update), and the authorization/order advance (`valid` / `ready`).

**finalize** (`POST /acme/order/:id/finalize`, order `ready`): parse and validate the CSR (`CsrValidator`), spend the
issuance rate limits (unless the order `replaces` a certificate of the same account for the same address – renewals
are exempt as in Let's Encrypt), re-check CAA, sign, store the certificate, mark the order `valid` and answer with it.
Downloaded as `application/pem-certificate-chain` (leaf + issuing CA chain excluding the root).

## Rate limits (Let's Encrypt style, GCRA token buckets)

Every limit is `burst` tokens refilled at `count / period`; a rejected request carries `Retry-After` (seconds) and
`Link: <acme.website>/docs/rate-limits;rel="help"` (`urn:ietf:params:acme:error:rateLimited`, HTTP 429). Defaults:

| Limit | Key | Default |
| --- | --- | --- |
| Endpoint request rates (nonce 20/s, new-account 5/s, new-order 100/s, revoke 10/s, everything else 250/s, directory 40/s) | ip | burst = 2× rate (nonce 10, new-account 15) |
| New accounts | ip (IPv6 → /48) | 10 / 3 h |
| New orders | account | 300 / 3 h |
| Pending authorizations | account | 300 (counted in the DB) |
| Consecutive authorization failures | account + email | 5 / h (refunded on success) |
| Certificates per e-mail address & type | email | 5 / 7 d (renewals exempt) |
| Certificates per e-mail domain | domain | 200 / 7 d (renewals exempt) |
| **Challenge e-mails per address, per account** | account + email | 3 / h (what one stranger can cause alone) |
| Challenge e-mails per recipient address | email | 12 / h and 40 / day (all accounts together) |
| Challenge e-mails per recipient domain | domain | 600 / h |
| Challenge e-mails per account | account | 60 / h |
| Challenge e-mails per source IP | ip | 120 / h |
| Finalize requests | account | 20 / h (burst 10): a finalize does signature checks and a signature |

The last three protect third parties: this CA sends mail to addresses a stranger names, so it must not become a
mail-bomb amplifier. `overrides` (config) raise or lower a specific key.

## Public trust endpoints (unauthenticated, cacheable)

| Path | Content |
| --- | --- |
| `GET /ca` | JSON list of issuers: id, name, role, subject, serial, validity, SHA-256 fingerprints (cert + SPKI), PEM, **JWK** of the public key, and its `crl`/`ocsp`/`certificate` URLs |
| `GET /ca/<id>.crt` `.der` / `.pem` | the issuer certificate (`application/pkix-cert` / `application/x-pem-file`) – the AIA `caIssuers` target |
| `GET /ca/roots.pem` | every root certificate – the trust anchor bundle |
| `GET /ca/chain.pem`, `GET /ca/<id>/chain.pem` | issuing CA(s) + root |
| `GET /ca/jwks.json` | JWK Set of every issuer's public key |
| `GET /crl/<id>.crl` | latest CRL (`application/pkix-crl`) |
| `GET /ocsp/<b64>` / `POST /ocsp` | OCSP responder (RFC 6960 / 5019) |
| `GET /certs/<serial>` | an issued certificate by serial (PEM), with revocation status headers |
| `GET /acme/renewal-info/<certId>` | ARI |
| `GET /terms` | terms of service (the URL in the directory `meta`) |

## Module contracts

*These are the signatures the libraries were specified against before they were written. The source and its JSDoc are the
authority: the PKI library added members and options (e.g. `Issuer` takes an options object and exposes `keyHash()`/`nameHash()`,
`OpenBaoTransitSigner` pins the key version it read, the mail library exports `composeChallengeMessage()`), and where a limit
or a check was tightened it is described in the JSDoc and in `docs/CPS.md`.*

### `src/lib/pki` – pure library, no RapidREST imports

```ts
export type CertificateType = "signing" | "encryption" | "signing-encryption";

// Signer.ts – the only place a CA private key is touched
export type SignatureAlgorithm =
    "ecdsa-with-SHA256" | "ecdsa-with-SHA384" | "ecdsa-with-SHA512" |
    "sha256WithRSAEncryption" | "sha384WithRSAEncryption" | "sha512WithRSAEncryption";
export interface CaSigner {
    readonly algorithm: SignatureAlgorithm;
    readonly spki: Uint8Array;                       // DER SubjectPublicKeyInfo of the signing key
    sign(data: Uint8Array): Promise<Uint8Array>;     // X.509-style signature (ECDSA in DER SEQUENCE form)
}
export class LocalKeySigner implements CaSigner { static fromPem(pem: string, passphrase?: string): LocalKeySigner; static generate(kind: "ecdsa-p256" | "ecdsa-p384" | "rsa-3072" | "rsa-4096"): Promise<{ signer: LocalKeySigner; privateKeyPem: (passphrase?: string) => string }>; }
export class OpenBaoTransitSigner implements CaSigner { constructor(o: { url: string; mount?: string; keyName: string; token: string | (() => Promise<string>); hash?: "sha2-256" | "sha2-384" | "sha2-512"; httpPost?: ... }); static create(o): Promise<OpenBaoTransitSigner> /* reads the public key */ }

// Issuer.ts
export interface IssuerInfo { id: string; name: string; role: "root" | "intermediate"; subject: string; serialNumber: string; notBefore: string; notAfter: string; sha256Fingerprint: string; spkiSha256: string; pem: string; jwk: JsonWebKey; }
export class Issuer { readonly id: string; readonly name: string; readonly certificate: x509.X509Certificate; readonly chain: x509.X509Certificate[]; /* CAs above `certificate`, nearest first, root last */ readonly signer: CaSigner; readonly active: boolean; readonly keyId: Uint8Array; /* SKI of certificate */ info(): IssuerInfo; }
export class IssuerRegistry {
    static fromManifest(manifestPath: string, opts?: { env?: NodeJS.ProcessEnv; fetch?: typeof fetch }): Promise<IssuerRegistry>;
    static fromIssuers(issuers: Issuer[]): IssuerRegistry;
    all(): Issuer[]; get(id: string): Issuer | undefined; active(): Issuer;   // active() throws if there is not exactly one
    roots(): x509.X509Certificate[];                                          // de-duplicated chain tops
    findByIssuerKeyHash(algorithm: "sha1", issuerKeyHash: Uint8Array): Issuer | undefined;
}

// CertificateBuilder.ts
export interface LeafCertificateRequest { spki: Uint8Array; email: string; type: CertificateType; notBefore: Date; notAfter: Date; serial?: Uint8Array; }
export interface IssuedCertificate { der: Uint8Array; pem: string; serialHex: string; /* lower-case hex, no leading 00 */ notBefore: Date; notAfter: Date; sha256Fingerprint: string; }
export interface IssuerUrls { crl: string; caIssuers: string; ocsp: string; }   // absolute URLs written into the certificate
export function issueLeafCertificate(issuer: Issuer, urls: IssuerUrls, req: LeafCertificateRequest): Promise<IssuedCertificate>;
export function buildCaCertificate(o: { subject: string; subjectSpki: Uint8Array; issuer?: Issuer /* undefined = self-signed with `signer` */; signer: CaSigner; notBefore: Date; notAfter: Date; pathLen?: number; urls?: IssuerUrls; ekuEmailProtection?: boolean }): Promise<IssuedCertificate>;
export function keyUsageFor(type: CertificateType, keyKind: "rsa" | "ec"): string[];

// CsrValidator.ts
export class PkiPolicyError extends Error { readonly code: "badCSR" | "badPublicKey"; }
export interface ValidatedCsr { spki: Uint8Array; spkiSha256: string; keyKind: "rsa" | "ec"; keyDescription: string; /* "RSA 3072" | "ECDSA P-256" */ emails: string[]; /* lower-cased domain, order preserved */ requestedType?: CertificateType; /* undefined = CSR has no KeyUsage request */ }
export function validateCsr(csr: Uint8Array | string /* DER or PEM or base64url DER */, o?: { forbiddenSpkiSha256?: Iterable<string>; }): Promise<ValidatedCsr>;
export function checkPublicKey(spki: Uint8Array): { keyKind: "rsa" | "ec"; description: string };   // throws PkiPolicyError("badPublicKey")
export function resolveCertificateType(requested: CertificateType | undefined, profile: CertificateType | undefined): CertificateType;   // throws PkiPolicyError("badCSR")

// Crl.ts
export interface RevokedEntry { serialHex: string; revokedAt: Date; reason?: number; }
export function buildCrl(issuer: Issuer, o: { number: bigint; thisUpdate: Date; nextUpdate: Date; revoked: RevokedEntry[] }): Promise<{ der: Uint8Array; pem: string }>;

// Ocsp.ts
export type CertStatusLookup = (issuer: Issuer, serialHex: string) => Promise<{ status: "good" | "revoked" | "unknown"; revokedAt?: Date; reason?: number }>;
export class OcspResponder { constructor(registry: IssuerRegistry, lookup: CertStatusLookup, o?: { validityHours?: number; now?: () => Date }); respond(requestDer: Uint8Array): Promise<Uint8Array>; /* always returns a DER OCSPResponse, incl. malformedRequest / unauthorized / internalError statuses */ }

// Ari.ts (RFC 9773)
export function ariCertId(cert: x509.X509Certificate): string;    // base64url(AKI keyIdentifier) "." base64url(serial DER INTEGER content)
export function parseAriCertId(id: string): { authorityKeyId: Uint8Array; serialHex: string } | undefined;

// util.ts
export function derToPem(der: Uint8Array, label: string): string; export function pemToDer(pem: string): Uint8Array; export function sha256Hex(data: Uint8Array): string; export function b64url(data: Uint8Array): string; export function fromB64url(s: string): Uint8Array;
```

`scripts/ca-init.ts` (`yarn ca:init`) builds root/issuer hierarchies with the same library and writes `issuers.json`.

### `src/lib/mail` – pure library, no RapidREST imports

```ts
// ChallengeMailer.ts
export interface ChallengeMail { to: string; tokenPart1: string; from: string; replyTo: string; messageId?: string; }
export interface ChallengeMailTransport { send(mail: ChallengeMail): Promise<{ messageId: string }>; }
export class SmtpChallengeMailer implements ChallengeMailTransport { constructor(o: { smtp: { url?: string; host?: string; port?: number; secure?: boolean; auth?: { user: string; pass: string }; ignoreTLS?: boolean }; dkim?: { domain: string; selector: string; privateKey: string }; hostname?: string }); }
export class MemoryChallengeMailer implements ChallengeMailTransport { readonly sent: Array<ChallengeMail & { messageId: string; subject: string; raw: string }>; }
export function challengeSubject(tokenPart1: string): string;         // "ACME: <token-part1>"

// InboundReply.ts
export interface InboundReply { messageId?: string; inReplyTo: string[]; from?: string; /* lower-cased addr-spec of the From header */ subject: string; tokenPart1?: string; digest?: string; dkimDomains: string[]; /* d= of every DKIM-Signature that verified AND signed the From header */ }
export type DnsTxtResolver = (name: string, rr: string) => Promise<unknown>;      // mailauth's `resolver` option
export function parseInboundReply(raw: Buffer | string, o?: { resolver?: DnsTxtResolver; sender?: string; ip?: string }): Promise<InboundReply>;
export function dkimAligned(reply: InboundReply, mode: "strict" | "relaxed"): boolean;

// SmtpReceiver.ts
export interface InboundEnvelope { mailFrom: string; rcptTo: string[]; remoteAddress: string; clientHostname?: string; }
export interface SmtpReceiverOptions { host?: string; port: number; hostname?: string; recipients: string[]; /* accepted RCPT TO addresses, case-insensitive */ maxSizeBytes?: number; tls?: { key: string; cert: string }; maxConnections?: number; }
export class SmtpReceiver { constructor(o: SmtpReceiverOptions, onMessage: (raw: Buffer, envelope: InboundEnvelope) => Promise<void>); start(): Promise<void>; stop(): Promise<void>; readonly port: number; }
```
