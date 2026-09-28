# acme — Design Decisions & Session Notes

This file exists so that Claude sessions working in this repo don't re-litigate settled
decisions or re-discover the same issues from scratch. It is local to this repo (not tied to
any one machine's global Claude memory), so it travels with the code.

**Maintenance rule:** when a standing decision changes, update the section below in place
(don't just append a contradiction lower down). When a new investigation/session produces a
decision, finding, or reverted approach worth remembering, add a dated entry under Session Log.
Keep entries terse — this is a reference, not a transcript.

## Standing decisions

- **Commit discipline.** Don't `git commit` unless explicitly asked for *that specific piece of
  work*. An autonomous-execution/"commit as you go" approval given for one approved plan (e.g. via
  plan mode) is scoped to that plan only — it does not carry forward to later, separate requests in
  the same session, even ones that look similar in kind (a follow-up review-and-fix pass, a
  refactor, a new feature), and even after a full review-and-fix cycle with passing tests. Default
  to leaving changes staged/unstaged and saying so; only commit automatically within the exact
  scope of a plan that was explicitly approved as autonomous. If unsure whether new work falls
  inside that scope, treat it as outside and ask.
- **Commit message style: a flat list of one-line, verb-led items — no summary/title line, no
  `-`/`*` bullet markers.** This isn't just a style preference — it's dictated by how `release`
  (`@rapidrest/cli`) actually builds `CHANGELOG.md`. `collectChangelogBullets`/
  `classifyChangelogLine` (that repo's `src/lib/release.ts`) parse `git log --pretty=format:%B` and
  treat **every non-blank line of a commit's full message as its own changelog bullet** — there is
  no subject/body distinction. A conventional "short imperative subject + blank line + prose body"
  commit therefore leaks one changelog bullet per body sentence, and a `-`/`*`-prefixed line breaks
  `classifyChangelogLine`'s verb detection (it reads the line's first whitespace-delimited word as
  the verb; a leading `-` defeats that lookup and the dash leaks into the changelog text as
  `"- - Added foo"`). Correct format:
  - No separate summary/title line — if a commit needs an overview, that overview is itself just
    one more flat line, not a heading distinct from the rest.
  - No bullet-marker prefix of any kind — write bare lines.
  - Lead each line with an imperative verb where it fits: `Add`/`Fix`/`Remove` (and `-ing` forms)
    are recognized and become `Added`/`Fixed`/`Removed` entries; `Configuring`/`Converting`/
    `Refactoring`/`Updating`/etc. become `Changed`. Anything else still works, defaulting to
    `Changed` verbatim — see `CHANGELOG_VERB_REWRITES` in that repo's `src/lib/release.ts` for the
    full map.
  - A blank line before a trailing git trailer (`Co-Authored-By:`, `Signed-off-by:`, etc.) is fine
    — trailers matching `CHANGELOG_NOISE_PATTERNS` are dropped from the changelog — but nothing
    else should follow the item list.
  This mirrors JP's standing convention across his other repos; copy this exact rule verbatim into
  each sibling repo's own NOTES.md rather than paraphrasing it, since the paraphrase is what caused
  this to be gotten wrong in the first place (see `@rapidrest/cli`'s own NOTES.md, 2026-09-07 entry,
  for the full incident writeup and the `CHANGELOG_NOISE_PATTERNS` fix that accompanied it).
- **This is the RapidMX ACME CA**: a standalone RapidREST service (planned host `acme.rapidmx.io`)
  that issues S/MIME certificates over ACME (RFC 8555) with the RFC 8823 `email-reply-00`
  challenge. It exists because the public CA `@rapidmx/restapi`'s
  `Rfc8823AcmeSigningCertificateEnrollment` defaulted to (`acme.castle.cloud`) never finished a
  request (stuck in "verification" for 24 h+ on the live test server, 2026-09-23). The design and the
  module contracts are in `docs/ARCHITECTURE.md`; the issuance policy is in `docs/CPS.md`.
- **Trust model, stated everywhere and never softened:** the root is *not* in any OS/browser/mail-client
  trust store. Certificates verify only where the RapidMX root (`GET /ca/roots.pem`) is trusted. The code
  follows the S/MIME Baseline Requirements' mailbox-validated profile where practical but asserts no CA/B
  Forum policy OIDs and is not an audit statement. Public WebPKI trust is a separate compliance project.
- **`src/lib/` is invisible to RapidREST's class loader** (`class_loader.ignore` has `/^lib$/`). The loader
  registers *every* export of every scanned file as a DI class and stamps `fqn` onto it, which throws on a
  module namespace / frozen object (`Cannot redefine property: fqn`) and silently leaks an `fqn` key into
  any exported constant object that ends up in JSON (it showed up in the directory's `meta.profiles`).
  Consequences: pure libraries (PKI, mail, ACME primitives) live in `lib/`; nothing under `routes/`,
  `services/`, `models/`, `jobs/` may export a non-class constant object or a barrel `index.ts`.
- **One RapidREST `Server` per process.** `Server`'s constructor registers prom-client metrics in the
  global registry, so a second one throws. The test harness calls `prom.register.clear()` first.
- **The framework insists on an `auth` config block and (unless `rbac.enabled: false`) an `acl`
  datastore**, though no route uses either. `config.ts` sets `rbac.enabled: false` and a random per-process
  `auth.secret`, so no JWT can ever be minted for it. Don't "clean this up".
- **`@Init` does not wait for `@Inject`ed async dependencies** (it runs right after the injection loop while
  their promises are still pending). Services that need one resolve it with
  `await objectFactory.newInstance(...)` inside `init()`, like `AcmeContext` does. Injection failures are
  logged and swallowed, which is why `server.ts` checks `AcmeContext.ready` after `start()` and exits 1.
- **Everything is built from ASN.1 structures and signed through one seam** (`CaSigner.sign()`), so a remote
  key (OpenBao Transit) works exactly like a file key. No `X509CertificateGenerator` for issuing.
- **Serials are whole bytes**: lower-case even-length hex without leading zero *bytes*
  (`lib/acme/Util.normalizeSerial`). Trimming a leading zero *nibble* (regex `^0+`) corrupts 1 in 16 serials
  — it broke the CRL builder ("Invalid serial number") until found by a test. Never normalize serials with a
  digit-wise regex.
- **The rate limiter is ours, not the framework's** `RateLimiter` (fixed window, bare 429): ACME needs
  `Retry-After`, `rateLimited` problem documents with a `rel="help"` link and token-bucket semantics.
  GCRA in `lib/acme/AcmeStore.ts`; the Redis Lua script is tested by running its *text* in a Lua VM
  (`test/support/luaRedis.ts`, fengari) against the reference for 1,600 random operations. Never verified
  against a real Redis server (none available on the dev machine).
- **Inbound reply verification is the CA's own DKIM check** (`mailauth`), not a trusted
  `Authentication-Results` header: RFC 8823 wants `d=` = the From domain, `From` = the identifier, and a
  digest of token-part1‖token-part2‖"."‖account-key-thumbprint. A challenge becomes valid only when both the
  verified reply *and* the client's POST to the challenge URL exist (either order).
- **Adversarial review (2026-09-24) found no way to get a certificate for a mailbox you don't control**, and six availability/
  robustness defects, all fixed with regression tests in `test/review/`: mail budgets that let one stranger lock an address or a
  whole domain out (now a small per-(account,address) budget plus large shared ones and a per-IP one); DKIM verification (a DNS query
  per signature) done before the token lookup (now two-pass, signature count capped, per-IP SMTP connection cap); the RSA modulus
  tests run before the CSR signature check (now cheap checks, signature, then deep checks; plus a per-account finalize limit);
  missing indexes for the pending-authorization count; a lost race leaving an authorization marked mailed but never mailed (claim
  released and tokens refunded on any failure); finalize on a ready order whose authorization was deactivated. Still open by design:
  OCSP responses are signed per request (no cache), nonces are stored for every POST including errors.
- **Recipient protection is a feature**: this CA sends mail to addresses strangers name, so it limits mails
  per address/domain/account (`challengeMails*` limits) and never answers an inbound mail (no reflector).
- **`resolutions` pins `mailauth/nodemailer` to 10.0.10.** mailauth 5.0.3 ships its own nodemailer 9.0.4, whose
  `addressparser` (quadratic time, high severity, fixed in 9.1.0) mailauth's DKIM verifier runs on the attacker-controlled
  `From` of every inbound reply. Remove the pin only when mailauth depends on nodemailer >= 9.1.0 itself. `yarn npm audit -A -R
  --environment production` still reports joi (low; mailauth, not reachable), cron-parser and prom-client deprecation (both
  pulled in by RapidREST itself) - not ours to fix here.
- **Addresses are canonicalized once, in `lib/pki/mailbox.ts` (`canonicalMailbox`)**: NFC local part as given, domain as lower-case
  A-labels; `key` (lower-case, NFC) is what limits and comparisons use. A non-ASCII local part goes into the certificate as an
  `SmtpUTF8Mailbox` otherName (RFC 8398, U-label domain), anything else as an `rfc822Name` with A-labels (RFC 8399). Non-NFC and
  compatibility-mapped input is refused, never silently rewritten. Do not lower-case or regex addresses anywhere else - always
  `canonicalMailbox()`/`parseEmailIdentifier()`/`sameAddress()`. The MIME parser and mailauth may spell the same From differently
  (U-labels vs Punycode); `comparableAddress()` in InboundReply.ts reconciles them.
- **The operator API (`/admin`, `acme.admin_secret`) is a single bearer secret with power over every certificate**: 404 when unset,
  a wrong token costs the caller's IP a token from `adminAuthFailuresPerIp` (429 once empty, even for the right token), every action is
  logged with `X-Operator`, revocations record source/note/operator, and the Helm chart never routes it publicly. All revocations go
  through `CertificateService.markRevoked()`.
- **Not implemented (documented follow-ups):** external account binding, wildcard/multi-identifier orders
  beyond `acme.max_identifiers`, Ed25519 subject keys, a delegated
  OCSP responder certificate (responses are signed by the issuer key), CRL sharding, ROCA/Debian weak-key
  blocklists beyond the fingerprint check, a public-suffix list for "per registered domain" limits (the
  e-mail domain is used as is), pre-authorization, and CT logging of issued
  certificates (S/MIME has no CT requirement).
- **Consumers still point at CASTLE.** `@rapidmx/restapi`'s `Rfc8823AcmeSigningCertificateEnrollment` and
  `server`'s `config.mongo.ts`/`config.sql.ts`/`helm/values.yaml` default `mail:pki:rfc8823:directory_url`
  to `https://acme.castle.cloud/acme/directory`; switching to `https://acme.rapidmx.io/directory` is a change
  in those repos (not done here). The restapi client sends no `profile` and no `replaces` yet; encryption
  certificates need its CSR to carry a KeyUsage request (RFC 8823 §3.3).

## Session Log

### 2026-09-24 — Initial build

Scaffolded with `rapidrest generate server` (the *source-checkout* CLI: the npm-published `@rapidrest/cli`
strips `src/`, `tsconfig.json` and `.gitignore` from its server template), then built the whole service:
RFC 8555 + 8823 + 9773 protocol core, PKI library, mail layer, rate limits, CRL/OCSP, trust endpoints,
deployment artifacts. Verified: 800+ unit and integration tests (95% line coverage) (real RapidREST server over real HTTP against
an in-memory MongoDB), interop with the independent `acme-client` package driven exactly like
`Rfc8823AcmeSigningCertificateEnrollment`, `openssl` accepting certificates/CRLs/OCSP responses (PKI
agent), and a smoke run of the *built* server as a real process (real DNS MX/CAA lookups, a genuine
DKIM-signed challenge through a real SMTP relay stub, the SMTP receiver, the production config guard).
Findings worth remembering: `example.com` publishes a null MX (RFC 7505) so the CA correctly refuses it
against real DNS; use `gmail.com`-like domains in real-DNS smoke tests. DNSSEC: CAA goes through `DnsChecks` + `CaaValidator` (`lib/dnssec` `DnssecResolver`, fail closed; `bogus`/`indeterminate` both -> `dns` problem); it is skipped when a `DnsLookup` is registered in DI (tests) unless a `CaaValidator` is registered too (`startCa({}, { dnssec: true })`). Expiry reminders: `ReminderService` (run by MaintenanceJob) + pure schedule in `lib/acme/Reminders.ts`; per-cert `reminderStage`/`nextReminderAt` claimed with a conditional update, mail via `ChallengeMailTransport.sendNotice`, recipients are the ACCOUNT contacts (never the certificate's mailbox), "renewed" = another valid cert with same email+type outliving it. Reminder tests fake time with `ca.ctx.now` and must assert on `mailsTo(contact)`, not on run totals (other tests' certs are due at the same simulated time). Not verified: a real Redis, a real
OpenBao Transit, a real inbound MTA/DKIM signature from a live mail server, a real Outlook/Thunderbird trust
import, Linux/POSIX file modes (developed on Windows).

### 2026-09-25 - release bump levels follow upstream

When releasing packages that depend on each other (rapidmx: restapi / react-shared -> web-client -> meet-plugin, booking-plugin, autodiscover, mapi, activesync, server; rapidrest: core / service-core -> auth / auth-server / react / cli and the projects built on them), the bump level of a downstream release matches the level of the upstream release it picks up: an upstream **minor** is a downstream **minor**, an upstream patch a downstream patch, major to major. Where a downstream bump crosses several upstream releases, use the highest level among them, and never choose "patch" just because the downstream's own diff is only a `package.json` bump. Betas keep their prerelease line but follow the same idea - say which level was chosen.

Why: meet-plugin 0.4.2 and booking-plugin 0.5.2 were cut as patches after web-client 0.15.x -> 0.16.0 and react-shared 0.17.0 -> 0.18.0 (both minors), and autodiscover 1.1.1 after restapi 0.20.1 -> 0.21.0; the downstream versions then hid additive behaviour. JP accepted those releases as they were (2026-09-25) and asked for the rule going forward. Releases only happen when JP asks for them.

### 2026-09-28 - Always wait for CI to go green before releasing

Standing process rule, applies to every rapidmx/rapidrest repo: push pending commits, wait for the GitHub Actions **Build** workflow on that push to report `success` (`https://api.github.com/repos/<org>/<repo>/actions/runs`, or ask JP for the downloaded log archive if API log access needs auth - it 403s without a token), and only then run `npx @rapidrest/cli release ...`. Do not tag/release first and diagnose CI failures afterward. During a 2026-09-28 multi-repo release wave, restapi was released immediately after pushing pending commits without waiting for CI; CI then failed on a real coverage-threshold regression the pending changes introduced (a missing test for `BasePluginRoute.newestSearchResult()`'s catch branch) - not a flake, as an incomplete local-only reproduction first suggested. Because the release commit/tag were already pushed, the fix had to land as a follow-up commit on top of an already-tagged release instead of before it.
