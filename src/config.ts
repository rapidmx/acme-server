///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { randomBytes } from "crypto";
import { createRequire } from "module";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import nconf from "nconf";

const _filename = fileURLToPath(import.meta.url);
const _dirname = dirname(_filename);
const _require = createRequire(import.meta.url);
const packageInfo = _require(join(process.cwd(), "package.json"));

// Environment variables override everything below with `__` as the nesting separator, e.g.
// `acme__external_url=https://acme.rapidmx.io` or `datastores__mongo__url=mongodb://mongo/acme`. See
// docs/ARCHITECTURE.md ("Configuration") for what each `acme.*` key means.
const conf = nconf
    .argv()
    .env({
        separator: "__",
        parseValues: true,
    });

conf.defaults({
    service_name: packageInfo.name,
    version: packageInfo.version,
    base_path: _dirname,
    // RapidREST's class loader registers every export of every file it scans as a DI class. `lib/` holds pure libraries (PKI,
    // mail, ACME primitives) that are constructed explicitly and export constants and namespaces the loader cannot stamp.
    class_loader: {
        ignore: [/server\..*/, /config\..*/, /^lib$/],
    },
    // The CA has no users and no access-controlled resources: every endpoint is public or authenticated by its own JWS.
    rbac: {
        enabled: false,
    },
    // RapidREST's request pipeline insists on an authentication strategy being configured even though no route here uses it.
    // The secret is random per process, so no token can ever be minted for it: nothing here trusts a JWT.
    auth: {
        strategy: "auth.JWTStrategy",
        secret: randomBytes(32).toString("hex"),
        options: {
            expiresIn: "1 hour",
            audience: "acme.rapidmx.io",
            issuer: "acme.rapidmx.io",
        },
    },
    // ACME requests and their JOSE envelopes are tiny; the only large body is a raw e-mail on the HTTP ingest route.
    max_body_size: 2 * 1024 * 1024,
    // Addresses of reverse proxies whose X-Forwarded-For is trusted for the per-IP rate limits (see RateLimiter).
    trusted_proxies: [],
    datastores: {
        mongo: {
            type: "mongodb",
            host: "localhost",
            database: "acme",
            // Creates the collections and indexes the models declare (unique serials, token lookups, TTLs...).
            synchronize: true,
        },
        // No `cache` (Redis) datastore by default: nonces and rate-limit buckets then live in process memory, which is only right
        // for a single instance and development. A real deployment sets `datastores__cache__type=redis` and
        // `datastores__cache__url=redis://...` so every replica shares them (the Helm chart does).
    },
    logger: {
        level: "info",
    },
    // The framework's own per-route rate limiter (used for the cheap public endpoints that are not ACME requests).
    rateLimit: {
        enabled: true,
        maxAttempts: 600,
        windowSeconds: 60,
        ip: { maxAttempts: 300, windowSeconds: 60 },
    },
    acme: {
        // The public base URL every URL handed to a client is built from. No trailing slash.
        external_url: "http://localhost:3000",
        terms_of_service_url: "",
        website: "https://rapidmx.io",
        // What a domain's CAA `issuemail` property must name for this CA to issue for it (RFC 9495).
        caa_identities: ["rapidmx.io"],
        order_expiry_hours: 168,
        authorization_expiry_hours: 168,
        nonce_ttl_seconds: 3600,
        // Identifiers per order. The RapidMX client asks for one address at a time.
        max_identifiers: 1,
        ca: {
            manifest: "/var/lib/acme/ca/issuers.json",
            backdate_minutes: 60,
            profiles: {
                signing: { validity_days: 90 },
                encryption: { validity_days: 90 },
                "signing-encryption": { validity_days: 90 },
            },
            // How often the CRL is regenerated (it is also regenerated at once when something is revoked), and how long
            // each one is valid for. The Baseline Requirements cap a CRL's validity at 10 days.
            crl_refresh_hours: 12,
            crl_validity_hours: 168,
            ocsp_validity_hours: 24,
        },
        mail: {
            // Placeholders for development; a real deployment must set both to addresses on the CA's own domain.
            from: "acme-challenge@acme.localdomain",
            reply_to: "acme-response@acme.localdomain",
            smtp: {},
            dkim: {},
            // "strict": the DKIM d= must equal the From domain (RFC 8823). "relaxed": a parent domain is enough.
            dkim_alignment: "strict",
            inbound: {
                smtp: {
                    enabled: false,
                    host: "0.0.0.0",
                    port: 2525,
                    max_size_bytes: 1024 * 1024,
                },
                // Bearer secret of POST /internal/mail/inbound (an MTA bridge). Unset = the route answers 404.
                http_secret: "",
            },
        },
        dns: {
            // Extra resolvers; empty = the system's.
            servers: [],
            // "validate": CAA answers are DNSSEC-validated in-process against the root trust anchors (a broken or stripped signature
            // refuses the order); "off": the resolver's unvalidated answer is used. Refused outside development.
            dnssec: "validate",
        },
        reminders: {
            // Expiry reminders to the account contacts: 1 week, 3 days and 1 day before, on the day, and 1 day and 1 week after.
            enabled: true,
            // The most certificates one run (every ten minutes) picks up.
            batch_size: 500,
        },
        rate_limits: {
            enabled: true,
            overrides: [],
        },
        // Bearer secret of the operator API (/admin: search, revoke, suspend). Unset = the API does not exist (404). At least 32
        // characters outside development. Never route /admin through a public gateway.
        admin_secret: "",
        // Bearer secret for GET /metrics. Unset = the route answers 404 (scrape from inside the cluster with it set).
        metrics_secret: "",
    },
});

export default conf;
