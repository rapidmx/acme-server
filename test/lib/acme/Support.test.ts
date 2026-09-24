///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// The small pieces around the protocol: problem documents, URLs, nonces, the rate limiter's arithmetic and wording, the info
// pages, the settings reader and the startup guard.
import { AcmeProblem } from "../../../src/lib/acme/AcmeProblem.js";
import { AcmeUrls } from "../../../src/lib/acme/AcmeUrls.js";
import { MemoryAcmeStore } from "../../../src/lib/acme/AcmeStore.js";
import { renderRateLimits, renderTerms } from "../../../src/lib/acme/InfoPages.js";
import { randomId, randomToken, safeEqual, sha256B64url, sha256Hex } from "../../../src/lib/acme/Ids.js";
import { NonceService } from "../../../src/lib/acme/Nonces.js";
import { DEFAULT_LIMITS, AcmeRateLimiter, ipSubject } from "../../../src/lib/acme/RateLimits.js";
import { isDuplicateKey, normalizeSerial } from "../../../src/lib/acme/Util.js";
import { assertProductionConfig } from "../../../src/config.defaults.js";
import { AcmeSettings } from "../../../src/services/AcmeSettings.js";

describe("AcmeProblem", () => {
    it("carries the ACME URN, the mapped HTTP status and the document fields", () => {
        const problem = new AcmeProblem("badNonce", "use a new nonce");
        expect(problem.type).toBe("urn:ietf:params:acme:error:badNonce");
        expect(problem.status).toBe(400);
        expect(problem.toDocument()).toEqual({ type: "urn:ietf:params:acme:error:badNonce", detail: "use a new nonce", status: 400 });
        expect(new AcmeProblem("unauthorized", "x").status).toBe(403);
        expect(new AcmeProblem("rateLimited", "x").status).toBe(429);
        expect(new AcmeProblem("serverInternal", "x").status).toBe(500);
        expect(new AcmeProblem("malformed", "x", 415).status).toBe(415);
        expect(new AcmeProblem("alreadyReplaced", "x").status).toBe(409);
        expect(new AcmeProblem("badCertificateIdentifier", "x").status).toBe(404);
    });

    it("exposes algorithms and subproblems only when set", () => {
        const problem = new AcmeProblem("badSignatureAlgorithm", "no");
        expect(problem.toDocument()).not.toHaveProperty("algorithms");
        problem.algorithms = ["ES256"];
        problem.subproblems = [{ type: "urn:ietf:params:acme:error:malformed", detail: "d", identifier: { type: "email", value: "a@example.com" } }];
        expect(problem.toDocument()).toMatchObject({ algorithms: ["ES256"], subproblems: [{ detail: "d" }] });
    });

    it("builds rate limit problems with a whole-second retry and never a 0", () => {
        const limited = AcmeProblem.rateLimited("too many", 0.2, "https://x/help");
        expect(limited.retryAfterSeconds).toBe(1);
        expect(limited.helpUrl).toBe("https://x/help");
        expect(AcmeProblem.rateLimited("too many", 61.2).retryAfterSeconds).toBe(62);
        expect(AcmeProblem.internal().status).toBe(500);
        expect(AcmeProblem.internal().message).not.toMatch(/stack|mongo|at /i);
        expect(AcmeProblem.unauthorized("x").errorType).toBe("unauthorized");
        expect(AcmeProblem.malformed("x").errorType).toBe("malformed");
    });
});

describe("AcmeUrls", () => {
    const urls = new AcmeUrls("https://acme.example.org///");

    it("builds every URL from the external URL, without a doubled slash", () => {
        expect(urls.base).toBe("https://acme.example.org");
        expect(urls.directory()).toBe("https://acme.example.org/directory");
        expect(urls.newNonce()).toBe("https://acme.example.org/acme/new-nonce");
        expect(urls.newAccount()).toBe("https://acme.example.org/acme/new-acct");
        expect(urls.newOrder()).toBe("https://acme.example.org/acme/new-order");
        expect(urls.revokeCert()).toBe("https://acme.example.org/acme/revoke-cert");
        expect(urls.keyChange()).toBe("https://acme.example.org/acme/key-change");
        expect(urls.renewalInfoBase()).toBe("https://acme.example.org/acme/renewal-info");
        expect(urls.renewalInfo("a.b")).toBe("https://acme.example.org/acme/renewal-info/a.b");
        expect(urls.account("id1")).toBe("https://acme.example.org/acme/acct/id1");
        expect(urls.accountOrders("id1")).toBe("https://acme.example.org/acme/acct/id1/orders");
        expect(urls.order("o")).toBe("https://acme.example.org/acme/order/o");
        expect(urls.finalize("o")).toBe("https://acme.example.org/acme/order/o/finalize");
        expect(urls.authorization("a")).toBe("https://acme.example.org/acme/authz/a");
        expect(urls.challenge("a", "c")).toBe("https://acme.example.org/acme/chall/a/c");
        expect(urls.certificate("c")).toBe("https://acme.example.org/acme/cert/c");
        expect(urls.terms()).toBe("https://acme.example.org/terms");
        expect(urls.forPath("/x")).toBe("https://acme.example.org/x");
    });

    it("parses ids only out of its own URLs", () => {
        expect(urls.accountIdFrom("https://acme.example.org/acme/acct/abcdefgh12345678")).toBe("abcdefgh12345678");
        expect(urls.accountIdFrom("https://evil.example/acme/acct/abcdefgh12345678")).toBeUndefined();
        expect(urls.accountIdFrom("https://acme.example.org/acme/acct/abc")).toBeUndefined();
        expect(urls.accountIdFrom("https://acme.example.org/acme/acct/abcdefgh12345678/orders")).toBeUndefined();
        expect(urls.accountIdFrom("https://acme.example.org/acme/acct/../../x")).toBeUndefined();
        expect(urls.accountIdFrom(42 as any)).toBeUndefined();
        expect(urls.certificateIdFrom("https://acme.example.org/acme/cert/abcdefgh12345678")).toBe("abcdefgh12345678");
        expect(urls.certificateIdFrom("https://acme.example.org/acme/order/abcdefgh12345678")).toBeUndefined();
    });
});

describe("NonceService", () => {
    it("issues distinct 144-bit nonces and accepts each exactly once", async () => {
        const store = new MemoryAcmeStore();
        const nonces = new NonceService(store, 60);
        const a = await nonces.issue();
        const b = await nonces.issue();
        expect(a).not.toBe(b);
        expect(a).toMatch(/^[A-Za-z0-9_-]{24}$/);
        expect(await nonces.consume(a)).toBe(true);
        expect(await nonces.consume(a)).toBe(false);
        expect(await nonces.consume(b)).toBe(true);
        await store.close();
    });

    it("refuses nonces that were never issued, that are the wrong shape, or that expired", async () => {
        let now = 0;
        const store = new MemoryAcmeStore(() => now);
        const nonces = new NonceService(store, 10);
        expect(await nonces.consume("AAAAAAAAAAAAAAAAAAAAAAAA")).toBe(false);
        for (const junk of ["", "short", "x".repeat(65), "has spaces in it 123456", 5 as any, undefined as any]) {
            expect(await nonces.consume(junk)).toBe(false);
        }
        const expired = await nonces.issue();
        now += 11_000;
        expect(await nonces.consume(expired)).toBe(false);
        await store.close();
    });
});

describe("ids and helpers", () => {
    it("generates unguessable ids and tokens", () => {
        expect(randomId()).toMatch(/^[A-Za-z0-9_-]{22}$/);
        expect(randomToken()).toMatch(/^[A-Za-z0-9_-]{43}$/);
        expect(new Set(Array.from({ length: 200 }, randomId)).size).toBe(200);
    });

    it("hashes and compares", () => {
        expect(sha256Hex("abc")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        expect(sha256B64url("abc")).toBe("ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0");
        expect(safeEqual("abc", "abc")).toBe(true);
        expect(safeEqual("abc", "abd")).toBe(false);
        expect(safeEqual("abc", "abcd")).toBe(false);
        expect(safeEqual("", "")).toBe(true);
    });

    it("keeps serials as whole bytes", () => {
        expect(normalizeSerial("0ABC")).toBe("0abc");
        expect(normalizeSerial("ABC")).toBe("0abc");
        expect(normalizeSerial("00ff")).toBe("ff");
        expect(normalizeSerial("0000ff")).toBe("ff");
        expect(normalizeSerial("00")).toBe("00");
        expect(normalizeSerial("7f")).toBe("7f");
    });

    it("recognizes MongoDB's duplicate key error", () => {
        expect(isDuplicateKey({ code: 11000 })).toBe(true);
        expect(isDuplicateKey({ code: 121 })).toBe(false);
        expect(isDuplicateKey(undefined)).toBe(false);
        expect(isDuplicateKey(new Error("x"))).toBe(false);
    });
});

describe("ipSubject", () => {
    it("counts an IPv4 address as itself and unwraps IPv4-mapped IPv6", () => {
        expect(ipSubject("203.0.113.7")).toBe("203.0.113.7");
        expect(ipSubject("::ffff:203.0.113.7")).toBe("203.0.113.7");
        expect(ipSubject("::FFFF:203.0.113.7")).toBe("203.0.113.7");
    });

    it("counts an IPv6 address as its /48, so one host cannot mint identities from its whole prefix", () => {
        expect(ipSubject("2001:db8:abcd:1234:5678:9abc:def0:1234")).toBe("2001:0db8:abcd::/48");
        expect(ipSubject("2001:db8:abcd:ffff::1")).toBe("2001:0db8:abcd::/48");
        expect(ipSubject("2001:DB8:ABCD::")).toBe("2001:0db8:abcd::/48");
        expect(ipSubject("::1")).toBe("0000:0000:0000::/48");
        expect(ipSubject("fe80::1%eth0")).toBe("fe80:0000:0000::/48");
    });

    it("has a bucket for an unknown address", () => {
        expect(ipSubject(undefined)).toBe("unknown");
        expect(ipSubject("")).toBe("unknown");
    });
});

describe("AcmeRateLimiter", () => {
    const fresh = (options: ConstructorParameters<typeof AcmeRateLimiter>[1] = {}, now: () => number = () => Date.UTC(2030, 5, 1, 12, 0, 0)) => {
        // One clock for the buckets and for the wording, so the arithmetic is exact.
        const store = new MemoryAcmeStore(now);
        return { store, limiter: new AcmeRateLimiter(store, options, now) };
    };

    it("does nothing when disabled", async () => {
        const { limiter, store } = fresh({ enabled: false });
        for (let i = 0; i < 1000; i++) {
            await limiter.spend("newAccountsPerIp", "1.2.3.4");
        }
        await limiter.refund("newAccountsPerIp", "1.2.3.4");
        expect(store.size()).toBe(0);
        await store.close();
    });

    it("words a rejection like Let's Encrypt: the limit, the window, when to retry and where to read more", async () => {
        const { limiter, store } = fresh({ helpUrl: "https://acme.example/rate-limits" });
        for (let i = 0; i < 10; i++) {
            await limiter.spend("newAccountsPerIp", "1.2.3.4");
        }
        const error: AcmeProblem = await limiter.spend("newAccountsPerIp", "1.2.3.4").then(
            () => Promise.reject(new Error("should have been limited")),
            (err) => err,
        );
        expect(error).toBeInstanceOf(AcmeProblem);
        expect(error.errorType).toBe("rateLimited");
        expect(error.status).toBe(429);
        expect(error.message).toBe("too many new accounts from this IP address (10 in the last 3h0m0s), retry after 2030-06-01 12:18:00 UTC: see https://acme.example/rate-limits#new-registrations-per-ip-address");
        expect(error.retryAfterSeconds).toBe(1080);
        expect(error.helpUrl).toBe("https://acme.example/rate-limits#new-registrations-per-ip-address");
        await store.close();
    });

    it("words per-second and per-week limits", async () => {
        const { limiter, store } = fresh();
        const drain = async (name: Parameters<typeof limiter.spend>[0], subject: string, times: number) => {
            for (let i = 0; i < times; i++) {
                await limiter.spend(name, subject);
            }
            return await limiter.spend(name, subject).then(() => "", (err: AcmeProblem) => err.message);
        };
        expect(await drain("endpointNonce", "ip", 10)).toContain("too many new-nonce requests (20/s)");
        expect(await drain("certificatesPerEmail", "a@example.com", 5)).toContain("too many certificates for this address (5 in the last 168h0m0s)");
        expect(await drain("challengeMailsPerAccountEmailHour", "acct|a@example.com", 3)).toContain("(3 in the last 1h0m0s)");
        await store.close();
    });

    it("keeps subjects apart, ignoring case", async () => {
        const { limiter, store } = fresh();
        for (let i = 0; i < 3; i++) {
            await limiter.spend("challengeMailsPerAccountEmailHour", "Acct|Victim@Example.com");
        }
        await expect(limiter.spend("challengeMailsPerAccountEmailHour", "acct|victim@example.com")).rejects.toBeInstanceOf(AcmeProblem);
        await expect(limiter.spend("challengeMailsPerAccountEmailHour", "acct|other@example.com")).resolves.toBeUndefined();
        await store.close();
    });

    it("check refuses without spending, refund makes room again", async () => {
        const { limiter, store } = fresh();
        for (let i = 0; i < 5; i++) {
            await limiter.spend("failedAuthorizations", "acct|a@example.com");
        }
        await expect(limiter.check("failedAuthorizations", "acct|a@example.com")).rejects.toBeInstanceOf(AcmeProblem);
        await limiter.refund("failedAuthorizations", "acct|a@example.com");
        await expect(limiter.check("failedAuthorizations", "acct|a@example.com")).resolves.toBeUndefined();
        await expect(limiter.check("failedAuthorizations", "acct|a@example.com", 2)).rejects.toBeInstanceOf(AcmeProblem);
        await store.close();
    });

    it("applies an override to its subject only, defaulting the burst to the new count", async () => {
        const { limiter, store } = fresh({ overrides: [{ limit: "newOrdersPerAccount", subject: "VIP", count: 2, period_seconds: 60 }] });
        expect(limiter.definition("newOrdersPerAccount", "vip")).toMatchObject({ count: 2, periodSeconds: 60, burst: 2 });
        expect(limiter.definition("newOrdersPerAccount", "someone")).toEqual(DEFAULT_LIMITS.newOrdersPerAccount);
        await limiter.spend("newOrdersPerAccount", "vip");
        await limiter.spend("newOrdersPerAccount", "vip");
        await expect(limiter.spend("newOrdersPerAccount", "vip")).rejects.toBeInstanceOf(AcmeProblem);
        for (let i = 0; i < 300; i++) {
            await limiter.spend("newOrdersPerAccount", "someone");
        }
        await expect(limiter.spend("newOrdersPerAccount", "someone")).rejects.toBeInstanceOf(AcmeProblem);
        await store.close();
    });

    it("has a definition, anchor and description for every limit", () => {
        for (const [name, def] of Object.entries(DEFAULT_LIMITS)) {
            expect(def.count, name).toBeGreaterThan(0);
            expect(def.periodSeconds, name).toBeGreaterThan(0);
            expect(def.burst, name).toBeGreaterThanOrEqual(1);
            expect(def.anchor, name).toMatch(/^[a-z0-9-]+$/);
            expect(def.what.length, name).toBeGreaterThan(5);
        }
    });
});

describe("info pages", () => {
    it("renders the terms with the CA's own URLs and identities, escaped", () => {
        const html = renderTerms({ externalUrl: "https://acme.example.org", caIdentities: ["rapidmx.io", "<script>x</script>"], website: "https://example.org/?a=1&b=2" });
        expect(html).toContain('href="https://acme.example.org/ca"');
        expect(html).toContain("<code>rapidmx.io</code>");
        expect(html).not.toContain("<script>");
        expect(html).toContain("&lt;script&gt;");
        expect(html).toContain("a=1&amp;b=2");
        expect(html).toContain("<strong>not</strong> included in");
    });

    it("renders a section per limit anchor", () => {
        const html = renderRateLimits(DEFAULT_LIMITS);
        for (const def of Object.values(DEFAULT_LIMITS)) {
            expect(html).toContain(`id="${def.anchor}"`);
        }
        expect(html).toContain("10 per 3 hour(s)");
        expect(html).toContain("5 per 7 day(s)");
        expect(html).toContain("20 per second");
        expect(html).toContain('id="pending-authorizations"');
    });
});

describe("AcmeSettings", () => {
    const settings = (values: Record<string, unknown>) => new AcmeSettings({ get: (key: string) => values[key] });

    it("falls back to defaults for anything unset or blank", () => {
        const s = settings({ "acme:external_url": "", "acme:order_expiry_hours": "" });
        expect(s.externalUrl).toBe("http://localhost:3000");
        expect(s.termsOfServiceUrl).toBe("http://localhost:3000/terms");
        expect(s.orderExpiryHours).toBe(168);
        expect(s.authorizationExpiryHours).toBe(168);
        expect(s.nonceTtlSeconds).toBe(3600);
        expect(s.maxIdentifiers).toBe(1);
        expect(s.validityDays("signing")).toBe(90);
        expect(s.caaIdentities).toEqual(["rapidmx.io"]);
        expect(s.dkimAlignment).toBe("strict");
        expect(s.inboundSmtpEnabled).toBe(false);
        expect(s.inboundSmtpTls).toBeUndefined();
        expect(s.rateLimitsEnabled).toBe(true);
        expect(s.rateLimitOverrides).toEqual([]);
        expect(s.dnsServers).toEqual([]);
        expect(s.metricsSecret).toBe("");
    });

    it("reads configured values, coercing the strings environment variables produce", () => {
        const s = settings({
            "acme:external_url": "https://acme.example.org/",
            "acme:terms_of_service_url": "https://example.org/tos",
            "acme:caa_identities": "a.example, b.example",
            "acme:order_expiry_hours": "24",
            "acme:max_identifiers": "0",
            "acme:ca:profiles:encryption:validity_days": 180,
            "acme:mail:dkim_alignment": "relaxed",
            "acme:mail:inbound:smtp:enabled": "true",
            "acme:mail:inbound:smtp:tls_key_path": "/k",
            "acme:mail:inbound:smtp:tls_cert_path": "/c",
            "acme:rate_limits:enabled": "false",
            "acme:rate_limits:overrides": [{ limit: "newOrdersPerAccount", subject: "x" }],
            "acme:dns:servers": ["9.9.9.9"],
        });
        expect(s.externalUrl).toBe("https://acme.example.org");
        expect(s.termsOfServiceUrl).toBe("https://example.org/tos");
        expect(s.caaIdentities).toEqual(["a.example", "b.example"]);
        expect(s.orderExpiryHours).toBe(24);
        expect(s.maxIdentifiers).toBe(1);
        expect(s.validityDays("encryption")).toBe(180);
        expect(s.dkimAlignment).toBe("relaxed");
        expect(s.inboundSmtpEnabled).toBe(true);
        expect(s.inboundSmtpTls).toEqual({ key: "/k", cert: "/c" });
        expect(s.rateLimitsEnabled).toBe(false);
        expect(s.rateLimitOverrides).toHaveLength(1);
        expect(s.dnsServers).toEqual(["9.9.9.9"]);
    });
});

describe("assertProductionConfig", () => {
    const good = {
        "acme:external_url": "https://acme.rapidmx.io",
        "acme:mail:from": "acme-challenge@acme.rapidmx.io",
        "acme:mail:reply_to": "acme-response@acme.rapidmx.io",
        "acme:mail:smtp:url": "smtp://relay.example.org:587",
        "acme:mail:dkim:domain": "acme.rapidmx.io",
        "acme:mail:dkim:selector": "s1",
        "acme:mail:dkim:private_key_path": "/etc/acme/dkim.pem",
    };
    const config = (values: Record<string, unknown>) => ({ get: (key: string) => values[key] });

    it("lets development environments run with the placeholders", () => {
        for (const env of ["dev", "development", "test"]) {
            expect(() => assertProductionConfig(config({}), env)).not.toThrow();
        }
    });

    it("accepts a correct production configuration", () => {
        expect(() => assertProductionConfig(config(good), "production")).not.toThrow();
        expect(() => assertProductionConfig(config({ ...good, "acme:external_url": "https://acme.rapidmx.io/" }), "production")).not.toThrow();
    });

    it("treats an unset or unfamiliar NODE_ENV as production", () => {
        expect(() => assertProductionConfig(config({}), undefined)).toThrow(/Refusing to start/);
        expect(() => assertProductionConfig(config({}), "staging")).toThrow(/Refusing to start/);
    });

    it("refuses a URL that would put wrong addresses into certificates", () => {
        for (const url of ["http://acme.rapidmx.io", "https://acme.rapidmx.io/base", "https://user:pw@acme.rapidmx.io", "https://acme.rapidmx.io?x=1", "https://acme.rapidmx.io#f", "not a url", "", undefined]) {
            expect(() => assertProductionConfig(config({ ...good, "acme:external_url": url }), "production"), String(url)).toThrow(/external_url/);
        }
    });

    it("requires an SMTP relay (a URL or a host) and DKIM signing of the verification e-mail", () => {
        expect(() => assertProductionConfig(config({ ...good, "acme:mail:smtp:url": "" }), "production")).toThrow(/SMTP relay/);
        expect(() => assertProductionConfig(config({ ...good, "acme:mail:smtp:url": undefined, "acme:mail:smtp:host": "smtp.example.org" }), "production")).not.toThrow();
        expect(() => assertProductionConfig(config({ ...good, "acme:mail:dkim:domain": "" }), "production")).toThrow(/DKIM/);
        expect(() => assertProductionConfig(config({ ...good, "acme:mail:dkim:selector": undefined }), "production")).toThrow(/DKIM/);
        expect(() => assertProductionConfig(config({ ...good, "acme:mail:dkim:private_key_path": "" }), "production")).toThrow(/DKIM/);
        expect(() => assertProductionConfig(config({ ...good, "acme:mail:dkim:private_key_path": "", "acme:mail:dkim:private_key": "-----BEGIN PRIVATE KEY-----" }), "production")).not.toThrow();
        // Several problems are reported together, so an operator fixes them in one pass.
        expect(() => assertProductionConfig(config({}), "production")).toThrow(/external_url.*mail:from.*SMTP relay.*DKIM/s);
    });

    it("refuses placeholder challenge addresses", () => {
        for (const value of ["acme-challenge@localhost", "acme-challenge@acme.localdomain", "x@host.local", "nonsense", "", undefined, "a b@x.io"]) {
            expect(() => assertProductionConfig(config({ ...good, "acme:mail:from": value }), "production"), String(value)).toThrow(/mail:from/);
            expect(() => assertProductionConfig(config({ ...good, "acme:mail:reply_to": value }), "production"), String(value)).toThrow(/mail:reply_to/);
        }
    });
});
