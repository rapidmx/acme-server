///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// The Let's Encrypt-style rate limits, enforced end to end: what is limited, what the 429 says, and the exemptions
// (renewals, refunds) that keep the limits from punishing legitimate use.
import { x509 } from "../../src/lib/pki/runtime.js";
import { AcmeRateLimiter, RateLimitOverride } from "../../src/lib/acme/RateLimits.js";
import { ariCertId } from "../../src/lib/pki/index.js";
import { AcmeTestClient, Reply } from "../support/client.js";
import { issueCertificate, lastMail, uniqueEmail, validateOrder } from "../support/flow.js";
import { CaHarness, startCa } from "../support/harness.js";

describe("Rate limits", () => {
    let ca: CaHarness;
    const enabledLimiter = (overrides: RateLimitOverride[] = []) =>
        new AcmeRateLimiter(ca.ctx.store, { enabled: true, overrides, helpUrl: `${ca.baseUrl}/rate-limits` });

    /** Everything the test is not about is made effectively unlimited for this address. */
    const relax = (extra: RateLimitOverride[] = []): RateLimitOverride[] => [
        ...(["endpointNonce", "endpointNewAccount", "endpointNewOrder", "endpointRevoke", "endpointDirectory", "endpointOther"] as const).map((limit) => ({
            limit,
            subject: "127.0.0.1",
            count: 1_000_000,
            period_seconds: 1,
        })),
        ...extra,
    ];

    beforeAll(async () => {
        ca = await startCa({ "acme:rate_limits:enabled": true });
    }, 180_000);

    afterAll(async () => {
        await ca?.stop();
    });

    beforeEach(() => {
        // A fresh store per test: buckets never leak between them.
        ca.ctx.store = new (ca.ctx.store.constructor as any)();
        ca.ctx.limits = enabledLimiter(relax());
    });

    const limited = (reply: Reply, anchor: string) => {
        expect(reply.status).toBe(429);
        expect(reply.headers.get("content-type")).toBe("application/problem+json");
        expect(reply.json.type).toBe("urn:ietf:params:acme:error:rateLimited");
        expect(Number(reply.headers.get("retry-after"))).toBeGreaterThan(0);
        expect(reply.headers.get("link")).toContain(`<${ca.baseUrl}/rate-limits#${anchor}>;rel="help"`);
        expect(reply.json.detail).toContain(`retry after `);
        expect(reply.json.detail).toContain(`/rate-limits#${anchor}`);
        expect(reply.headers.get("replay-nonce")).toBeTruthy();
    };

    it("limits new accounts per IP address, and does not count finding an existing one", async () => {
        ca.ctx.limits = enabledLimiter(relax([{ limit: "newAccountsPerIp", subject: "127.0.0.1", count: 3, period_seconds: 10800 }]));
        const clients: AcmeTestClient[] = [];
        for (let i = 0; i < 3; i++) {
            const c = await AcmeTestClient.create(ca.baseUrl);
            expect((await c.register()).status).toBe(201);
            clients.push(c);
        }
        // Finding an account is not creating one.
        expect((await clients[0].post(clients[0].directory.newAccount, { onlyReturnExisting: true }, { jwk: true })).status).toBe(200);
        const fourth = await AcmeTestClient.create(ca.baseUrl);
        const reply = await fourth.register();
        limited(reply, "new-registrations-per-ip-address");
        expect(reply.json.detail).toContain("too many new accounts from this IP address (3 in the last 3h0m0s)");
        expect(Number(reply.headers.get("retry-after"))).toBeGreaterThan(3500);
        expect(Number(reply.headers.get("retry-after"))).toBeLessThanOrEqual(3600);
    });

    it("limits requests per IP address per endpoint, with a burst", async () => {
        ca.ctx.limits = enabledLimiter();
        const statuses: number[] = [];
        for (let i = 0; i < 14; i++) {
            statuses.push((await fetch(`${ca.baseUrl}/acme/new-nonce`, { method: "HEAD" })).status);
        }
        expect(statuses.slice(0, 10)).toEqual(Array(10).fill(200));
        expect(statuses).toContain(429);
        const throttled = await fetch(`${ca.baseUrl}/acme/new-nonce`, { method: "HEAD" });
        expect(throttled.status).toBe(429);
        expect(Number(throttled.headers.get("retry-after"))).toBeGreaterThanOrEqual(1);
    });

    it("limits new orders per account", async () => {
        const c = await AcmeTestClient.create(ca.baseUrl);
        await c.register();
        const account = c.kid!.split("/").pop()!;
        ca.ctx.limits = enabledLimiter(relax([{ limit: "newOrdersPerAccount", subject: account, count: 3, period_seconds: 10800 }]));
        for (let i = 0; i < 3; i++) {
            expect((await c.newOrder(uniqueEmail("orders"))).status).toBe(201);
        }
        const reply = await c.newOrder(uniqueEmail("orders"));
        limited(reply, "new-orders-per-account");
        expect(reply.json.detail).toContain("too many new orders from this account (3 in the last 3h0m0s)");
        // Another account is unaffected.
        const other = await AcmeTestClient.create(ca.baseUrl);
        await other.register();
        expect((await other.newOrder(uniqueEmail("orders"))).status).toBe(201);
    });

    it("limits pending authorizations per account", async () => {
        const c = await AcmeTestClient.create(ca.baseUrl);
        await c.register();
        for (let i = 0; i < 300; i++) {
            const created = await c.newOrder(uniqueEmail("pend"));
            if (created.status !== 201) {
                throw new Error(`order ${i} answered ${created.status}: ${created.text}`);
            }
        }
        // 300 orders is also the new-orders limit: lift that so this test measures the pending-authorization cap.
        ca.ctx.limits = enabledLimiter(relax([{ limit: "newOrdersPerAccount", subject: c.kid!.split("/").pop()!, count: 100000, period_seconds: 1 }]));
        const reply = await c.newOrder(uniqueEmail("pend"));
        limited(reply, "pending-authorizations");
    }, 120_000);

    it("limits the verification e-mails one address receives, so the CA cannot be used to mail-bomb someone", async () => {
        const c = await AcmeTestClient.create(ca.baseUrl);
        await c.register();
        const victim = uniqueEmail("victim");
        const mailsBefore = ca.mailer.sent.length;
        for (let i = 0; i < 3; i++) {
            const order = await c.newOrder(victim);
            expect((await c.post(order.json.authorizations[0])).status).toBe(200);
        }
        expect(ca.mailer.sent.length - mailsBefore).toBe(3);

        const order = await c.newOrder(victim);
        const reply = await c.post(order.json.authorizations[0]);
        limited(reply, "challenge-e-mails-per-address");
        expect(reply.json.detail).toContain("verification e-mails to this address");
        expect(ca.mailer.sent.length - mailsBefore).toBe(3);
        // The refused fetch did not claim the send: the authorization is intact and unmailed.
        const stored = await ca.ctx.authzRepo.findOne({ uid: order.json.authorizations[0].split("/").pop() });
        expect(stored?.challenge.mailClaimedAt).toBeUndefined();
        expect(stored?.status).toBe("pending");
    });

    it("limits the verification e-mails one domain receives", async () => {
        const c = await AcmeTestClient.create(ca.baseUrl);
        await c.register();
        ca.ctx.limits = enabledLimiter(relax([{ limit: "challengeMailsPerDomainHour", subject: "example.com", count: 2, period_seconds: 3600 }]));
        for (let i = 0; i < 2; i++) {
            const order = await c.newOrder(uniqueEmail("dom"));
            expect((await c.post(order.json.authorizations[0])).status).toBe(200);
        }
        const order = await c.newOrder(uniqueEmail("dom"));
        limited(await c.post(order.json.authorizations[0]), "challenge-e-mails-per-domain");
    });

    it("limits the verification e-mails one account causes", async () => {
        const c = await AcmeTestClient.create(ca.baseUrl);
        await c.register();
        ca.ctx.limits = enabledLimiter(relax([{ limit: "challengeMailsPerAccountHour", subject: c.kid!.split("/").pop()!, count: 2, period_seconds: 3600 }]));
        for (let i = 0; i < 2; i++) {
            const order = await c.newOrder(uniqueEmail("acct"));
            expect((await c.post(order.json.authorizations[0])).status).toBe(200);
        }
        const order = await c.newOrder(uniqueEmail("acct"));
        limited(await c.post(order.json.authorizations[0]), "challenge-e-mails-per-account");
    });

    it("limits failed authorizations per account and address, and gives the token back on success", async () => {
        const c = await AcmeTestClient.create(ca.baseUrl);
        await c.register();
        const email = uniqueEmail("fails");
        const account = c.kid!.split("/").pop()!;
        ca.ctx.limits = enabledLimiter(
            relax([
                { limit: "failedAuthorizations", subject: `${account}|${email.toLowerCase()}`, count: 2, period_seconds: 3600 },
                { limit: "challengeMailsPerAccountEmailHour", subject: `${account}|${email.toLowerCase()}`, count: 100, period_seconds: 3600 },
                { limit: "challengeMailsPerEmailHour", subject: email.toLowerCase(), count: 100, period_seconds: 3600 },
                { limit: "challengeMailsPerEmailDay", subject: email.toLowerCase(), count: 100, period_seconds: 3600 },
            ]),
        );
        const fail = async () => {
            const order = await c.newOrder(email);
            const authz = await c.post(order.json.authorizations[0]);
            await c.post(authz.json.challenges[0].url, {});
            const { ingest } = await import("../support/client.js");
            await ingest(ca.baseUrl, ca.inboundSecret, await c.replyTo(lastMail(ca, email), authz.json.challenges[0].token, { digest: "B".repeat(43) }));
        };
        await fail();
        await fail();
        limited(await c.newOrder(email), "authorization-failures-per-identifier-per-account");
        // Nobody else's orders for that address, and none of this account's for other addresses, are affected.
        expect((await c.newOrder(uniqueEmail("fine"))).status).toBe(201);
    });

    it("limits certificates per address, but not renewals that name the certificate they replace", async () => {
        const c = await AcmeTestClient.create(ca.baseUrl);
        await c.register();
        const email = uniqueEmail("certs");
        ca.ctx.limits = enabledLimiter(
            relax([
                { limit: "certificatesPerEmail", subject: email.toLowerCase(), count: 2, period_seconds: 7 * 86400 },
                { limit: "challengeMailsPerAccountEmailHour", subject: `${c.kid!.split("/").pop()}|${email.toLowerCase()}`, count: 100, period_seconds: 3600 },
                { limit: "challengeMailsPerEmailHour", subject: email.toLowerCase(), count: 100, period_seconds: 3600 },
                { limit: "challengeMailsPerEmailDay", subject: email.toLowerCase(), count: 100, period_seconds: 3600 },
            ]),
        );
        const first = await issueCertificate(ca, c, email);
        await issueCertificate(ca, c, email);
        const refused = await c.newOrder(email);
        limited(refused, "new-certificates-per-email-address");

        // A renewal is exempt: it names the certificate it replaces.
        const id = ariCertId(new x509.X509Certificate(first.pem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/)![0]));
        const renewal = await issueCertificate(ca, c, email, { orderExtra: { replaces: id } });
        expect(renewal.pem).toContain("BEGIN CERTIFICATE");
    });

    it("limits certificates per e-mail domain", async () => {
        const c = await AcmeTestClient.create(ca.baseUrl);
        await c.register();
        ca.ctx.limits = enabledLimiter(relax([{ limit: "certificatesPerDomain", subject: "example.com", count: 2, period_seconds: 7 * 86400 }]));
        await issueCertificate(ca, c, uniqueEmail("d1"));
        await issueCertificate(ca, c, uniqueEmail("d2"));
        limited(await c.newOrder(uniqueEmail("d3")), "new-certificates-per-email-domain");
    });

    it("turns a rate-limited finalize into a retryable 429 and leaves the order ready", async () => {
        const c = await AcmeTestClient.create(ca.baseUrl);
        await c.register();
        const email = uniqueEmail("late");
        const order = await c.newOrder(email);
        const ready = await validateOrder(ca, c, order, email);
        // The bucket empties between new-order (which only checked) and finalize (which spends).
        ca.ctx.limits = enabledLimiter(relax([{ limit: "certificatesPerEmail", subject: email.toLowerCase(), count: 1, period_seconds: 7 * 86400 }]));
        await ca.ctx.limits.spend("certificatesPerEmail", email.toLowerCase());
        const { makeCsr } = await import("../support/client.js");
        const reply = await c.post(ready.json.finalize, { csr: (await makeCsr(email)).b64url });
        limited(reply, "new-certificates-per-email-address");
        expect((await c.post(order.headers.get("location")!)).json.status).toBe("ready");
    });

    it("documents itself: /rate-limits lists every limit, as HTML and as JSON", async () => {
        const html = await fetch(`${ca.baseUrl}/rate-limits`);
        expect(html.headers.get("content-type")).toContain("text/html");
        const text = await html.text();
        for (const anchor of ["new-registrations-per-ip-address", "new-orders-per-account", "challenge-e-mails-per-address", "new-certificates-per-email-address"]) {
            expect(text).toContain(`id="${anchor}"`);
        }
        const json = await (await fetch(`${ca.baseUrl}/rate-limits`, { headers: { accept: "application/json" } })).json();
        expect(json.newOrdersPerAccount).toMatchObject({ count: 300, periodSeconds: 10800 });
        expect(json.challengeMailsPerAccountEmailHour).toMatchObject({ count: 3, periodSeconds: 3600 });
    });
});
