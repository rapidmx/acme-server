///////////////////////////////////////////////////////////////////////////////
// Security review: sendChallengeMail() CHECKS the budgets, then CLAIMS the send, then SPENDS the budgets. The spend can still
// be refused (two authorizations for the same address checked before either spent), and it is not inside the try/catch that
// releases the claim - so the loser keeps `mailClaimedAt`, never gets a mail, and every later fetch returns 200 without
// sending one. The authorization is dead until it expires (7 days).
///////////////////////////////////////////////////////////////////////////////
import { AcmeRateLimiter, RateLimitOverride } from "../../src/lib/acme/RateLimits.js";
import { AcmeTestClient } from "../support/client.js";
import { uniqueEmail } from "../support/flow.js";
import { CaHarness, startCa } from "../support/harness.js";

describe("Review: check/claim/spend race in sendChallengeMail", () => {
    let ca: CaHarness;
    const limiter = (extra: RateLimitOverride[] = []) =>
        new AcmeRateLimiter(ca.ctx.store, {
            enabled: true,
            overrides: [
                ...(["endpointNonce", "endpointNewAccount", "endpointNewOrder", "endpointRevoke", "endpointDirectory", "endpointOther", "newAccountsPerIp"] as const).map((limit) => ({
                    limit,
                    subject: "127.0.0.1",
                    count: 1_000_000,
                    period_seconds: 1,
                })),
                ...extra,
            ],
        });

    beforeAll(async () => {
        ca = await startCa({ "acme:rate_limits:enabled": true });
    }, 180_000);
    afterAll(async () => {
        await ca?.stop();
    });

    it("never leaves an authorization claimed-but-unmailed when the budget refuses the send, and a later fetch still mails it", async () => {
        const target = uniqueEmail("race");
        ca.ctx.limits = limiter([{ limit: "challengeMailsPerEmailHour", subject: target, count: 1, period_seconds: 3600 }]);

        const clients: AcmeTestClient[] = [];
        const authzUrls: string[] = [];
        for (let i = 0; i < 4; i++) {
            const c = await AcmeTestClient.create(ca.baseUrl);
            await c.register();
            const order = await c.newOrder(target);
            expect(order.status).toBe(201);
            clients.push(c);
            authzUrls.push(order.json.authorizations[0]);
        }
        const before = ca.mailer.sent.filter((m) => m.to === target).length;
        // Four accounts fetch their authorization for the same address at the same moment; the budget allows one mail.
        const replies = await Promise.all(clients.map((c, i) => c.post(authzUrls[i])));
        console.log("statuses:", replies.map((r) => r.status).join(","));
        const mailed = ca.mailer.sent.filter((m) => m.to === target).length - before;
        expect(mailed).toBe(1);

        const stored = await Promise.all(authzUrls.map((u) => ca.ctx.authzRepo.findOne({ uid: u.split("/").pop() })));
        const claimedWithoutMail = stored.filter((a) => a?.challenge.mailClaimedAt && !a.challenge.mailSentAt);
        console.log("claimed but never mailed:", claimedWithoutMail.length);
        expect(claimedWithoutMail.length).toBe(0);

        // The budget refills (fresh store); the refused clients retry as the 429's Retry-After told them to.
        ca.ctx.store = new (ca.ctx.store.constructor as any)();
        ca.ctx.limits = limiter();
        for (let i = 0; i < clients.length; i++) {
            if (replies[i].status !== 200) {
                const retry = await clients[i].post(authzUrls[i]);
                expect(retry.status).toBe(200);
            }
        }
        expect(ca.mailer.sent.filter((m) => m.to === target).length - before).toBe(clients.length);
    }, 120_000);
});
