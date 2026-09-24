///////////////////////////////////////////////////////////////////////////////
// Security review: the challenge-mail budgets (per address, per domain) are shared by every account, and a budget is spent
// merely by ORDERING and FETCHING an authorization for an address - the mailbox never has to answer, or even exist.
// So one anonymous throw-away account can lock every other applicant at a domain (or one specific person) out of getting a
// verification e-mail. These tests assert the behaviour a victim would need; they fail against the current code.
///////////////////////////////////////////////////////////////////////////////
import { AcmeRateLimiter, RateLimitOverride } from "../../src/lib/acme/RateLimits.js";
import { AcmeTestClient } from "../support/client.js";
import { uniqueEmail } from "../support/flow.js";
import { CaHarness, startCa } from "../support/harness.js";

describe("Review: cross-account exhaustion of the challenge-mail budgets", () => {
    let ca: CaHarness;

    /** Default limits everywhere except the per-IP request throttles (the tests run from one address). */
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
            helpUrl: `${ca.baseUrl}/rate-limits`,
        });

    beforeAll(async () => {
        ca = await startCa({ "acme:rate_limits:enabled": true });
    }, 180_000);
    afterAll(async () => {
        await ca?.stop();
    });
    beforeEach(() => {
        ca.ctx.store = new (ca.ctx.store.constructor as any)();
        ca.ctx.limits = limiter();
    });

    async function account(): Promise<AcmeTestClient> {
        const c = await AcmeTestClient.create(ca.baseUrl);
        expect((await c.register()).status).toBe(201);
        return c;
    }

    it("one throw-away account cannot use up the verification-mail budget of a whole domain for everybody else", async () => {
        const attacker = await account();
        // 60/h is the per-domain default (and, conveniently, the per-account default): the attacker orders 60 addresses that do
        // not exist and merely fetches each authorization. No mailbox ever answers.
        let sent = 0;
        for (let i = 0; i < 60; i++) {
            const order = await attacker.newOrder(uniqueEmail("ghost"));
            const fetched = await attacker.post(order.json.authorizations[0]);
            if (fetched.status === 200) {
                sent++;
            }
        }
        expect(sent).toBe(60);

        // A different person at the same domain, with a different account, asks for a certificate for their own address.
        const victim = await account();
        const order = await victim.newOrder(uniqueEmail("real-user"));
        const fetched = await victim.post(order.json.authorizations[0]);
        expect(fetched.status).toBe(200); // currently 429: "too many verification e-mails to addresses at this domain"
    }, 180_000);

    it("one account cannot lock a specific person out of getting their verification e-mail", async () => {
        const target = uniqueEmail("target");
        const attacker = await account();
        // 3 per hour to one address, from anybody: the attacker spends all of it without owning the mailbox.
        for (let i = 0; i < 3; i++) {
            const order = await attacker.newOrder(target);
            expect((await attacker.post(order.json.authorizations[0])).status).toBe(200);
        }
        const owner = await account();
        const order = await owner.newOrder(target);
        const fetched = await owner.post(order.json.authorizations[0]);
        expect(fetched.status).toBe(200); // currently 429: the legitimate owner cannot get a challenge mail for the next hour(s)
    }, 60_000);
});
