///////////////////////////////////////////////////////////////////////////////
// Security review (a check that the code is SAFE): with no trusted proxy configured, X-Forwarded-For / X-Real-IP must not let a
// client choose the address its per-IP bucket is keyed on. Passes against the current code.
///////////////////////////////////////////////////////////////////////////////
import { AcmeRateLimiter } from "../../src/lib/acme/RateLimits.js";
import { CaHarness, startCa } from "../support/harness.js";

describe("Review: per-IP buckets cannot be dodged with forwarding headers when no proxy is trusted", () => {
    let ca: CaHarness;
    beforeAll(async () => {
        ca = await startCa({ "acme:rate_limits:enabled": true });
    }, 180_000);
    afterAll(async () => {
        await ca?.stop();
    });

    it("keys the bucket on the socket address whatever X-Forwarded-For says", async () => {
        ca.ctx.limits = new AcmeRateLimiter(ca.ctx.store, {
            enabled: true,
            overrides: [{ limit: "endpointDirectory", subject: "127.0.0.1", count: 1, period_seconds: 3600 }],
        });
        const statuses: number[] = [];
        for (let i = 0; i < 4; i++) {
            const reply = await fetch(`${ca.baseUrl}/directory`, { headers: { "x-forwarded-for": `203.0.113.${i + 1}`, "x-real-ip": `198.51.100.${i + 1}` } });
            statuses.push(reply.status);
            await reply.text();
        }
        expect(statuses).toEqual([200, 429, 429, 429]);
    });
});
