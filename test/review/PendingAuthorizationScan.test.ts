///////////////////////////////////////////////////////////////////////////////
// Security review: every new-order runs authzRepo.count({ accountUid, status: "pending", expires: { $gt: now } }).
// AcmeAuthorization has indexes on orderUid, status, expires, tokenHash and purgeAt - but not accountUid. So the per-account
// pending-authorization cap is enforced by examining every pending authorization of EVERY account: the work per new-order
// grows with the total number of pending authorizations, which anonymous accounts can create 300 at a time.
///////////////////////////////////////////////////////////////////////////////
import { randomBytes } from "node:crypto";
import { CaHarness, startCa } from "../support/harness.js";

describe("Review: the pending-authorization cap query", () => {
    let ca: CaHarness;
    beforeAll(async () => {
        ca = await startCa();
    }, 180_000);
    afterAll(async () => {
        await ca?.stop();
    });

    it("is answered from an index that starts at the account, not by examining other accounts' authorizations", async () => {
        const collection = ca.ctx.authzRepo.collection as any;
        const now = new Date();
        const future = new Date(now.getTime() + 86_400_000);
        const docs = Array.from({ length: 20_000 }, (_, i) => ({
            uid: randomBytes(16).toString("base64url"),
            accountUid: `other-account-${i % 200}`,
            orderUid: `o${i}`,
            status: "pending",
            expires: future,
            tokenHash: randomBytes(32).toString("hex"),
            challenge: { status: "pending" },
            purgeAt: future,
        }));
        await collection.insertMany(docs);

        const explain = await collection.find({ accountUid: "victim-account", status: "pending", expires: { $gt: now } }).explain("executionStats");
        const stats = explain.executionStats;
        console.log(`docs examined for an account that owns nothing: ${stats.totalDocsExamined}, keys examined: ${stats.totalKeysExamined}`);
        expect(stats.totalDocsExamined).toBeLessThan(300);
    }, 120_000);
});
