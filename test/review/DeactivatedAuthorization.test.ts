///////////////////////////////////////////////////////////////////////////////
// Security review: a READY order is only re-derived from its authorizations while it is `pending` (OrderService.refresh), so an
// authorization that is deactivated after the order became ready no longer stops the finalize. RFC 8555 section 7.5.2: the
// client relinquishes its authorization to issue for the identifier. (Own account only: low severity, but it is a
// "revocation of proof that does not revoke".)
///////////////////////////////////////////////////////////////////////////////
import { AcmeTestClient, makeCsr } from "../support/client.js";
import { uniqueEmail, validateOrder } from "../support/flow.js";
import { CaHarness, startCa } from "../support/harness.js";

describe("Review: finalize after the authorization was deactivated", () => {
    let ca: CaHarness;
    beforeAll(async () => {
        ca = await startCa();
    }, 180_000);
    afterAll(async () => {
        await ca?.stop();
    });

    it("does not issue a certificate for an order whose authorization was deactivated", async () => {
        const c = await AcmeTestClient.create(ca.baseUrl);
        await c.register();
        const email = uniqueEmail("deact");
        const created = await c.newOrder(email);
        const ready = await validateOrder(ca, c, created, email);
        expect(ready.json.status).toBe("ready");

        const deactivated = await c.post(created.json.authorizations[0], { status: "deactivated" });
        expect(deactivated.json.status).toBe("deactivated");

        const csr = await makeCsr(email);
        const finalized = await c.post(ready.json.finalize, { csr: csr.b64url });
        console.log(`finalize after deactivation: ${finalized.status} ${finalized.json?.status}`);
        expect(finalized.json?.status).not.toBe("valid");
    }, 60_000);
});
