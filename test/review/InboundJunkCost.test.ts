///////////////////////////////////////////////////////////////////////////////
// Security review: handleInbound() parses the mail and verifies every DKIM signature - one DNS TXT query per DKIM-Signature
// header, aimed at names the sender chooses - BEFORE it looks the token up. Mail carrying an unknown (or no useful) token is
// junk and can be discarded for the price of one hash + one indexed query. Anyone who can reach the SMTP listener (or the
// bridge) can make the CA issue thousands of DNS queries and signature checks per message instead.
///////////////////////////////////////////////////////////////////////////////
import { createHash, randomBytes } from "node:crypto";
import { ingest } from "../support/client.js";
import { CaHarness, startCa } from "../support/harness.js";

function junkWithSignatures(count: number): Buffer {
    const body = "hello\r\n";
    const bh = createHash("sha256").update(body).digest("base64");
    const signatures = Array.from(
        { length: count },
        (_, i) => `DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=d${i}.victim-dns.example; s=k; h=from; bh=${bh}; b=${randomBytes(48).toString("base64")}\r\n`
    ).join("");
    return Buffer.from(
        signatures +
            "From: someone@junk.example\r\nTo: acme-response@acme.rapidmx.test\r\nSubject: ACME: " +
            randomBytes(32).toString("base64url") +
            "\r\nMessage-ID: <x@junk.example>\r\n\r\n" +
            body
    );
}

describe("Review: what unauthenticated junk mail costs the CA", () => {
    let ca: CaHarness;
    beforeAll(async () => {
        ca = await startCa();
    }, 180_000);
    afterAll(async () => {
        await ca?.stop();
    });

    it("does not query DNS for a message whose token belongs to no authorization", async () => {
        const queries: string[] = [];
        ca.ctx.dkimResolver = async (name: string, rr: string) => {
            queries.push(`${rr} ${name}`);
            throw Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" });
        };
        const raw = junkWithSignatures(300);
        console.log(`junk message: ${raw.length} bytes, 300 DKIM-Signature headers`);
        const started = Date.now();
        const answer = await ingest(ca.baseUrl, ca.inboundSecret, raw);
        console.log(`answered ${answer.status} after ${Date.now() - started} ms; DNS queries issued: ${queries.length}`);
        expect(answer.status).toBe(202);
        expect(queries.length).toBe(0);
    }, 120_000);
});
