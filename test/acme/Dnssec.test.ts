///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// The CAA check with DNSSEC validation switched on: new-order and the re-check at finalize both go through the validator, and a
// failed validation refuses the order instead of falling back to the unvalidated answer.
import { AcmeTestClient, makeCsr, Reply } from "../support/client.js";
import { uniqueEmail, validateOrder } from "../support/flow.js";
import { CaHarness, dnsState, dnssecState, startCa } from "../support/harness.js";

describe("CAA with DNSSEC validation", () => {
    let ca: CaHarness;
    let client: AcmeTestClient;

    beforeAll(async () => {
        ca = await startCa({}, { dnssec: true });
        client = await AcmeTestClient.create(ca.baseUrl);
        await client.register();
    }, 180_000);

    afterAll(async () => {
        await ca?.stop();
    });

    beforeEach(() => {
        dnssecState.answers = {};
        dnssecState.failures = {};
        dnssecState.asked = [];
        dnsState.caa = {};
    });

    const problem = (reply: Reply, type: string) => {
        expect(reply.json?.type).toBe(`urn:ietf:params:acme:error:${type}`);
    };

    it("takes the CAA policy from the validator, never from the unvalidated resolver", async () => {
        // The unvalidated stub would forbid this; the validated answer allows it.
        dnsState.caa["signed.example.org"] = [{ critical: 0, issuemail: ";" }];
        dnssecState.answers["signed.example.org"] = { records: [{ critical: 0, tag: "issuemail", value: "rapidmx.io" }] };
        expect((await client.newOrder("user@signed.example.org")).status).toBe(201);
        expect(dnssecState.asked).toContain("signed.example.org");
    });

    it("refuses a domain whose validated policy does not name this CA", async () => {
        dnssecState.answers["strict.example.org"] = { records: [{ critical: 0, tag: "issuemail", value: "other-ca.example" }] };
        problem(await client.newOrder("user@strict.example.org"), "caa");
    });

    it("refuses when DNSSEC validation fails, and does not fall back to an unvalidated answer", async () => {
        dnssecState.failures["bogus.example.org"] = "bogus";
        problem(await client.newOrder("user@bogus.example.org"), "dns");
        dnssecState.failures["unknown.example.org"] = "indeterminate";
        problem(await client.newOrder("user@unknown.example.org"), "dns");
    });

    it("refuses when a parent zone's answer is bogus even though the domain's own is empty", async () => {
        dnssecState.failures["example.net"] = "bogus";
        problem(await client.newOrder("user@sub.example.net"), "dns");
    });

    it("accepts a domain in an unsigned zone", async () => {
        dnssecState.answers["unsigned.example.org"] = { records: [], insecure: true };
        expect((await client.newOrder("user@unsigned.example.org")).status).toBe(201);
    });

    it("re-checks with validation at finalize, and refuses issuance when validation then fails", async () => {
        const email = uniqueEmail("finalize");
        const order = await client.newOrder(email);
        expect(order.status).toBe(201);
        const ready = await validateOrder(ca, client, order, email);
        expect(ready.json.status).toBe("ready");
        dnssecState.failures["example.com"] = "bogus";
        problem(await client.post(ready.json.finalize, { csr: (await makeCsr(email)).b64url }), "dns");
    });
});
