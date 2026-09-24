///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Internationalized addresses (RFC 6531 / 8398 / 8399 / 8823) through the whole ACME flow: the order, the verification e-mail, a reply
// that spells the domain as U-labels while its DKIM signature says A-labels, and a certificate carrying an SmtpUTF8Mailbox.
import { AsnConvert } from "@peculiar/asn1-schema";
import { Certificate, SubjectAlternativeName } from "@peculiar/asn1-x509";
import { readDerUtf8String } from "../../src/lib/pki/index.js";
import { AcmeTestClient, ingest, makeCsr, Reply } from "../support/client.js";
import { lastMail } from "../support/flow.js";
import { CaHarness, idnDkim, startCa } from "../support/harness.js";

/** The ASCII (A-label) form the CA canonicalizes bücher.com to. */
const IDN = "xn--bcher-kva.com";

describe("SMTPUTF8 addresses", () => {
    let ca: CaHarness;
    let client: AcmeTestClient;

    beforeAll(async () => {
        ca = await startCa();
        client = await AcmeTestClient.create(ca.baseUrl);
        await client.register();
    }, 180_000);

    afterAll(async () => {
        await ca?.stop();
    });

    const problem = (reply: Reply, type: string) => {
        expect(reply.json?.type).toBe(`urn:ietf:params:acme:error:${type}`);
    };

    /** Orders `address`, answers the verification e-mail from `from` (signed for bücher.com) and returns the ready order. */
    const validated = async (address: string, from: string) => {
        const created = await client.newOrder(address);
        expect(created.status).toBe(201);
        const authz = await client.post(created.json.authorizations[0]);
        const challenge = authz.json.challenges[0];
        const mail = lastMail(ca, created.json.identifiers[0].value);
        const reply = await client.replyTo(mail, challenge.token, { from, dkimKey: idnDkim });
        expect((await ingest(ca.baseUrl, ca.inboundSecret, reply)).status).toBe(202);
        await client.post(challenge.url, {});
        const ready = await client.post(created.headers.get("location")!);
        return { created, mail, ready };
    };

    const sanOf = (pem: string) => {
        const der = Buffer.from(pem.match(/-----BEGIN CERTIFICATE-----([^-]+)-----END CERTIFICATE-----/)![1].replace(/\s/g, ""), "base64");
        const certificate = AsnConvert.parse(der, Certificate);
        const extension = certificate.tbsCertificate.extensions!.find((e) => e.extnID === "2.5.29.17")!;
        return AsnConvert.parse(extension.extnValue.buffer, SubjectAlternativeName);
    };

    it("issues a certificate with an SmtpUTF8Mailbox for a non-ASCII local part at an IDN domain", async () => {
        const { created, mail, ready } = await validated("用户@bücher.com", "用户@bücher.com");
        // The order and the authorization carry the canonical form: the domain as A-labels.
        expect(created.json.identifiers).toEqual([{ type: "email", value: `用户@${IDN}` }]);
        expect(mail.to).toBe(`用户@${IDN}`);
        expect(mail.raw).toContain("To: 用户@bücher.com");
        expect(ready.json.status).toBe("ready");

        const csr = await makeCsr("用户@bücher.com", { smtpUtf8: "用户@bücher.com" });
        const finalized = await client.post(ready.json.finalize, { csr: csr.b64url });
        expect(finalized.status).toBe(200);
        const pem = (await client.post(finalized.json.certificate)).text;
        const names = sanOf(pem);
        expect(names).toHaveLength(1);
        expect(names[0].rfc822Name).toBeUndefined();
        expect(readDerUtf8String(new Uint8Array(names[0].otherName!.value))).toBe("用户@bücher.com");
    });

    it("accepts the same order when the CSR spells the domain as A-labels", async () => {
        const { ready } = await validated("用户2@bücher.com", `用户2@${IDN}`);
        const csr = await makeCsr("x@x.com", { smtpUtf8: `用户2@${IDN}` });
        expect((await client.post(ready.json.finalize, { csr: csr.b64url })).status).toBe(200);
    });

    it("issues an rfc822Name with A-labels for an ASCII local part at an IDN domain", async () => {
        const { created, ready } = await validated("user@bücher.com", "user@bücher.com");
        expect(created.json.identifiers[0].value).toBe(`user@${IDN}`);
        const csr = await makeCsr(`user@${IDN}`);
        const finalized = await client.post(ready.json.finalize, { csr: csr.b64url });
        expect(finalized.status).toBe(200);
        const names = sanOf((await client.post(finalized.json.certificate)).text);
        expect(names[0].otherName).toBeUndefined();
        expect(names[0].rfc822Name).toBe(`user@${IDN}`);
    });

    it("refuses a CSR for a different mailbox, or an rfc822Name for a non-ASCII local part", async () => {
        const { ready } = await validated("用户3@bücher.com", "用户3@bücher.com");
        problem(await client.post(ready.json.finalize, { csr: (await makeCsr("x@x.com", { smtpUtf8: "用户4@bücher.com" })).b64url }), "badCSR");
        // An rfc822Name cannot carry a non-ASCII local part (IA5String): the CSR must use the otherName.
        problem(await client.post(ready.json.finalize, { csr: (await makeCsr("用户3@bücher.com")).b64url }), "badCSR");
        expect((await client.post(ready.json.finalize, { csr: (await makeCsr("x@x.com", { smtpUtf8: "用户3@bücher.com" })).b64url })).status).toBe(200);
    });

    it("does not accept a reply from a look-alike address (a different local part, or a decomposed spelling)", async () => {
        const created = await client.newOrder("ålice@bücher.com");
        const authz = await client.post(created.json.authorizations[0]);
        const challenge = authz.json.challenges[0];
        const mail = lastMail(ca, created.json.identifiers[0].value);
        for (const from of ["alice@bücher.com", "ålice@bücher.com"]) {
            await ingest(ca.baseUrl, ca.inboundSecret, await client.replyTo(mail, challenge.token, { from, dkimKey: idnDkim }));
        }
        await client.post(challenge.url, {});
        expect((await client.post(created.json.authorizations[0])).json.status).toBe("pending");
        await ingest(ca.baseUrl, ca.inboundSecret, await client.replyTo(mail, challenge.token, { from: "ÅLICE@BÜCHER.com", dkimKey: idnDkim }));
        expect((await client.post(created.json.authorizations[0])).json.status).toBe("valid");
    });

    it("rejects malformed internationalized identifiers, and reserved domains in U-label form", async () => {
        for (const value of ["ålice@bücher.com", "al​ice@bücher.com", "ålice@ｂücher.com", "ålice@xn--a.com"]) {
            const reply = await client.newOrder(value);
            expect(reply.status, value).toBe(400);
            problem(reply, "malformed");
        }
        problem(await client.newOrder("ålice@bücher.test"), "rejectedIdentifier");
    });

    it("looks the domain up in DNS by its A-label name", async () => {
        const seen: string[] = [];
        const original = ca.ctx.dns.assertDeliverable.bind(ca.ctx.dns);
        ca.ctx.dns.assertDeliverable = async (domain: string) => {
            seen.push(domain);
            return await original(domain);
        };
        try {
            await client.newOrder("用户@bücher.com");
        } finally {
            ca.ctx.dns.assertDeliverable = original;
        }
        expect(seen).toEqual([IDN]);
    });
});
