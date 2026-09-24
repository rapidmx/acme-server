///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Interoperability with an ACME client this project did not write: the `acme-client` package, driven exactly the way
// `Rfc8823AcmeSigningCertificateEnrollment` in @rapidmx/restapi drives it (createOrder, getAuthorizations, the reply e-mail's
// digest from getChallengeKeyAuthorization with a spoofed http-01 challenge, completeChallenge, finalizeOrder, getCertificate).
import { createHash, X509Certificate } from "crypto";
import * as acme from "acme-client";
import { ingest, makeCsr } from "../support/client.js";
import { CaHarness, applicantDkim, startCa } from "../support/harness.js";
import { lastMail, uniqueEmail } from "../support/flow.js";
import { composeGenuineReply } from "../lib/mail/helpers.js";

describe("Interoperability with acme-client", () => {
    let ca: CaHarness;
    let client: acme.Client;
    let accountKey: Buffer;

    beforeAll(async () => {
        ca = await startCa();
        accountKey = await acme.crypto.createPrivateEcdsaKey("P-256");
        client = new acme.Client({ directoryUrl: `${ca.baseUrl}/directory`, accountKey });
        await client.createAccount({ termsOfServiceAgreed: true, contact: ["mailto:ops@example.com"] });
    }, 180_000);

    afterAll(async () => {
        await ca?.stop();
    });

    const pemToDer = (pem: string): Buffer => Buffer.from(pem.replace(/-----[A-Z ]+-----|\s/g, ""), "base64");

    /** acme-client wants the CSR as PEM. */
    const csrPem = (der: Uint8Array): string =>
        `-----BEGIN CERTIFICATE REQUEST-----\n${Buffer.from(der).toString("base64").match(/.{1,64}/g)!.join("\n")}\n-----END CERTIFICATE REQUEST-----\n`;

    /** The applicant side of RFC 8823, as the RapidMX server does it. */
    const answerChallenge = async (email: string, challenge: any): Promise<void> => {
        const mail = lastMail(ca, email);
        // token = token-part1 || token-part2; acme-client only knows how to build key authorizations for http-01, and for that
        // type the key authorization is exactly token "." thumbprint - which is what RFC 8823 §3 hashes.
        const keyAuthorization: string = await client.getChallengeKeyAuthorization({
            type: "http-01",
            url: challenge.url,
            status: "pending",
            token: mail.tokenPart1 + challenge.token,
        } as any);
        const digest = createHash("sha256").update(keyAuthorization).digest("base64url");
        const reply = await composeGenuineReply(
            { identity: email, replyTo: mail.replyTo, challengeSubject: mail.subject, challengeMessageId: mail.messageId, digest },
            { key: applicantDkim },
        );
        expect((await ingest(ca.baseUrl, ca.inboundSecret, reply)).status).toBe(202);
        await client.completeChallenge(challenge);
        await client.waitForValidStatus(challenge);
    };

    it("issues a certificate through the complete RapidMX enrollment sequence", async () => {
        const email = uniqueEmail("interop");
        const order = await client.createOrder({ identifiers: [{ type: "email", value: email }] });
        expect(order.status).toBe("pending");

        const [authorization] = await client.getAuthorizations(order);
        expect(authorization.identifier).toEqual({ type: "email", value: email });
        const challenge: any = (authorization.challenges as any[]).find((c) => c.type === "email-reply-00");
        expect(challenge).toBeDefined();
        expect(challenge.from).toBe("acme-challenge@acme.rapidmx.test");
        expect(challenge.token).toBeTruthy();
        expect(challenge.url).toBeTruthy();

        await answerChallenge(email, challenge);
        const ready = await client.getOrder(order);
        expect(ready.status).toBe("ready");

        const csr = await makeCsr(email, { type: "signing" });
        const finalized = await client.finalizeOrder(ready, csrPem(csr.der));
        expect(finalized.status).toBe("valid");
        const chain: string = await client.getCertificate(finalized);

        const [leaf, issuer] = chain.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g)!;
        const cert = new X509Certificate(leaf);
        expect(cert.subjectAltName).toBe(`email:${email}`);
        expect(cert.verify(new X509Certificate(issuer).publicKey)).toBe(true);
        expect(cert.checkEmail(email)).toBe(email);
        expect(cert.checkEmail("someone.else@example.com")).toBeUndefined();
        // The chain the CA serves verifies against the root it publishes.
        const roots = await (await fetch(`${ca.baseUrl}/ca/roots.pem`)).text();
        expect(new X509Certificate(issuer).verify(new X509Certificate(roots).publicKey)).toBe(true);
        expect(pemToDer(leaf).length).toBeGreaterThan(300);
    });

    it("issues an RSA encryption certificate the same way", async () => {
        const email = uniqueEmail("interop-enc");
        const order = await client.createOrder({ identifiers: [{ type: "email", value: email }] });
        const [authorization] = await client.getAuthorizations(order);
        await answerChallenge(email, (authorization.challenges as any[])[0]);
        const csr = await makeCsr(email, { type: "encryption", key: "rsa-2048" });
        const finalized = await client.finalizeOrder(await client.getOrder(order), csrPem(csr.der));
        const chain = await client.getCertificate(finalized);
        // Node reports the extended key usage as `keyUsage`: emailProtection and nothing else.
        expect(new X509Certificate(chain).keyUsage).toEqual(["1.3.6.1.5.5.7.3.4"]);
        expect(new X509Certificate(chain).publicKey.asymmetricKeyType).toBe("rsa");
    });

    it("rolls the account key over, updates the account, and deactivates it", async () => {
        const rolling = new acme.Client({ directoryUrl: `${ca.baseUrl}/directory`, accountKey: await acme.crypto.createPrivateEcdsaKey("P-384") });
        await rolling.createAccount({ termsOfServiceAgreed: true });
        const newKey = await acme.crypto.createPrivateEcdsaKey("P-256");
        await rolling.updateAccountKey(newKey);
        const updated: any = await rolling.updateAccount({ contact: ["mailto:rolled@example.com"] });
        expect(updated.contact).toEqual(["mailto:rolled@example.com"]);
        const gone: any = await rolling.updateAccount({ status: "deactivated" });
        expect(gone.status).toBe("deactivated");
    });

    it("revokes a certificate it obtained", async () => {
        const email = uniqueEmail("interop-rev");
        const order = await client.createOrder({ identifiers: [{ type: "email", value: email }] });
        const [authorization] = await client.getAuthorizations(order);
        await answerChallenge(email, (authorization.challenges as any[])[0]);
        const csr = await makeCsr(email);
        const chain = await client.getCertificate(await client.finalizeOrder(await client.getOrder(order), csrPem(csr.der)));
        await client.revokeCertificate(chain, { reason: 4 });
        const serial = new X509Certificate(chain).serialNumber.toLowerCase();
        const lookup = await (await fetch(`${ca.baseUrl}/certs/${serial}`, { headers: { accept: "application/json" } })).json();
        expect(lookup.status).toBe("revoked");
    });
});
