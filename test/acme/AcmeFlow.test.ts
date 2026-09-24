///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// The happy path, end to end over real HTTP against the real server: directory, nonce, account, order, the
// email-reply-00 challenge through a DKIM-signed reply, finalize with a CSR, and the certificate that comes back.
import { X509Certificate } from "crypto";
import { AcmeTestClient } from "../support/client.js";
import { CaHarness, startCa } from "../support/harness.js";
import { issueCertificate } from "../support/flow.js";

describe("ACME: issuing a certificate", () => {
    let ca: CaHarness;

    beforeAll(async () => {
        ca = await startCa();
    }, 180_000);

    afterAll(async () => {
        await ca?.stop();
    });

    it("publishes a directory with every endpoint, the terms and the profiles", async () => {
        const client = await AcmeTestClient.create(ca.baseUrl);
        expect(client.directory).toMatchObject({
            newNonce: `${ca.baseUrl}/acme/new-nonce`,
            newAccount: `${ca.baseUrl}/acme/new-acct`,
            newOrder: `${ca.baseUrl}/acme/new-order`,
            revokeCert: `${ca.baseUrl}/acme/revoke-cert`,
            keyChange: `${ca.baseUrl}/acme/key-change`,
            renewalInfo: `${ca.baseUrl}/acme/renewal-info`,
        });
        expect(client.directory.meta.termsOfService).toBe(`${ca.baseUrl}/terms`);
        expect(client.directory.meta.externalAccountRequired).toBe(false);
        expect(Object.keys(client.directory.meta.profiles)).toEqual(["signing", "encryption", "signing-encryption"]);
    });

    it("issues a signing certificate for an e-mail address", async () => {
        const client = await AcmeTestClient.create(ca.baseUrl);
        const account = await client.register();
        expect(account.status).toBe(201);
        expect(account.json).toMatchObject({ status: "valid", contact: ["mailto:owner@example.com"] });

        const issued = await issueCertificate(ca, client, "alice@example.com");
        const leaf = new X509Certificate(issued.pem);
        expect(leaf.subjectAltName).toBe("email:alice@example.com");
        expect(issued.pem.match(/BEGIN CERTIFICATE/g)).toHaveLength(2);
        const issuer = new X509Certificate(issued.pem.split("-----END CERTIFICATE-----")[1].trim() + "\n-----END CERTIFICATE-----\n");
        expect(leaf.verify(issuer.publicKey)).toBe(true);
    });
});
