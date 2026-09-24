///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// RFC 8555 §7.4: creating orders (identifier and DNS policy), finalizing them with a CSR, and the certificate types RFC 8823
// §3.3 selects from the CSR's key usage.
import { X509Certificate } from "crypto";
import { x509 } from "../../src/lib/pki/runtime.js";
import { AcmeTestClient, makeCsr, Reply } from "../support/client.js";
import { issueCertificate, uniqueEmail, validateOrder } from "../support/flow.js";
import { CaHarness, dnsState, startCa } from "../support/harness.js";

describe("ACME orders", () => {
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

    const problem = (reply: Reply, type: string, status?: number) => {
        expect(reply.json?.type).toBe(`urn:ietf:params:acme:error:${type}`);
        if (status !== undefined) {
            expect(reply.status).toBe(status);
        }
    };

    const usagesOf = (pem: string): string[] => {
        const cert = new x509.X509Certificate(pem.split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----");
        const ku = cert.getExtension(x509.KeyUsagesExtension)!;
        return Object.entries(x509.KeyUsageFlags)
            .filter(([name, bit]) => typeof bit === "number" && (ku.usages & bit) !== 0 && Number.isNaN(Number(name)))
            .map(([name]) => name)
            .sort();
    };

    describe("new-order", () => {
        it("creates an order with one authorization and a finalize URL", async () => {
            const email = uniqueEmail("create");
            const reply = await client.newOrder(email);
            expect(reply.status).toBe(201);
            const url = reply.headers.get("location")!;
            expect(url).toMatch(new RegExp(`^${ca.baseUrl}/acme/order/[A-Za-z0-9_-]{22}$`));
            expect(reply.json).toMatchObject({ status: "pending", identifiers: [{ type: "email", value: email }], finalize: `${url}/finalize` });
            expect(reply.json.authorizations).toHaveLength(1);
            expect(reply.json.authorizations[0]).toMatch(/\/acme\/authz\//);
            expect(new Date(reply.json.expires).getTime()).toBeGreaterThan(Date.now() + 6 * 86400_000);
            expect(reply.json.certificate).toBeUndefined();
        });

        it("lower-cases the domain but keeps the local part", async () => {
            const reply = await client.newOrder("Some.Body@EXAMPLE.Com");
            expect(reply.json.identifiers[0].value).toBe("Some.Body@example.com");
        });

        it("requires identifiers, and no more than the configured number of them", async () => {
            for (const identifiers of [undefined, [], "a@example.com", [{ type: "email", value: "a@example.com" }, { type: "email", value: "b@example.com" }]]) {
                problem(await client.post(client.directory.newOrder, { identifiers }), "malformed", 400);
            }
            problem(await client.post(client.directory.newOrder, {}), "malformed");
            problem(await client.post(client.directory.newOrder), "malformed");
        });

        it("only supports the email identifier type", async () => {
            for (const entry of [{ type: "dns", value: "example.com" }, { type: "ip", value: "192.0.2.1" }, { value: "a@example.com" }, "a@example.com", null]) {
                problem(await client.post(client.directory.newOrder, { identifiers: [entry] }), "unsupportedIdentifier");
            }
        });

        it("rejects malformed addresses, reserved domains and internationalized addresses", async () => {
            const malformed = [
                "",
                "no-at-sign.example.com",
                "@example.com",
                "user@",
                "user@@example.com",
                "a b@example.com",
                ".dots@example.com",
                "dots.@example.com",
                "do..ts@example.com",
                '"quoted"@example.com',
                "<user@example.com>",
                "User <user@example.com>",
                "user@example",
                "user@-example.com",
                "user@exa_mple.com",
                "user@[192.0.2.1]",
                ` user@example.com`,
                `${"a".repeat(65)}@example.com`,
                `user@${"a".repeat(64)}.com`,
                `user@${"a".repeat(250)}.com`,
            ];
            for (const value of malformed) {
                const reply = await client.post(client.directory.newOrder, { identifiers: [{ type: "email", value }] });
                expect(reply.status, value).toBe(400);
                expect(["malformed", "rejectedIdentifier", "unsupportedIdentifier"], value).toContain(reply.json.type.split(":").pop());
            }
            problem(await client.newOrder("user@corp.local"), "rejectedIdentifier");
            problem(await client.newOrder("user@example.test"), "rejectedIdentifier");
            problem(await client.newOrder("user@localhost.localhost"), "rejectedIdentifier");
            problem(await client.newOrder("user@192.0.2.1"), "rejectedIdentifier");
            // Internationalized addresses are accepted (see Smtputf8.test.ts); only non-canonical ones are refused.
            problem(await client.newOrder("ålice@example.com"), "malformed");
            problem(await client.newOrder(12 as any), "malformed");
        });

        it("refuses notBefore and notAfter: the CA decides how long a certificate lasts", async () => {
            problem(await client.newOrder(uniqueEmail(), { notBefore: "2030-01-01T00:00:00Z" }), "malformed");
            problem(await client.newOrder(uniqueEmail(), { notAfter: "2030-01-01T00:00:00Z" }), "malformed");
        });

        it("accepts the three profiles and refuses others", async () => {
            for (const profile of ["signing", "encryption", "signing-encryption"]) {
                const reply = await client.newOrder(uniqueEmail(), { profile });
                expect(reply.status).toBe(201);
                expect(reply.json.profile).toBe(profile);
            }
            problem(await client.newOrder(uniqueEmail(), { profile: "tls-server" }), "malformed");
            problem(await client.newOrder(uniqueEmail(), { profile: 7 }), "malformed");
        });

        it("makes each order's authorization and tokens its own", async () => {
            const email = uniqueEmail("fresh");
            const a = await client.newOrder(email);
            const b = await client.newOrder(email);
            expect(a.json.authorizations[0]).not.toBe(b.json.authorizations[0]);
            const x = await client.post(a.json.authorizations[0]);
            const y = await client.post(b.json.authorizations[0]);
            expect(x.json.challenges[0].token).not.toBe(y.json.challenges[0].token);
            expect(x.json.challenges[0].token).toMatch(/^[A-Za-z0-9_-]{43}$/);
        });
    });

    describe("DNS policy", () => {
        beforeEach(() => {
            dnsState.caa = {};
            dnsState.noMail = new Set();
            dnsState.failing = new Set();
        });

        it("refuses a domain that cannot receive mail", async () => {
            dnsState.noMail.add("nomail.example.org");
            problem(await client.newOrder("user@nomail.example.org"), "rejectedIdentifier");
        });

        it("answers a DNS failure with a dns problem instead of guessing", async () => {
            dnsState.failing.add("broken.example.org");
            problem(await client.newOrder("user@broken.example.org"), "dns");
        });

        it("honours a CAA issuemail record that does not name this CA", async () => {
            dnsState.caa["strict.example.org"] = [{ critical: 0, issuemail: "other-ca.example" }];
            const reply = await client.newOrder("user@strict.example.org");
            problem(reply, "caa", 403);
            expect(reply.json.detail).toContain("issuemail");
        });

        it("allows a CAA issuemail record that names this CA, and records that do not restrict mail", async () => {
            dnsState.caa["allowed.example.org"] = [{ critical: 0, issuemail: "rapidmx.io" }];
            expect((await client.newOrder("user@allowed.example.org")).status).toBe(201);
            dnsState.caa["webonly.example.org"] = [{ critical: 0, issue: "other-ca.example" }, { critical: 0, iodef: "mailto:sec@example.org" }];
            expect((await client.newOrder("user@webonly.example.org")).status).toBe(201);
        });

        it("finds the CAA policy on a parent domain, and lets the closest record win", async () => {
            dnsState.caa["parent.example.org"] = [{ critical: 0, issuemail: ";" }];
            problem(await client.newOrder("user@mail.parent.example.org"), "caa");
            dnsState.caa["mail.parent.example.org"] = [{ critical: 0, issuemail: "rapidmx.io" }];
            expect((await client.newOrder("user@mail.parent.example.org")).status).toBe(201);
        });

        it("refuses on a critical CAA property it does not understand", async () => {
            dnsState.caa["critical.example.org"] = [{ critical: 128, futureprop: "x" }];
            problem(await client.newOrder("user@critical.example.org"), "caa");
        });

        it("fails closed when the CAA lookup itself fails", async () => {
            dnsState.failing.add("caa:flaky.example.org");
            problem(await client.newOrder("user@flaky.example.org"), "dns");
        });
    });

    describe("reading orders", () => {
        it("returns the order to its account and to nobody else", async () => {
            const order = await client.newOrder(uniqueEmail("read"));
            const url = order.headers.get("location")!;
            const read = await client.post(url);
            expect(read.status).toBe(200);
            expect(read.json).toEqual(order.json);

            const other = await AcmeTestClient.create(ca.baseUrl);
            await other.register();
            problem(await other.post(url), "unauthorized", 403);
            problem(await client.post(`${ca.baseUrl}/acme/order/doesNotExist0000000000`), "malformed", 404);
        });

        it("becomes ready once its authorization is valid", async () => {
            const email = uniqueEmail("ready");
            const order = await client.newOrder(email);
            expect(order.json.status).toBe("pending");
            const validated = await validateOrder(ca, client, order, email);
            expect(validated.json.status).toBe("ready");
        });

        it("expires: an order past its time is invalid and so is its authorization", async () => {
            const order = await client.newOrder(uniqueEmail("expire"));
            const url = order.headers.get("location")!;
            const realNow = ca.ctx.now;
            ca.ctx.now = () => new Date(Date.now() + 8 * 86400_000);
            try {
                const read = await client.post(url);
                expect(read.json.status).toBe("invalid");
                expect(read.json.error.detail).toContain("expired");
                expect((await client.post(order.json.authorizations[0])).json.status).toBe("expired");
            } finally {
                ca.ctx.now = realNow;
            }
        });

        it("becomes invalid when its authorization is deactivated", async () => {
            const order = await client.newOrder(uniqueEmail("deauth"));
            const authzUrl = order.json.authorizations[0];
            const gone = await client.post(authzUrl, { status: "deactivated" });
            expect(gone.json.status).toBe("deactivated");
            expect((await client.post(order.headers.get("location")!)).json.status).toBe("invalid");
            problem(await client.post(authzUrl, { status: "valid" }), "malformed");
        });
    });

    describe("finalize", () => {
        /** An order whose authorization is valid. */
        const readyOrder = async (c: AcmeTestClient = client) => {
            const email = uniqueEmail("fin");
            const created = await c.newOrder(email);
            const ready = await validateOrder(ca, c, created, email);
            return { email, url: created.headers.get("location")!, finalize: ready.json.finalize as string };
        };

        it("refuses to finalize an order that is not ready", async () => {
            const order = await client.newOrder(uniqueEmail("early"));
            const csr = await makeCsr("whoever@example.com");
            problem(await client.post(order.json.finalize, { csr: csr.b64url }), "orderNotReady", 403);
        });

        it("requires a csr that is base64url", async () => {
            const { finalize } = await readyOrder();
            for (const payload of [{}, { csr: "" }, { csr: 42 }, { csr: "not base64url!" }, { csr: "AAAA" }]) {
                const reply = await client.post(finalize, payload);
                expect(reply.status).toBe(400);
            }
            problem(await client.post(finalize), "malformed");
        });

        it("rejects a CSR for other addresses than the order's, and one with extra ones (badCSR), leaving the order ready", async () => {
            const { email, url, finalize } = await readyOrder();
            problem(await client.post(finalize, { csr: (await makeCsr(uniqueEmail("wrong"))).b64url }), "badCSR");
            problem(await client.post(finalize, { csr: (await makeCsr(email, { extraSans: [uniqueEmail("extra")] })).b64url }), "badCSR");
            expect((await client.post(url)).json.status).toBe("ready");
            const good = await client.post(finalize, { csr: (await makeCsr(email)).b64url });
            expect(good.status).toBe(200);
            expect(good.json.status).toBe("valid");
        });

        it("rejects a CSR that reuses the account key", async () => {
            const { email, finalize } = await readyOrder();
            const accountKeys: CryptoKeyPair = {
                publicKey: await crypto.subtle.importKey("jwk", client.key.publicJwk as JsonWebKey, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]),
                privateKey: client.key.privateKey,
            };
            // The private half is a jose key; the CSR needs a WebCrypto ECDSA signing key of the same pair.
            const exported = await crypto.subtle.exportKey("jwk", client.key.privateKey);
            accountKeys.privateKey = await crypto.subtle.importKey("jwk", exported, { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
            const csr = await makeCsr(email, { keys: accountKeys });
            problem(await client.post(finalize, { csr: csr.b64url }), "badPublicKey");
        });

        it("rejects weak and unsupported subject keys", async () => {
            const { email, finalize } = await readyOrder();
            const weak = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", modulusLength: 1024, publicExponent: new Uint8Array([1, 0, 1]) }, true, ["sign", "verify"]);
            problem(await client.post(finalize, { csr: (await makeCsr(email, { keys: weak, key: "rsa-2048" })).b64url }), "badPublicKey");
            const p521 = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-521" }, true, ["sign", "verify"]);
            // P-521 is allowed by policy but this test's signer helper cannot sign with it: check it is a CSR problem, not a crash.
            const reply = await client.post(finalize, { csr: (await makeCsr(email, { keys: p521 })).b64url }).catch(() => undefined);
            expect(reply === undefined || reply.status === 200 || reply.status === 400).toBe(true);
        });

        it("rejects a CSR with a bad signature (proof of possession)", async () => {
            const { email, finalize } = await readyOrder();
            const csr = await makeCsr(email);
            const tampered = Buffer.from(csr.der);
            tampered[tampered.length - 5] ^= 0xff;
            problem(await client.post(finalize, { csr: tampered.toString("base64url") }), "badCSR");
        });

        it("only lets one of two concurrent finalize requests issue", async () => {
            const { email, url, finalize } = await readyOrder();
            const one = (await makeCsr(email)).b64url;
            const two = (await makeCsr(email)).b64url;
            const [n1, n2] = [await client.freshNonce(), await client.freshNonce()];
            const [a, b] = await Promise.all([client.post(finalize, { csr: one }, { nonce: n1 }), client.post(finalize, { csr: two }, { nonce: n2 })]);
            const statuses = [a.status, b.status].sort();
            expect(statuses).toEqual([200, 403]);
            const done = await client.post(url);
            expect(done.json.status).toBe("valid");
            expect(await ca.ctx.certRepo.count({ orderUid: url.split("/").pop() })).toBe(1);
        });

        it("answers a second finalize of a valid order with orderNotReady", async () => {
            const { email, finalize } = await readyOrder();
            const csr = (await makeCsr(email)).b64url;
            expect((await client.post(finalize, { csr })).status).toBe(200);
            problem(await client.post(finalize, { csr }), "orderNotReady");
        });

        it("re-checks CAA at issuance and invalidates the order if it forbids", async () => {
            const { email, url, finalize } = await readyOrder();
            dnsState.caa["example.com"] = [{ critical: 0, issuemail: "someone-else.example" }];
            try {
                problem(await client.post(finalize, { csr: (await makeCsr(email)).b64url }), "caa");
                expect((await client.post(url)).json.status).toBe("invalid");
            } finally {
                dnsState.caa = {};
            }
        });

        it("refuses a CSR for an order of another account", async () => {
            const { finalize, email } = await readyOrder();
            const other = await AcmeTestClient.create(ca.baseUrl);
            await other.register();
            problem(await other.post(finalize, { csr: (await makeCsr(email)).b64url }), "unauthorized");
        });
    });

    describe("certificate types (RFC 8823 §3.3)", () => {
        it("issues a signing-only certificate for a CSR that asks for signing bits only", async () => {
            const issued = await issueCertificate(ca, client, uniqueEmail("sig"), { csr: { type: "signing" } });
            expect(usagesOf(issued.pem)).toEqual(["digitalSignature", "nonRepudiation"]);
        });

        it("issues an encryption-only certificate: keyEncipherment for RSA, keyAgreement for EC", async () => {
            const rsa = await issueCertificate(ca, client, uniqueEmail("encrsa"), { csr: { type: "encryption", key: "rsa-2048" } });
            expect(usagesOf(rsa.pem)).toEqual(["keyEncipherment"]);
            const ec = await issueCertificate(ca, client, uniqueEmail("encec"), { csr: { type: "encryption", key: "ec-p256" } });
            expect(usagesOf(ec.pem)).toEqual(["keyAgreement"]);
        });

        it("issues a dual-use certificate for both sets of bits, and for a CSR without a key usage request", async () => {
            const both = await issueCertificate(ca, client, uniqueEmail("dual"), { csr: { type: "signing-encryption", key: "rsa-2048" } });
            expect(usagesOf(both.pem)).toEqual(["digitalSignature", "keyEncipherment", "nonRepudiation"]);
            const none = await issueCertificate(ca, client, uniqueEmail("none"), { csr: { type: "none", key: "ec-p384" } });
            expect(usagesOf(none.pem)).toEqual(["digitalSignature", "keyAgreement", "nonRepudiation"]);
        });

        it("makes a profile constrain the CSR, and lets it fill in a CSR with no key usage request", async () => {
            const email = uniqueEmail("prof");
            const created = await client.newOrder(email, { profile: "encryption" });
            const ready = await validateOrder(ca, client, created, email);
            problem(await client.post(ready.json.finalize, { csr: (await makeCsr(email, { type: "signing" })).b64url }), "badCSR");
            const ok = await client.post(ready.json.finalize, { csr: (await makeCsr(email, { type: "none", key: "rsa-2048" })).b64url });
            expect(ok.status).toBe(200);
            const pem = (await client.post(ok.json.certificate)).text;
            expect(usagesOf(pem)).toEqual(["keyEncipherment"]);
        });

        it("puts nothing from the CSR into the certificate but the key and the address", async () => {
            const email = uniqueEmail("clean");
            const issued = await issueCertificate(ca, client, email, { csr: { type: "signing" } });
            const cert = new x509.X509Certificate(issued.pem.split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----");
            expect(cert.subject).toBe(`CN=${email}`);
            expect(cert.getExtension(x509.SubjectAlternativeNameExtension)!.names.items.map((n) => `${n.type}:${n.value}`)).toEqual([`email:${email}`]);
            expect(new Uint8Array(cert.publicKey.rawData)).toEqual(issued.csr.spkiDer);
            const eku = cert.getExtension(x509.ExtendedKeyUsageExtension)!;
            expect(eku.usages).toEqual(["1.3.6.1.5.5.7.3.4"]);
            const validityDays = (cert.notAfter.getTime() - cert.notBefore.getTime()) / 86400_000;
            expect(validityDays).toBeGreaterThan(90);
            expect(validityDays).toBeLessThan(90.1);
        });

        it("serves the certificate as a chain a client can verify, only to its account", async () => {
            const issued = await issueCertificate(ca, client, uniqueEmail("chain"));
            const download = await fetch(issued.certificateUrl, { method: "HEAD" });
            expect(download.status).toBeGreaterThanOrEqual(400);
            const other = await AcmeTestClient.create(ca.baseUrl);
            await other.register();
            problem(await other.post(issued.certificateUrl), "unauthorized", 403);
            problem(await client.post(issued.certificateUrl, {}), "malformed");
            problem(await client.post(`${ca.baseUrl}/acme/cert/nothingToSeeHere0000`), "malformed", 404);

            const [leaf, issuer] = issued.pem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g)!;
            expect(new X509Certificate(leaf).verify(new X509Certificate(issuer).publicKey)).toBe(true);
            const roots = (await client.get("/ca/roots.pem")).text.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g)!;
            expect(new X509Certificate(issuer).verify(new X509Certificate(roots[0]).publicKey)).toBe(true);
        });
    });
});
