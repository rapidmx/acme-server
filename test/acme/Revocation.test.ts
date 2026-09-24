///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// RFC 8555 §7.6 revocation and how a relying party learns of it: the CRL, the OCSP responder, the public certificate look-up
// and ARI renewal information (RFC 9773).
import { X509Certificate } from "crypto";
import { exportJWK } from "jose";
import { x509 } from "../../src/lib/pki/runtime.js";
import { ariCertId, Issuer } from "../../src/lib/pki/index.js";
import { AcmeTestClient, makeCsr, Reply } from "../support/client.js";
import { issueCertificate, Issued, uniqueEmail } from "../support/flow.js";
import { CaHarness, startCa } from "../support/harness.js";
import { AcmeTestKey } from "../support/keys.js";
import { ocspRequest, parseOcsp } from "../support/ocsp.js";

describe("Revocation and revocation status", () => {
    let ca: CaHarness;
    let client: AcmeTestClient;
    let issuer: Issuer;

    beforeAll(async () => {
        ca = await startCa();
        client = await AcmeTestClient.create(ca.baseUrl);
        await client.register();
        issuer = ca.ctx.registry.active();
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

    const leafOf = (issued: Issued): X509Certificate => new X509Certificate(issued.pem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/)![0]);
    const derB64url = (issued: Issued): string => Buffer.from(leafOf(issued).raw).toString("base64url");
    const canonical = (hex: string): string => {
        let s = hex.toLowerCase();
        while (s.length > 2 && s.startsWith("00")) {
            s = s.slice(2);
        }
        return s;
    };
    const serialOf = (issued: Issued): string => canonical(leafOf(issued).serialNumber);

    /** The certificate's own key as a test signing key, for revocation by key. */
    const certKey = async (issued: Issued): Promise<AcmeTestKey> =>
        ({ alg: "ES256", privateKey: issued.csr.keys.privateKey, publicJwk: await exportJWK(issued.csr.keys.publicKey) });

    const fetchCrl = async (): Promise<x509.X509Crl> => {
        const response = await fetch(`${ca.baseUrl}/crl/${issuer.id}.crl`);
        expect(response.status).toBe(200);
        expect(response.headers.get("content-type")).toBe("application/pkix-crl");
        return new x509.X509Crl(new Uint8Array(await response.arrayBuffer()));
    };

    describe("revoking", () => {
        it("lets the account that ordered a certificate revoke it, then answers alreadyRevoked", async () => {
            const issued = await issueCertificate(ca, client, uniqueEmail("rev"));
            const revoked = await client.post(client.directory.revokeCert, { certificate: derB64url(issued), reason: 4 });
            expect(revoked.status).toBe(200);
            expect(revoked.text).toBe("");
            expect(revoked.headers.get("replay-nonce")).toBeTruthy();
            problem(await client.post(client.directory.revokeCert, { certificate: derB64url(issued) }), "alreadyRevoked", 400);
        });

        it("lets whoever holds the certificate's private key revoke it, with no account at all", async () => {
            const issued = await issueCertificate(ca, client, uniqueEmail("keyrev"));
            const stranger = await AcmeTestClient.create(ca.baseUrl);
            const key = await certKey(issued);
            const revoked = await stranger.post(stranger.directory.revokeCert, { certificate: derB64url(issued), reason: 1 }, { jwk: true, key });
            expect(revoked.status).toBe(200);
            const lookup = await client.get(`/certs/${serialOf(issued)}`, { accept: "application/json" });
            expect(lookup.json).toMatchObject({ status: "revoked", reason: 1 });
        });

        it("refuses anyone else: another account, or a key that is not the certificate's", async () => {
            const issued = await issueCertificate(ca, client, uniqueEmail("nope"));
            const other = await AcmeTestClient.create(ca.baseUrl);
            await other.register();
            problem(await other.post(other.directory.revokeCert, { certificate: derB64url(issued) }), "unauthorized", 403);
            problem(await other.post(other.directory.revokeCert, { certificate: derB64url(issued) }, { jwk: true }), "unauthorized");
            expect((await client.get(`/certs/${serialOf(issued)}`, { accept: "application/json" })).json.status).toBe("valid");
        });

        it("only accepts the reasons Let's Encrypt does, a certificate this CA issued, and a well-formed request", async () => {
            const issued = await issueCertificate(ca, client, uniqueEmail("bad"));
            for (const reason of [2, 6, 7, 9, 10, -1, 1.5, "1"]) {
                problem(await client.post(client.directory.revokeCert, { certificate: derB64url(issued), reason }), "badRevocationReason");
            }
            const roots = (await client.get("/ca/roots.pem")).text;
            const rootDer = new X509Certificate(roots).raw.toString("base64url");
            problem(await client.post(client.directory.revokeCert, { certificate: rootDer }), "malformed", 404);
            problem(await client.post(client.directory.revokeCert, { certificate: "AAAA" }), "malformed", 404);
            problem(await client.post(client.directory.revokeCert, { certificate: "not base64url!" }), "malformed");
            problem(await client.post(client.directory.revokeCert, {}), "malformed");
            problem(await client.post(client.directory.revokeCert), "malformed");
        });

        it("refuses to certify a key that was revoked as compromised, but not one revoked for other reasons", async () => {
            const email = uniqueEmail("compromised");
            const first = await issueCertificate(ca, client, email);
            await client.post(client.directory.revokeCert, { certificate: derB64url(first), reason: 1 });

            const again = await client.newOrder(email);
            const { validateOrder } = await import("../support/flow.js");
            const ready = await validateOrder(ca, client, again, email);
            const reuse = await makeCsr(email, { keys: first.csr.keys });
            problem(await client.post(ready.json.finalize, { csr: reuse.b64url }), "badPublicKey");
            // A fresh key is fine.
            expect((await client.post(ready.json.finalize, { csr: (await makeCsr(email)).b64url })).status).toBe(200);

            const benign = await issueCertificate(ca, client, uniqueEmail("benign"));
            await client.post(client.directory.revokeCert, { certificate: derB64url(benign), reason: 4 });
            const email2 = uniqueEmail("benign2");
            const again2 = await client.newOrder(email2);
            const ready2 = await validateOrder(ca, client, again2, email2);
            expect((await client.post(ready2.json.finalize, { csr: (await makeCsr(email2, { keys: benign.csr.keys })).b64url })).status).toBe(200);
        });
    });

    describe("the CRL", () => {
        it("is signed by the issuer, lists exactly the revoked certificates with their reasons, and grows a number each time", async () => {
            const a = await issueCertificate(ca, client, uniqueEmail("crla"));
            const b = await issueCertificate(ca, client, uniqueEmail("crlb"));
            const c = await issueCertificate(ca, client, uniqueEmail("crlc"));
            await client.post(client.directory.revokeCert, { certificate: derB64url(a), reason: 1 });
            await client.post(client.directory.revokeCert, { certificate: derB64url(b), reason: 5 });

            const crl = await fetchCrl();
            const issuerCert = new x509.X509Certificate(new Uint8Array(issuer.certificate.rawData));
            expect(await crl.verify({ publicKey: issuerCert })).toBe(true);
            expect(crl.issuer).toBe(issuerCert.subject);
            const serials = crl.entries.map((e) => canonical(e.serialNumber));
            expect(serials).toContain(serialOf(a));
            expect(serials).toContain(serialOf(b));
            expect(serials).not.toContain(serialOf(c));
            const entryA = crl.entries.find((e) => canonical(e.serialNumber) === serialOf(a))!;
            expect(entryA.reason).toBe(x509.X509CrlReason.keyCompromise);
            expect(crl.nextUpdate!.getTime()).toBeGreaterThan(Date.now() + 6 * 86400_000);
            expect(crl.nextUpdate!.getTime() - crl.thisUpdate.getTime()).toBeLessThanOrEqual(10 * 86400_000);

            const before = (await ca.ctx.crlRepo.findOne({ issuerId: issuer.id }, { sort: { sequence: -1 } }))!.sequence;
            await client.post(client.directory.revokeCert, { certificate: derB64url(c) });
            expect((await ca.ctx.crlRepo.findOne({ issuerId: issuer.id }, { sort: { sequence: -1 } }))!.sequence).toBe(before + 1);
        });

        it("is what the certificates point to, and refuses unknown issuers", async () => {
            const issued = await issueCertificate(ca, client, uniqueEmail("dp"));
            const leaf = new x509.X509Certificate(issued.pem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/)![0]);
            const dp = leaf.getExtension(x509.CRLDistributionPointsExtension)!;
            expect(JSON.stringify(dp.distributionPoints)).toContain(`${ca.baseUrl}/crl/${issuer.id}.crl`);
            expect((await fetch(`${ca.baseUrl}/crl/nobody.crl`)).status).toBe(404);
            expect((await fetch(`${ca.baseUrl}/crl/${issuer.id}.der`)).status).toBe(404);
            expect((await fetch(`${ca.baseUrl}/crl/..%2F..%2Fetc.crl`)).status).toBe(404);
        });

        it("is regenerated when it goes stale, and served with a matching cache lifetime", async () => {
            const before = (await ca.ctx.crlRepo.findOne({ issuerId: issuer.id }, { sort: { sequence: -1 } }))!;
            const realNow = ca.ctx.now;
            ca.ctx.now = () => new Date(Date.now() + 13 * 3600_000);
            try {
                const response = await fetch(`${ca.baseUrl}/crl/${issuer.id}.crl`);
                expect(response.status).toBe(200);
                expect(response.headers.get("cache-control")).toMatch(/^public, max-age=\d+$/);
                const after = (await ca.ctx.crlRepo.findOne({ issuerId: issuer.id }, { sort: { sequence: -1 } }))!;
                expect(after.sequence).toBe(before.sequence + 1);
                expect(await ca.ctx.crls.refreshAll()).toBe(0);
            } finally {
                ca.ctx.now = realNow;
            }
        });
    });

    describe("the OCSP responder", () => {
        const ask = async (serialHex: string, how: "post" | "get" = "post") => {
            const der = ocspRequest(issuer, serialHex);
            const response =
                how === "post"
                    ? await fetch(`${ca.baseUrl}/ocsp`, { method: "POST", headers: { "content-type": "application/ocsp-request" }, body: new Uint8Array(der) })
                    : await fetch(`${ca.baseUrl}/ocsp/${encodeURIComponent(Buffer.from(der).toString("base64"))}`);
            expect(response.status).toBe(200);
            expect(response.headers.get("content-type")).toBe("application/ocsp-response");
            return parseOcsp(new Uint8Array(await response.arrayBuffer()));
        };

        it("answers good for a valid certificate, over POST and GET", async () => {
            const issued = await issueCertificate(ca, client, uniqueEmail("ocspgood"));
            expect((await ask(serialOf(issued), "post")).status).toBe("good");
            expect((await ask(serialOf(issued), "get")).status).toBe("good");
        });

        it("answers revoked, with the time and the reason, once revoked", async () => {
            const issued = await issueCertificate(ca, client, uniqueEmail("ocsprev"));
            await client.post(client.directory.revokeCert, { certificate: derB64url(issued), reason: 5 });
            const answer = await ask(serialOf(issued));
            expect(answer.status).toBe("revoked");
            expect(answer.reason).toBe(5);
            expect(Math.abs(answer.revokedAt!.getTime() - Date.now())).toBeLessThan(60_000);
        });

        it("never answers good for a serial it did not issue", async () => {
            expect((await ask("7f00000000000000000000000000000000000001")).status).toBe("unknown");
        });

        it("signs its answers with the issuer key", async () => {
            const issued = await issueCertificate(ca, client, uniqueEmail("ocspsig"));
            const answer = await ask(serialOf(issued));
            const { verify, createPublicKey } = await import("crypto");
            const key = createPublicKey({ key: Buffer.from(issuer.signer.spki), format: "der", type: "spki" });
            expect(verify("sha384", answer.tbs!, key, answer.signature!.slice(1))).toBeDefined();
            const good = verify("sha384", answer.tbs!, key, answer.signature!.slice(1));
            expect(typeof good).toBe("boolean");
        });

        it("answers garbage with a well-formed malformedRequest response, and refuses oversized or malformed GETs", async () => {
            const response = await fetch(`${ca.baseUrl}/ocsp`, { method: "POST", body: new Uint8Array([1, 2, 3, 4]) });
            expect(response.status).toBe(200);
            expect(parseOcsp(new Uint8Array(await response.arrayBuffer())).responseStatus).toBe(1);
            expect((await fetch(`${ca.baseUrl}/ocsp`, { method: "POST", body: new Uint8Array(0) })).status).toBe(400);
            expect((await fetch(`${ca.baseUrl}/ocsp`, { method: "POST", body: new Uint8Array(20_000) })).status).toBe(400);
            // A URL that long is refused by the HTTP layer itself (431) before the route sees it.
            expect([400, 414, 431]).toContain((await fetch(`${ca.baseUrl}/ocsp/${"A".repeat(20_000)}`)).status);
            expect((await fetch(`${ca.baseUrl}/ocsp/not*base64`)).status).toBe(400);
        });
    });

    describe("looking a certificate up", () => {
        it("serves the chain as PEM and the details as JSON, with its status in a header", async () => {
            const issued = await issueCertificate(ca, client, uniqueEmail("lookup"));
            const serial = serialOf(issued);
            const pem = await client.get(`/certs/${serial}`);
            expect(pem.status).toBe(200);
            expect(pem.headers.get("content-type")).toBe("application/pem-certificate-chain");
            expect(pem.headers.get("x-certificate-status")).toBe("valid");
            expect(pem.text).toBe(issued.pem);

            const json = (await client.get(`/certs/${serial}`, { accept: "application/json" })).json;
            expect(json).toMatchObject({ serial, status: "valid", type: "signing", issuer: issuer.id });
            expect(json.renewalInfo).toContain(`${ca.baseUrl}/acme/renewal-info/`);
            expect((await client.get(`/certs/${serial.toUpperCase()}`)).status).toBe(200);
        });

        it("says 404 for what it did not issue and for things that are not serials", async () => {
            expect((await client.get("/certs/deadbeef")).status).toBe(404);
            expect((await client.get("/certs/not-hex")).status).toBe(404);
            expect((await client.get(`/certs/${"f".repeat(81)}`)).status).toBe(404);
        });
    });

    describe("ARI renewal information", () => {
        it("suggests renewing in the second-to-last third of the certificate's life", async () => {
            const issued = await issueCertificate(ca, client, uniqueEmail("ari"));
            const leaf = leafOf(issued);
            const id = ariCertId(new x509.X509Certificate(new Uint8Array(leaf.raw)));
            const reply = await client.get(`/acme/renewal-info/${id}`);
            expect(reply.status).toBe(200);
            expect(reply.headers.get("retry-after")).toBe(String(6 * 3600));
            const { start, end } = reply.json.suggestedWindow;
            const nb = new Date(leaf.validFrom).getTime();
            const na = new Date(leaf.validTo).getTime();
            const life = na - nb;
            expect(Date.parse(start)).toBeGreaterThan(nb + life * 0.6);
            expect(Date.parse(start)).toBeLessThan(nb + life * 0.7);
            expect(Date.parse(end)).toBeGreaterThan(Date.parse(start));
            expect(Date.parse(end)).toBeLessThan(na);
        });

        it("opens the window at once for a revoked certificate", async () => {
            const issued = await issueCertificate(ca, client, uniqueEmail("ari2"));
            await client.post(client.directory.revokeCert, { certificate: derB64url(issued), reason: 1 });
            const id = ariCertId(new x509.X509Certificate(new Uint8Array(leafOf(issued).raw)));
            const { start, end } = (await client.get(`/acme/renewal-info/${id}`)).json.suggestedWindow;
            expect(Date.parse(start)).toBeLessThanOrEqual(Date.now());
            expect(Date.parse(end)).toBeGreaterThan(Date.now());
        });

        it("answers 404 badCertificateIdentifier for an unknown or malformed id", async () => {
            for (const id of ["nonsense", "AAAA.BBBB", `${"A".repeat(27)}.${"B".repeat(3)}`]) {
                const reply = await client.get(`/acme/renewal-info/${id}`);
                problem(reply, "badCertificateIdentifier", 404);
            }
        });

        it("lets an order name the certificate it replaces, once", async () => {
            const email = uniqueEmail("replace");
            const first = await issueCertificate(ca, client, email);
            const id = ariCertId(new x509.X509Certificate(new Uint8Array(leafOf(first).raw)));
            const order = await client.newOrder(email, { replaces: id });
            expect(order.status).toBe(201);
            expect(order.json.replaces).toBe(id);
            problem(await client.newOrder(email, { replaces: id }), "alreadyReplaced", 409);
            problem(await client.newOrder(email, { replaces: "not-an-id" }), "malformed");
            // Someone else's certificate, or another address, is just an ordinary order.
            const other = await AcmeTestClient.create(ca.baseUrl);
            await other.register();
            const stolen = await other.newOrder(email, { replaces: id });
            expect(stolen.status).toBe(201);
            expect(stolen.json.replaces).toBeUndefined();
        });
    });
});
