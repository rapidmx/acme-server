///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// The public endpoints a relying party uses to validate the certificates this CA issued: issuer certificates, trust anchors, chains
// and public keys - plus the operational endpoints (status, metrics) and the pages the directory links to.
import { createHash, createPublicKey, X509Certificate } from "crypto";
import { AcmeTestClient } from "../support/client.js";
import { issueCertificate, uniqueEmail } from "../support/flow.js";
import { CaHarness, startCa } from "../support/harness.js";
import { x509 } from "../../src/lib/pki/runtime.js";
import { normalizeSerial } from "../../src/lib/acme/Util.js";

describe("Public trust endpoints", () => {
    let ca: CaHarness;
    const issuerId = "test-ca";

    beforeAll(async () => {
        ca = await startCa();
    }, 180_000);

    afterAll(async () => {
        await ca?.stop();
    });

    const get = (path: string, headers: Record<string, string> = {}) => fetch(`${ca.baseUrl}${path}`, { headers });
    const certs = (pem: string): string[] => pem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g) ?? [];

    describe("GET /ca", () => {
        it("describes the issuers and the roots to trust, with everything needed to pin them", async () => {
            const response = await get("/ca");
            expect(response.status).toBe(200);
            expect(response.headers.get("cache-control")).toBe("public, max-age=86400");
            expect(response.headers.get("access-control-allow-origin")).toBe("*");
            const body = await response.json();

            expect(body.issuers).toHaveLength(1);
            const issuer = body.issuers[0];
            expect(issuer).toMatchObject({ id: issuerId, name: "RapidMX Test S/MIME CA", role: "intermediate", active: true });
            expect(issuer.subject).toContain("RapidMX Test S/MIME CA");
            const cert = new X509Certificate(issuer.pem);
            expect(issuer.sha256Fingerprint).toBe(cert.fingerprint256.replace(/:/g, "").toLowerCase());
            expect(issuer.serialNumber).toBe(normalizeSerial(cert.serialNumber));
            expect(new Date(issuer.notAfter).getTime()).toBe(new Date(cert.validTo).getTime());
            expect(issuer.urls).toEqual({
                certificate: `${ca.baseUrl}/ca/${issuerId}.crt`,
                pem: `${ca.baseUrl}/ca/${issuerId}.pem`,
                chain: `${ca.baseUrl}/ca/${issuerId}/chain.pem`,
                crl: `${ca.baseUrl}/crl/${issuerId}.crl`,
                ocsp: `${ca.baseUrl}/ocsp`,
            });

            expect(body.roots).toHaveLength(1);
            const root = new X509Certificate(body.roots[0].pem);
            expect(body.roots[0].sha256Fingerprint).toBe(root.fingerprint256.replace(/:/g, "").toLowerCase());
            expect(cert.verify(root.publicKey)).toBe(true);
            expect(body.bundles).toEqual({ roots: `${ca.baseUrl}/ca/roots.pem`, chain: `${ca.baseUrl}/ca/chain.pem`, jwks: `${ca.baseUrl}/ca/jwks.json` });
        });

        it("publishes a JWK that is the issuer certificate's public key", async () => {
            const { issuers } = await (await get("/ca")).json();
            const jwk = issuers[0].jwk;
            expect(jwk).toMatchObject({ kty: "EC", crv: "P-384", kid: issuerId, use: "sig", alg: "ES384" });
            const fromJwk = createPublicKey({ key: jwk, format: "jwk" });
            const fromCert = new X509Certificate(issuers[0].pem).publicKey;
            expect(fromJwk.export({ type: "spki", format: "der" }).equals(fromCert.export({ type: "spki", format: "der" }))).toBe(true);
            expect(issuers[0].spkiSha256).toBe(createHash("sha256").update(fromCert.export({ type: "spki", format: "der" })).digest("hex"));
        });
    });

    describe("issuer certificates", () => {
        it("serves DER for the AIA caIssuers URL (.crt, .cer, .der) and PEM for .pem", async () => {
            const { issuers } = await (await get("/ca")).json();
            for (const extension of ["crt", "cer", "der"]) {
                const response = await get(`/ca/${issuerId}.${extension}`);
                expect(response.status, extension).toBe(200);
                expect(response.headers.get("content-type")).toBe("application/pkix-cert");
                const der = Buffer.from(await response.arrayBuffer());
                expect(new X509Certificate(der).subject).toContain("RapidMX Test S/MIME CA");
                expect(createHash("sha256").update(der).digest("hex")).toBe(issuers[0].sha256Fingerprint);
            }
            const pem = await get(`/ca/${issuerId}.pem`);
            expect(pem.headers.get("content-type")).toBe("application/x-pem-file");
            expect(await pem.text()).toBe(issuers[0].pem.trim() + "\n");
        });

        it("is what an issued certificate's AIA points to", async () => {
            const client = await AcmeTestClient.create(ca.baseUrl);
            await client.register();
            const issued = await issueCertificate(ca, client, uniqueEmail("aia"));
            const leaf = new x509.X509Certificate(certs(issued.pem)[0]);
            const aia = leaf.getExtension(x509.AuthorityInfoAccessExtension)!;
            const text = JSON.stringify(aia.caIssuers) + JSON.stringify(aia.ocsp);
            expect(text).toContain(`${ca.baseUrl}/ca/${issuerId}.crt`);
            expect(text).toContain(`${ca.baseUrl}/ocsp`);
            const fetched = new X509Certificate(Buffer.from(await (await get(`/ca/${issuerId}.crt`)).arrayBuffer()));
            expect(new X509Certificate(certs(issued.pem)[0]).verify(fetched.publicKey)).toBe(true);
            // The JWK validates it too.
            const { issuers } = await (await get("/ca")).json();
            expect(new X509Certificate(certs(issued.pem)[0]).verify(createPublicKey({ key: issuers[0].jwk, format: "jwk" }))).toBe(true);
        });

        it("says 404 for unknown issuers, unknown extensions and names that could be a path", async () => {
            for (const path of ["/ca/nobody.crt", `/ca/${issuerId}.txt`, `/ca/${issuerId}`, "/ca/..%2Fsecret.pem", "/ca/.pem", "/ca/UPPER.crt", "/ca/nobody/chain.pem"]) {
                expect((await get(path)).status, path).toBe(404);
            }
        });
    });

    describe("bundles", () => {
        it("serves the roots to trust as one PEM bundle", async () => {
            const response = await get("/ca/roots.pem");
            expect(response.status).toBe(200);
            expect(response.headers.get("content-type")).toBe("application/x-pem-file");
            const roots = certs(await response.text());
            expect(roots).toHaveLength(1);
            const root = new X509Certificate(roots[0]);
            expect(root.ca).toBe(true);
            expect(root.verify(root.publicKey)).toBe(true);
        });

        it("serves the chain of all issuers, or of one, from the issuer up to the root", async () => {
            for (const path of ["/ca/chain.pem", `/ca/${issuerId}/chain.pem`]) {
                const chain = certs(await (await get(path)).text());
                expect(chain).toHaveLength(2);
                const [issuer, root] = chain.map((c) => new X509Certificate(c));
                expect(issuer.verify(root.publicKey)).toBe(true);
                expect(root.verify(root.publicKey)).toBe(true);
            }
        });

        it("serves the public keys of all issuers as a JWK set", async () => {
            const response = await get("/ca/jwks.json");
            expect(response.status).toBe(200);
            expect(response.headers.get("content-type")).toBe("application/jwk-set+json");
            const { keys } = await response.json();
            expect(keys).toHaveLength(1);
            expect(keys[0]).toMatchObject({ kty: "EC", kid: issuerId, use: "sig" });
            expect(keys[0].d).toBeUndefined();
        });
    });

    describe("operational and informational endpoints", () => {
        it("reports its status without authentication", async () => {
            const response = await get("/status");
            expect(response.status).toBe(200);
            const body = await response.json();
            expect(body).toMatchObject({ name: "acme-test", version: "0.0.0" });
            expect(typeof body.time).toBe("number");
        });

        it("keeps metrics behind the bearer secret", async () => {
            expect((await get("/metrics")).status).toBe(401);
            expect((await get("/metrics", { authorization: "Bearer wrong" })).status).toBe(401);
            const ok = await get("/metrics", { authorization: "Bearer test-metrics-secret" });
            expect(ok.status).toBe(200);
            expect(ok.headers.get("content-type")).toContain("text/plain");
            expect(await ok.text()).toContain("# HELP");
        });

        it("has no metrics endpoint at all without a secret", async () => {
            const bare = await startCa({ "acme:metrics_secret": "" });
            try {
                expect((await fetch(`${bare.baseUrl}/metrics`, { headers: { authorization: "Bearer " } })).status).toBe(404);
            } finally {
                await bare.stop();
            }
        }, 60_000);

        it("serves the terms of service the directory points to", async () => {
            const client = await AcmeTestClient.create(ca.baseUrl);
            const response = await fetch(client.directory.meta.termsOfService);
            expect(response.status).toBe(200);
            expect(response.headers.get("content-type")).toContain("text/html");
            expect(await response.text()).toContain("Terms of service");
        });

        it("answers CORS preflights, so a browser client can read the trust anchors", async () => {
            const response = await fetch(`${ca.baseUrl}/ca/roots.pem`, { method: "OPTIONS", headers: { origin: "https://mail.example.org", "access-control-request-method": "GET" } });
            expect(response.status).toBe(204);
            expect(response.headers.get("access-control-allow-origin")).toBe("*");
        });
    });
});
