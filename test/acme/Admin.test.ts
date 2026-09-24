///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// The operator API: who may call it, searching what was issued, revoking one certificate or a selection, and suspending accounts -
// and that an operator's revocation is, to the CRL, OCSP and the compromised-key blocklist, exactly like any other.
import { X509Certificate } from "crypto";
import { AcmeRateLimiter } from "../../src/lib/acme/RateLimits.js";
import { x509 } from "../../src/lib/pki/runtime.js";
import { AcmeTestClient, makeCsr } from "../support/client.js";
import { issueCertificate, Issued, uniqueEmail, validateOrder } from "../support/flow.js";
import { CaHarness, startCa } from "../support/harness.js";
import { ocspRequest, parseOcsp } from "../support/ocsp.js";

interface Reply {
    status: number;
    json: any;
    headers: Headers;
}

describe("Operator API", () => {
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

    const call = async (method: string, path: string, body?: unknown, headers: Record<string, string> = {}, secret: string | null = ca.adminSecret): Promise<Reply> => {
        const response = await fetch(`${ca.baseUrl}${path}`, {
            method,
            headers: { ...(secret ? { authorization: `Bearer ${secret}` } : {}), ...(body !== undefined ? { "content-type": "application/json" } : {}), ...headers },
            ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
        });
        const text = await response.text();
        return { status: response.status, json: text ? JSON.parse(text) : undefined, headers: response.headers };
    };

    const serialOf = (issued: Issued): string => {
        let hex = new X509Certificate(issued.pem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/)![0]).serialNumber.toLowerCase();
        while (hex.length > 2 && hex.startsWith("00")) {
            hex = hex.slice(2);
        }
        return hex;
    };
    const accountOf = (c: AcmeTestClient): string => c.kid!.split("/").pop()!;
    const crlSerials = async (): Promise<string[]> => {
        const crl = new x509.X509Crl(new Uint8Array(await (await fetch(`${ca.baseUrl}/crl/test-ca.crl`)).arrayBuffer()));
        return crl.entries.map((e) => e.serialNumber.toLowerCase().replace(/^(00)+(?=..)/, ""));
    };

    describe("authentication", () => {
        it("is answered only with the bearer secret", async () => {
            expect((await call("GET", "/admin/certificates", undefined, {}, null)).status).toBe(401);
            expect((await call("GET", "/admin/certificates", undefined, {}, "wrong-secret")).status).toBe(401);
            expect((await call("GET", "/admin/certificates", undefined, { authorization: `Basic ${ca.adminSecret}` }, null)).status).toBe(401);
            const ok = await call("GET", "/admin/certificates");
            expect(ok.status).toBe(200);
            expect(ok.headers.get("cache-control")).toBe("no-store");
            expect(ok.headers.get("content-type")).toBe("application/json");
        });

        it("does not exist without a configured secret", async () => {
            const bare = await startCa({ "acme:admin_secret": "" });
            try {
                for (const [method, path] of [["GET", "/admin/certificates"], ["POST", "/admin/revocations"], ["GET", "/admin/accounts/abcdefgh12345678"]]) {
                    const response = await fetch(`${bare.baseUrl}${path}`, { method, headers: { authorization: "Bearer " } });
                    expect(response.status, path).toBe(404);
                }
            } finally {
                await bare.stop();
            }
        }, 60_000);

        it("limits how often one address can get the token wrong", async () => {
            const original = ca.ctx.limits;
            ca.ctx.limits = new AcmeRateLimiter(ca.ctx.store, { enabled: true, overrides: [{ limit: "adminAuthFailuresPerIp", subject: "127.0.0.1", count: 5, period_seconds: 3600, burst: 5 }] });
            try {
                const statuses: number[] = [];
                for (let i = 0; i < 8; i++) {
                    statuses.push((await call("GET", "/admin/certificates", undefined, {}, "wrong-secret")).status);
                }
                expect(statuses.slice(0, 5)).toEqual([401, 401, 401, 401, 401]);
                expect(statuses.slice(5)).toEqual([429, 429, 429]);
                // While blocked, even the right secret is refused: the address cannot be used to test guesses.
                expect((await call("GET", "/admin/certificates")).status).toBe(429);
            } finally {
                ca.ctx.limits = original;
            }
        });
    });

    describe("searching", () => {
        it("finds certificates by address in any spelling, serial, account, key and status", async () => {
            const email = uniqueEmail("srch");
            const issued = await issueCertificate(ca, client, email);
            const serial = serialOf(issued);

            const byEmail = await call("GET", `/admin/certificates?email=${encodeURIComponent(email.toUpperCase())}`);
            expect(byEmail.json.certificates).toHaveLength(1);
            expect(byEmail.json.certificates[0]).toMatchObject({ serial, status: "valid", email: email.toLowerCase(), type: "signing", issuer: "test-ca", account: accountOf(client) });
            expect((await call("GET", `/admin/certificates?serial=${serial.toUpperCase()}`)).json.certificates[0].serial).toBe(serial);
            const spki = byEmail.json.certificates[0].spkiSha256;
            expect((await call("GET", `/admin/certificates?spki=${spki}`)).json.certificates.map((c: any) => c.serial)).toEqual([serial]);
            expect((await call("GET", `/admin/certificates?account=${accountOf(client)}&status=valid&issuer=test-ca&limit=100`)).json.certificates.length).toBeGreaterThan(0);
            expect((await call("GET", `/admin/certificates?email=${encodeURIComponent(uniqueEmail("nobody"))}`)).json.certificates).toEqual([]);
        });

        it("finds an internationalized address by either spelling of its domain", async () => {
            const stranger = await AcmeTestClient.create(ca.baseUrl);
            await stranger.register();
            const canonical = canonicalOf("ålice@bücher.com");
            await ca.ctx.certRepo.save(
                new (await import("../../src/models/AcmeCertificate.js")).AcmeCertificate({ serial: "0a0b0c", issuerId: "test-ca", email: canonical.key, accountUid: accountOf(stranger), pem: "x", sha256Fingerprint: "f".repeat(64), spkiSha256: "e".repeat(64) }),
                { insertOnly: true },
            );
            for (const spelling of ["ålice@bücher.com", "ålice@xn--bcher-kva.com", "ÅLICE@BÜCHER.COM"]) {
                expect((await call("GET", `/admin/certificates?email=${encodeURIComponent(spelling)}`)).json.certificates.map((c: any) => c.serial), spelling).toEqual(["0a0b0c"]);
            }
            // A serial with a leading zero nibble is found whichever way it is typed.
            expect((await call("GET", "/admin/certificates?serial=a0b0c")).json.certificates).toHaveLength(1);
        });

        it("pages newest first with a cursor, and refuses bad criteria", async () => {
            await issueCertificate(ca, client, uniqueEmail("page"));
            await issueCertificate(ca, client, uniqueEmail("page"));
            const a = await call("GET", "/admin/certificates?limit=2");
            expect(a.json.certificates).toHaveLength(2);
            expect(a.json.next).toBe(2);
            const b = await call("GET", `/admin/certificates?limit=2&cursor=${a.json.next}`);
            expect(b.json.certificates.map((c: any) => c.serial)).not.toEqual(a.json.certificates.map((c: any) => c.serial));
            for (const query of ["email=not-an-address", "serial=xyz", "account=..", "spki=abc", "status=pending", "issuer=A/B", "email=a@example.com&email=b@example.com"]) {
                const reply = await call("GET", `/admin/certificates?${query}`);
                expect(reply.status, query).toBe(400);
                expect(typeof reply.json.error).toBe("string");
            }
        });

        it("shows one certificate with its chain, and 404s an unknown or malformed serial", async () => {
            const issued = await issueCertificate(ca, client, uniqueEmail("one"));
            const one = await call("GET", `/admin/certificates/${serialOf(issued)}`);
            expect(one.json.pem).toBe(issued.pem);
            expect((await call("GET", "/admin/certificates/deadbeefdeadbeef")).status).toBe(404);
            expect((await call("GET", "/admin/certificates/not-hex")).status).toBe(400);
        });
    });

    describe("revoking one certificate", () => {
        it("revokes it, records who and why, and republishes the CRL and OCSP", async () => {
            const issued = await issueCertificate(ca, client, uniqueEmail("rev"));
            const serial = serialOf(issued);
            expect(await crlSerials()).not.toContain(serial);

            const reply = await call("POST", `/admin/certificates/${serial}/revoke`, { reason: "superseded", note: "  replaced by the new mailbox  " }, { "x-operator": "jp@example.org" });
            expect(reply.status).toBe(200);
            expect(reply.json).toMatchObject({ serial, status: "revoked", reason: 4, source: "operator", revokedBy: "jp@example.org", note: "replaced by the new mailbox" });
            expect(await crlSerials()).toContain(serial);

            const issuer = ca.ctx.registry.active();
            const response = await fetch(`${ca.baseUrl}/ocsp`, { method: "POST", body: new Uint8Array(ocspRequest(issuer, serial)) });
            expect(parseOcsp(new Uint8Array(await response.arrayBuffer()))).toMatchObject({ status: "revoked", reason: 4 });
            expect((await client.get(`/certs/${serial}`, { accept: "application/json" })).json.status).toBe("revoked");
        });

        it("answers 409 for a certificate that is already revoked, by anyone", async () => {
            const issued = await issueCertificate(ca, client, uniqueEmail("twice"));
            const serial = serialOf(issued);
            expect((await call("POST", `/admin/certificates/${serial}/revoke`, {})).status).toBe(200);
            expect((await call("POST", `/admin/certificates/${serial}/revoke`, {})).status).toBe(409);
            const der = new X509Certificate(issued.pem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/)![0]).raw.toString("base64url");
            const clientReply = await client.post(client.directory.revokeCert, { certificate: der });
            expect(clientReply.json.type).toBe("urn:ietf:params:acme:error:alreadyRevoked");
        });

        it("accepts the reasons by name or number and defaults to unspecified, and refuses the rest", async () => {
            for (const [reason, code] of [["keyCompromise", 1], [3, 3], ["cessationOfOperation", 5], ["privilegeWithdrawn", 9], [undefined, 0]] as const) {
                const issued = await issueCertificate(ca, client, uniqueEmail("reason"));
                const reply = await call("POST", `/admin/certificates/${serialOf(issued)}/revoke`, reason === undefined ? {} : { reason });
                expect(reply.status).toBe(200);
                expect(reply.json.reason ?? 0).toBe(code);
            }
            const issued = await issueCertificate(ca, client, uniqueEmail("badreason"));
            for (const reason of [2, 6, 7, 8, 10, -1, 1.5, "certificateHold", "nonsense", true]) {
                expect((await call("POST", `/admin/certificates/${serialOf(issued)}/revoke`, { reason })).status, String(reason)).toBe(400);
            }
            for (const note of ["x".repeat(501), "line\u0000break", 5]) {
                expect((await call("POST", `/admin/certificates/${serialOf(issued)}/revoke`, { note })).status).toBe(400);
            }
            expect((await call("GET", `/admin/certificates/${serialOf(issued)}`)).json.status).toBe("valid");
        });

        it("drops an operator label that is not plain, and refuses a body that is not a JSON object", async () => {
            const issued = await issueCertificate(ca, client, uniqueEmail("label"));
            const serial = serialOf(issued);
            expect((await fetch(`${ca.baseUrl}/admin/certificates/${serial}/revoke`, { method: "POST", headers: { authorization: `Bearer ${ca.adminSecret}` }, body: "[1]" })).status).toBe(400);
            expect((await fetch(`${ca.baseUrl}/admin/certificates/${serial}/revoke`, { method: "POST", headers: { authorization: `Bearer ${ca.adminSecret}` }, body: "{oops" })).status).toBe(400);
            const reply = await call("POST", `/admin/certificates/${serial}/revoke`, {}, { "x-operator": "<script>alert(1)</script>" });
            expect(reply.json.revokedBy).toBeUndefined();
        });

        it("makes a keyCompromise revocation block the key from ever being certified again", async () => {
            const email = uniqueEmail("keyop");
            const issued = await issueCertificate(ca, client, email);
            await call("POST", `/admin/certificates/${serialOf(issued)}/revoke`, { reason: "keyCompromise" });
            const order = await client.newOrder(email);
            const ready = await validateOrder(ca, client, order, email);
            const reply = await client.post(ready.json.finalize, { csr: (await makeCsr(email, { keys: issued.csr.keys })).b64url });
            expect(reply.json.type).toBe("urn:ietf:params:acme:error:badPublicKey");
        });

        it("records who revoked it when a client does", async () => {
            const issued = await issueCertificate(ca, client, uniqueEmail("clientrev"));
            const der = new X509Certificate(issued.pem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/)![0]).raw.toString("base64url");
            await client.post(client.directory.revokeCert, { certificate: der, reason: 4 });
            expect((await call("GET", `/admin/certificates/${serialOf(issued)}`)).json).toMatchObject({ status: "revoked", source: "account", reason: 4 });
        });
    });

    describe("revoking a selection", () => {
        it("revokes everything certified for an address, once, and regenerates the CRL once", async () => {
            const email = uniqueEmail("bulk");
            const first = await issueCertificate(ca, client, email);
            const second = await issueCertificate(ca, client, email);
            const other = await issueCertificate(ca, client, uniqueEmail("keep"));
            await call("POST", `/admin/certificates/${serialOf(first)}/revoke`, {});

            const sequence = async () => (await ca.ctx.crlRepo.findOne({ issuerId: "test-ca" }, { sort: { sequence: -1 } }))!.sequence;
            const before = await sequence();
            const preview = await call("POST", "/admin/revocations", { selector: { email }, dryRun: true });
            expect(preview.json).toEqual({ matched: 1, revoked: 0, alreadyRevoked: 1, dryRun: true, serials: [serialOf(second)] });
            expect(await sequence()).toBe(before);

            const done = await call("POST", "/admin/revocations", { selector: { email }, reason: "cessationOfOperation", note: "mailbox closed" }, { "x-operator": "ops" });
            expect(done.json).toEqual({ matched: 1, revoked: 1, alreadyRevoked: 1, dryRun: false, serials: [serialOf(second)] });
            expect(await sequence()).toBe(before + 1);
            const serials = await crlSerials();
            expect(serials).toContain(serialOf(second));
            expect(serials).not.toContain(serialOf(other));
            expect((await call("GET", `/admin/certificates/${serialOf(second)}`)).json).toMatchObject({ reason: 5, note: "mailbox closed", revokedBy: "ops" });
        });

        it("revokes every certificate certifying a key, whichever account or address ordered them", async () => {
            const keys = (await makeCsr("x@example.com")).keys;
            const emailA = uniqueEmail("sharedA");
            const emailB = uniqueEmail("sharedB");
            const a = await issueCertificate(ca, client, emailA, { csr: { keys } });
            const otherClient = await AcmeTestClient.create(ca.baseUrl);
            await otherClient.register();
            const b = await issueCertificate(ca, otherClient, emailB, { csr: { keys } });
            const spki = (await call("GET", `/admin/certificates/${serialOf(a)}`)).json.spkiSha256;
            const done = await call("POST", "/admin/revocations", { selector: { spki }, reason: 1 });
            expect(done.json.revoked).toBe(2);
            expect(done.json.serials.sort()).toEqual([serialOf(a), serialOf(b)].sort());
        });

        it("revokes an account's certificates, or an explicit list of serials", async () => {
            const c = await AcmeTestClient.create(ca.baseUrl);
            await c.register();
            const one = await issueCertificate(ca, c, uniqueEmail("acctA"));
            const two = await issueCertificate(ca, c, uniqueEmail("acctB"));
            const three = await issueCertificate(ca, c, uniqueEmail("acctC"));
            expect((await call("POST", "/admin/revocations", { selector: { serials: [serialOf(one).toUpperCase()] } })).json.revoked).toBe(1);
            const rest = await call("POST", "/admin/revocations", { selector: { account: accountOf(c) }, reason: 3 });
            expect(rest.json).toMatchObject({ matched: 2, revoked: 2, alreadyRevoked: 1 });
            expect(rest.json.serials.sort()).toEqual([serialOf(two), serialOf(three)].sort());
        });

        it("refuses a selector that is not exactly one criterion, or is malformed", async () => {
            for (const body of [
                {},
                { selector: {} },
                { selector: { email: "a@example.com", account: "abcdefgh12345678" } },
                { selector: { status: "valid" } },
                { selector: { email: "nonsense" } },
                { selector: { serials: [] } },
                { selector: { serials: "abc" } },
                { selector: { serials: ["xyz"] } },
                { selector: { serials: Array.from({ length: 201 }, () => "ab") } },
                { selector: { spki: "abc" } },
                { selector: { email: "a@example.com" }, reason: "nonsense" },
            ]) {
                const reply = await call("POST", "/admin/revocations", body);
                expect(reply.status, JSON.stringify(body).slice(0, 80)).toBe(400);
            }
        });

        it("refuses a selection that would revoke more than the cap", async () => {
            const cert = await ca.ctx.certRepo.findOne({ status: "valid" });
            const many = Array.from({ length: 1001 }, (_, i) => ({ ...cert!, _id: undefined, uid: `bulk-${i}-${Math.random().toString(36).slice(2)}`, serial: `77${i.toString(16).padStart(8, "0")}`, sha256Fingerprint: `${i}`.padStart(64, "a"), accountUid: "bulk-cap-account", status: "valid" }));
            await ca.ctx.certRepo.collection.insertMany(many as any);
            const reply = await call("POST", "/admin/revocations", { selector: { account: "bulk-cap-account" } });
            expect(reply.status).toBe(400);
            expect(reply.json.error).toContain("more than 1000");
            expect((await call("POST", "/admin/revocations", { selector: { account: "bulk-cap-account" }, dryRun: true })).status).toBe(400);
            await ca.ctx.certRepo.collection.deleteMany({ accountUid: "bulk-cap-account" });
        });
    });

    describe("accounts", () => {
        it("shows an account with what it has done", async () => {
            const c = await AcmeTestClient.create(ca.baseUrl);
            await c.register(["mailto:owner@example.com"]);
            await issueCertificate(ca, c, uniqueEmail("acct"));
            const account = await call("GET", `/admin/accounts/${accountOf(c)}`);
            expect(account.json).toMatchObject({ id: accountOf(c), status: "valid", contact: ["mailto:owner@example.com"], orders: 1, certificates: 1, validCertificates: 1 });
            expect((await call("GET", "/admin/accounts/doesNotExist0000000000")).status).toBe(404);
            expect((await call("GET", "/admin/accounts/x")).status).toBe(404);
        });

        it("suspends an account: nothing works for it, its open work is cancelled, its certificates can be revoked with it", async () => {
            const c = await AcmeTestClient.create(ca.baseUrl);
            await c.register();
            const issued = await issueCertificate(ca, c, uniqueEmail("susp"));
            const open = await c.newOrder(uniqueEmail("susp"));
            const reply = await call("POST", `/admin/accounts/${accountOf(c)}/suspend`, { note: "abuse report 42", revokeCertificates: true, reason: "keyCompromise" }, { "x-operator": "ops" });
            expect(reply.status).toBe(200);
            expect(reply.json).toMatchObject({ status: "revoked", revocation: { revoked: 1, matched: 1 } });

            const denied = await c.post(c.kid!);
            expect(denied.status).toBe(403);
            expect(denied.json.detail).toContain("revoked");
            expect((await ca.ctx.orderRepo.findOne({ uid: open.headers.get("location")!.split("/").pop() }))?.status).toBe("invalid");
            expect((await call("GET", `/admin/certificates/${serialOf(issued)}`)).json).toMatchObject({ status: "revoked", reason: 1, note: "abuse report 42" });
            // A suspended account cannot be re-registered by presenting its key again.
            const again = await c.post(c.directory.newAccount, { termsOfServiceAgreed: true }, { jwk: true });
            expect(again.headers.get("location")).toBe(c.kid);
        });

        it("reinstates a suspended account, but not one that is not suspended or was deactivated by its holder", async () => {
            const c = await AcmeTestClient.create(ca.baseUrl);
            await c.register();
            expect((await call("POST", `/admin/accounts/${accountOf(c)}/reinstate`, {})).status).toBe(409);
            await call("POST", `/admin/accounts/${accountOf(c)}/suspend`, {});
            expect((await c.post(c.kid!)).status).toBe(403);
            expect((await call("POST", `/admin/accounts/${accountOf(c)}/reinstate`, {})).json.status).toBe("valid");
            expect((await c.post(c.kid!)).status).toBe(200);

            await c.post(c.kid!, { status: "deactivated" });
            expect((await call("POST", `/admin/accounts/${accountOf(c)}/suspend`, {})).status).toBe(409);
            expect((await call("POST", `/admin/accounts/${accountOf(c)}/reinstate`, {})).status).toBe(409);
            expect((await call("POST", "/admin/accounts/doesNotExist0000000000/reinstate", {})).status).toBe(404);
            expect((await call("POST", "/admin/accounts/doesNotExist0000000000/suspend", {})).status).toBe(404);
        });
    });
});

function canonicalOf(address: string) {
    return { key: address.toLowerCase().replace(/@.*$/, "") + "@xn--bcher-kva.com" };
}
