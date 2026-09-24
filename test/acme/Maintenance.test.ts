///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// What keeps a CA healthy without a request driving it: the housekeeping job, CRL upkeep and races, an issuing CA that is about
// to expire, and the server refusing to serve while it is not ready.
import { X509Certificate } from "crypto";
import { MaintenanceJob } from "../../src/jobs/MaintenanceJob.js";
import { AcmeTestClient } from "../support/client.js";
import { issueCertificate, uniqueEmail } from "../support/flow.js";
import { CaHarness, startCa } from "../support/harness.js";

describe("Maintenance and resilience", () => {
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

    describe("MaintenanceJob", () => {
        const job = (): MaintenanceJob => ca.objectFactory.getInstance<MaintenanceJob>(MaintenanceJob) as MaintenanceJob;

        it("runs every ten minutes and starts and stops without ceremony", async () => {
            expect(job().schedule).toBe("*/10 * * * *");
            await expect(job().start()).resolves.toBeUndefined();
            await expect(job().stop()).resolves.toBeUndefined();
        });

        it("marks authorizations and orders that ran out of time as expired and invalid", async () => {
            const order = await client.newOrder(uniqueEmail("sweep"));
            const orderUid = order.headers.get("location")!.split("/").pop()!;
            const realNow = ca.ctx.now;
            ca.ctx.now = () => new Date(Date.now() + 8 * 86400_000);
            try {
                await job().run();
            } finally {
                ca.ctx.now = realNow;
            }
            expect((await ca.ctx.orderRepo.findOne({ uid: orderUid }))?.status).toBe("invalid");
            expect((await ca.ctx.authzRepo.findOne({ orderUid }))?.status).toBe("expired");
            expect((await ca.ctx.authzRepo.findOne({ orderUid }))?.challenge.status).toBe("invalid");
            // Nothing left to do the second time.
            expect(await ca.ctx.challenges.expire()).toEqual({ authorizations: 0, orders: 0 });
        });

        it("leaves valid, unexpired work alone", async () => {
            const email = uniqueEmail("keep");
            const issued = await issueCertificate(ca, client, email);
            const orderUid = issued.orderUrl.split("/").pop()!;
            await job().run();
            expect((await ca.ctx.orderRepo.findOne({ uid: orderUid }))?.status).toBe("valid");
            const open = await client.newOrder(uniqueEmail("keep"));
            await job().run();
            expect((await client.post(open.headers.get("location")!)).json.status).toBe("pending");
        });

        it("regenerates a CRL that has gone stale, and only then", async () => {
            const latest = async () => (await ca.ctx.crlRepo.findOne({ issuerId: "test-ca" }, { sort: { sequence: -1 } }))!.sequence;
            // Earlier tests moved the clock, so a CRL may exist that was made "in the future": start from a clean slate.
            await ca.ctx.crlRepo.collection.deleteMany({});
            await ca.ctx.crls.current(ca.ctx.registry.active());
            const before = await latest();
            await job().run();
            expect(await latest()).toBe(before);
            const realNow = ca.ctx.now;
            ca.ctx.now = () => new Date(Date.now() + 13 * 3600_000);
            try {
                await job().run();
            } finally {
                ca.ctx.now = realNow;
            }
            expect(await latest()).toBe(before + 1);
        });

        it("logs and carries on when a step fails", async () => {
            const realExpire = ca.ctx.challenges.expire.bind(ca.ctx.challenges);
            const realRefresh = ca.ctx.crls.refreshAll.bind(ca.ctx.crls);
            ca.ctx.challenges.expire = async () => {
                throw new Error("database is down");
            };
            let refreshed = false;
            ca.ctx.crls.refreshAll = async () => {
                refreshed = true;
                throw new Error("signer is down");
            };
            try {
                await expect(job().run()).resolves.toBeUndefined();
                expect(refreshed).toBe(true);
            } finally {
                ca.ctx.challenges.expire = realExpire;
                ca.ctx.crls.refreshAll = realRefresh;
            }
        });

        it("does nothing while the CA is not ready", async () => {
            ca.ctx.ready = false;
            const realExpire = ca.ctx.challenges.expire;
            let called = false;
            ca.ctx.challenges.expire = async () => {
                called = true;
                return { authorizations: 0, orders: 0 };
            };
            try {
                await job().run();
                expect(called).toBe(false);
            } finally {
                ca.ctx.ready = true;
                ca.ctx.challenges.expire = realExpire;
            }
        });
    });

    describe("recovering a finalize that died", () => {
        const stuckOrder = async (email: string) => {
            const created = await client.newOrder(email);
            const { validateOrder } = await import("../support/flow.js");
            await validateOrder(ca, client, created, email);
            const uid = created.headers.get("location")!.split("/").pop()!;
            await ca.ctx.orderRepo.updateOne({ uid }, { $set: { status: "processing", processingSince: new Date(Date.now() - 11 * 60_000) } });
            return { uid, url: created.headers.get("location")! };
        };

        it("returns an order to ready when no certificate was stored, so the client can finalize again", async () => {
            const { uid, url } = await stuckOrder(uniqueEmail("dead"));
            await ca.ctx.challenges.expire();
            expect((await ca.ctx.orderRepo.findOne({ uid }))?.status).toBe("ready");
            expect((await ca.ctx.orderRepo.findOne({ uid }))?.processingSince).toBeUndefined();
            const { makeCsr } = await import("../support/client.js");
            const order = await client.post(url);
            const email = order.json.identifiers[0].value;
            expect((await client.post(order.json.finalize, { csr: (await makeCsr(email)).b64url })).status).toBe(200);
        });

        it("completes an order whose certificate was already stored", async () => {
            const email = uniqueEmail("stored");
            const issued = await issueCertificate(ca, client, email);
            const uid = issued.orderUrl.split("/").pop()!;
            const cert = (await ca.ctx.certRepo.findOne({ orderUid: uid }))!;
            await ca.ctx.orderRepo.updateOne({ uid }, { $set: { status: "processing", processingSince: new Date(Date.now() - 11 * 60_000) }, $unset: { certificateUid: "" } });
            await ca.ctx.challenges.expire();
            const after = (await ca.ctx.orderRepo.findOne({ uid }))!;
            expect(after.status).toBe("valid");
            expect(after.certificateUid).toBe(cert.uid);
        });

        it("leaves a finalize that is still within its time alone", async () => {
            const { uid } = await stuckOrder(uniqueEmail("busy"));
            await ca.ctx.orderRepo.updateOne({ uid }, { $set: { processingSince: new Date() } });
            await ca.ctx.challenges.expire();
            expect((await ca.ctx.orderRepo.findOne({ uid }))?.status).toBe("processing");
        });
    });

    describe("CRL generation", () => {
        it("survives losing the race for a CRL number to another replica", async () => {
            const issuer = ca.ctx.registry.active();
            const realSave = ca.ctx.crlRepo.save.bind(ca.ctx.crlRepo);
            let attempts = 0;
            ca.ctx.crlRepo.save = (async (doc: any, options: any) => {
                attempts += 1;
                if (attempts <= 2) {
                    throw Object.assign(new Error("E11000 duplicate key"), { code: 11000 });
                }
                return await realSave(doc, options);
            }) as any;
            try {
                const crl = await ca.ctx.crls.regenerate(issuer);
                expect(attempts).toBe(3);
                expect(crl.issuerId).toBe(issuer.id);
            } finally {
                ca.ctx.crlRepo.save = realSave;
            }
        });

        it("falls back to whichever CRL the winner wrote when it keeps losing, and rethrows anything else", async () => {
            const issuer = ca.ctx.registry.active();
            const realSave = ca.ctx.crlRepo.save.bind(ca.ctx.crlRepo);
            ca.ctx.crlRepo.save = (async () => {
                throw Object.assign(new Error("E11000 duplicate key"), { code: 11000 });
            }) as any;
            try {
                const crl = await ca.ctx.crls.regenerate(issuer);
                expect(crl.issuerId).toBe(issuer.id);
                ca.ctx.crlRepo.save = (async () => {
                    throw new Error("disk full");
                }) as any;
                await expect(ca.ctx.crls.regenerate(issuer)).rejects.toThrow("disk full");
            } finally {
                ca.ctx.crlRepo.save = realSave;
            }
        });

        it("lists only revoked certificates that have not expired yet", async () => {
            const issued = await issueCertificate(ca, client, uniqueEmail("crlx"));
            const der = new X509Certificate(issued.pem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/)![0]).raw.toString("base64url");
            await client.post(client.directory.revokeCert, { certificate: der, reason: 4 });
            expect((await ca.ctx.crlRepo.findOne({ issuerId: "test-ca" }, { sort: { sequence: -1 } }))!.entries).toBeGreaterThan(0);
            const realNow = ca.ctx.now;
            ca.ctx.now = () => new Date(Date.now() + 200 * 86400_000);
            try {
                expect((await ca.ctx.crls.regenerate(ca.ctx.registry.active())).entries).toBe(0);
            } finally {
                ca.ctx.now = realNow;
            }
        });
    });

    describe("serving while not ready", () => {
        it("answers every ACME request with a serverInternal problem", async () => {
            ca.ctx.ready = false;
            try {
                const reply = await client.get(client.directory.newNonce);
                expect(reply.status).toBe(500);
                expect(reply.json.type).toBe("urn:ietf:params:acme:error:serverInternal");
                expect((await fetch(`${ca.baseUrl}/directory`)).status).toBe(500);
                expect((await fetch(`${ca.baseUrl}/ca`)).status).toBe(500);
            } finally {
                ca.ctx.ready = true;
            }
            expect((await fetch(`${ca.baseUrl}/directory`, { method: "HEAD" })).status).toBe(200);
        });
    });

    describe("an issuing CA that is about to expire", () => {
        it("caps a certificate's life at the issuer's, and refuses to issue in the last day", async () => {
            const short = await startCa({}, { issuerDays: 30 });
            try {
                const c = await AcmeTestClient.create(short.baseUrl);
                await c.register();
                const issued = await issueCertificate(short, c, uniqueEmail("capped"));
                const leaf = new X509Certificate(issued.pem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/)![0]);
                const issuerCert = short.ctx.registry.active().certificate;
                expect(new Date(leaf.validTo).getTime()).toBeLessThanOrEqual(issuerCert.notAfter.getTime());
                expect(new Date(leaf.validTo).getTime() - new Date(leaf.validFrom).getTime()).toBeLessThan(31 * 86400_000);

                short.ctx.now = () => new Date(issuerCert.notAfter.getTime() - 3600_000);
                const email = uniqueEmail("late");
                const created = await c.newOrder(email);
                const { validateOrder } = await import("../support/flow.js");
                const ready = await validateOrder(short, c, created, email);
                const { makeCsr } = await import("../support/client.js");
                const refused = await c.post(ready.json.finalize, { csr: (await makeCsr(email)).b64url });
                expect(refused.status).toBe(500);
                expect(refused.json.type).toBe("urn:ietf:params:acme:error:serverInternal");
                expect(refused.text).not.toContain("expires");
                // The order can be finalized once a new issuer is in place: it went back to ready, not to invalid.
                expect((await c.post(created.headers.get("location")!)).json.status).toBe("ready");
            } finally {
                await short.stop();
            }
        }, 120_000);
    });
});
