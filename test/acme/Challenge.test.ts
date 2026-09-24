///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// RFC 8823: the email-reply-00 challenge - when the verification e-mail goes out (and that it goes out once), what makes a reply
// count, and everything that must not.
import * as net from "net";
import nodemailer from "nodemailer";
import { AcmeTestClient, ingest, Reply } from "../support/client.js";
import { lastMail, uniqueEmail } from "../support/flow.js";
import { CaHarness, startCa } from "../support/harness.js";

describe("ACME email-reply-00 challenge", () => {
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

    /** A new order whose authorization has been fetched, so the verification e-mail is out. */
    const started = async (email: string = uniqueEmail("chal")) => {
        const order = await client.newOrder(email);
        const authzUrl: string = order.json.authorizations[0];
        const authz = await client.post(authzUrl);
        const challenge = authz.json.challenges[0];
        return { email, order, orderUrl: order.headers.get("location")!, authzUrl, authz, challenge, mail: lastMail(ca, email) };
    };

    const challengeStatus = async (authzUrl: string): Promise<{ authz: string; challenge: string; body: any }> => {
        const reply = await client.post(authzUrl);
        return { authz: reply.json.status, challenge: reply.json.challenges[0].status, body: reply.json };
    };

    describe("the verification e-mail", () => {
        it("goes out when the authorization is first fetched, not when the order is created", async () => {
            const email = uniqueEmail("timing");
            const order = await client.newOrder(email);
            expect(lastMail(ca, email)).toBeUndefined();
            await client.post(order.json.authorizations[0]);
            expect(lastMail(ca, email)).toBeDefined();
        });

        it("is addressed, worded and identified the way RFC 8823 §3.1 says", async () => {
            const { email, mail, challenge } = await started();
            expect(mail.to).toBe(email);
            expect(mail.from).toBe("acme-challenge@acme.rapidmx.test");
            expect(mail.replyTo).toBe("acme-response@acme.rapidmx.test");
            expect(mail.subject).toBe(`ACME: ${mail.tokenPart1}`);
            expect(mail.tokenPart1).toMatch(/^[A-Za-z0-9_-]{43}$/);
            expect(mail.messageId).toMatch(/^<.+@.+>$/);
            // token-part1 travels only by e-mail: the token in the challenge is the other half.
            expect(challenge.token).not.toBe(mail.tokenPart1);
            expect(challenge.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
            expect(challenge).toMatchObject({ type: "email-reply-00", status: "pending", from: "acme-challenge@acme.rapidmx.test" });
            expect(challenge.url).toMatch(/\/acme\/chall\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+$/);
            expect(JSON.stringify(challenge)).not.toContain(mail.tokenPart1);
        });

        it("goes out once, however often (and however concurrently) the authorization is fetched", async () => {
            const email = uniqueEmail("once");
            const order = await client.newOrder(email);
            const authzUrl = order.json.authorizations[0];
            for (let i = 0; i < 3; i++) {
                await client.post(authzUrl);
            }
            expect(ca.mailer.sent.filter((m) => m.to === email)).toHaveLength(1);

            const email2 = uniqueEmail("race");
            const order2 = await client.newOrder(email2);
            const nonces = await Promise.all([1, 2, 3, 4, 5].map(() => client.freshNonce()));
            await Promise.all(nonces.map((nonce) => client.post(order2.json.authorizations[0], undefined, { nonce })));
            expect(ca.mailer.sent.filter((m) => m.to === email2)).toHaveLength(1);
        });

        it("is retried on the next fetch when the relay refused it, without failing the fetch", async () => {
            const email = uniqueEmail("relay");
            const order = await client.newOrder(email);
            const real = ca.mailer.send.bind(ca.mailer);
            ca.mailer.send = async () => {
                throw new Error("relay refused");
            };
            try {
                const first = await client.post(order.json.authorizations[0]);
                expect(first.status).toBe(200);
                expect(first.json.challenges[0].status).toBe("pending");
                expect(lastMail(ca, email)).toBeUndefined();
            } finally {
                ca.mailer.send = real;
            }
            await client.post(order.json.authorizations[0]);
            expect(lastMail(ca, email)).toBeDefined();
        });

        it("is not sent for an authorization that is no longer pending", async () => {
            const email = uniqueEmail("gone");
            const order = await client.newOrder(email);
            await client.post(order.json.authorizations[0], { status: "deactivated" });
            await client.post(order.json.authorizations[0]).catch(() => undefined);
            expect(lastMail(ca, email)).toBeUndefined();
        });
    });

    describe("validation", () => {
        it("becomes valid when the reply arrives BEFORE the client says it is ready", async () => {
            const { email, authzUrl, orderUrl, mail, challenge } = await started();
            const reply = await client.replyTo(mail, challenge.token);
            expect((await ingest(ca.baseUrl, ca.inboundSecret, reply)).status).toBe(202);
            // A verified reply alone changes nothing the client can see: it still has to say it is ready.
            expect(await challengeStatus(authzUrl)).toMatchObject({ authz: "pending", challenge: "pending" });

            const ready = await client.post(challenge.url, {});
            expect(ready.status).toBe(200);
            expect(ready.json.status).toBe("valid");
            expect(ready.json.validated).toBeDefined();
            expect(ready.headers.get("link")).toContain(`<${authzUrl}>;rel="up"`);
            expect(await challengeStatus(authzUrl)).toMatchObject({ authz: "valid", challenge: "valid" });
            expect((await client.post(orderUrl)).json.status).toBe("ready");
            expect(email).toBeDefined();
        });

        it("becomes valid when the reply arrives AFTER the client says it is ready", async () => {
            const { authzUrl, orderUrl, mail, challenge } = await started();
            const ready = await client.post(challenge.url, {});
            expect(ready.json.status).toBe("processing");
            expect(await challengeStatus(authzUrl)).toMatchObject({ authz: "pending", challenge: "processing" });

            await ingest(ca.baseUrl, ca.inboundSecret, await client.replyTo(mail, challenge.token));
            expect(await challengeStatus(authzUrl)).toMatchObject({ authz: "valid", challenge: "valid" });
            expect((await client.post(orderUrl)).json.status).toBe("ready");
        });

        it("treats the client's ready POST as idempotent, and a POST-as-GET as a read", async () => {
            const { mail, challenge } = await started();
            await ingest(ca.baseUrl, ca.inboundSecret, await client.replyTo(mail, challenge.token));
            expect((await client.post(challenge.url, {})).json.status).toBe("valid");
            expect((await client.post(challenge.url, {})).json.status).toBe("valid");
            const read = await client.post(challenge.url);
            expect(read.status).toBe(200);
            expect(read.json.status).toBe("valid");
        });

        it("invalidates the challenge, the authorization and the order on a wrong digest", async () => {
            const { authzUrl, orderUrl, mail, challenge } = await started();
            await client.post(challenge.url, {});
            await ingest(ca.baseUrl, ca.inboundSecret, await client.replyTo(mail, challenge.token, { digest: "A".repeat(43) }));
            const after = await challengeStatus(authzUrl);
            expect(after).toMatchObject({ authz: "invalid", challenge: "invalid" });
            expect(after.body.challenges[0].error).toMatchObject({ type: "urn:ietf:params:acme:error:incorrectResponse", status: 400 });
            const order = await client.post(orderUrl);
            expect(order.json.status).toBe("invalid");
            expect(order.json.error.type).toBe("urn:ietf:params:acme:error:incorrectResponse");

            // Too late for the genuine reply: the authorization is gone.
            await ingest(ca.baseUrl, ca.inboundSecret, await client.replyTo(mail, challenge.token));
            expect((await challengeStatus(authzUrl)).authz).toBe("invalid");
        });

        it("rejects a digest computed with another account's key: only the account that ordered can answer", async () => {
            const { authzUrl, mail, challenge } = await started();
            const other = await AcmeTestClient.create(ca.baseUrl);
            await other.register();
            await client.post(challenge.url, {});
            await ingest(ca.baseUrl, ca.inboundSecret, await other.replyTo(mail, challenge.token));
            expect((await challengeStatus(authzUrl)).authz).toBe("invalid");
        });

        it("ignores a reply that is not DKIM-signed for the sender's domain, and accepts the genuine one after it", async () => {
            const { authzUrl, mail, challenge } = await started();
            await client.post(challenge.url, {});
            await ingest(ca.baseUrl, ca.inboundSecret, await client.replyTo(mail, challenge.token, { unsigned: true }));
            expect(await challengeStatus(authzUrl)).toMatchObject({ authz: "pending", challenge: "processing" });
            await ingest(ca.baseUrl, ca.inboundSecret, await client.replyTo(mail, challenge.token));
            expect(await challengeStatus(authzUrl)).toMatchObject({ authz: "valid" });
        });

        it("ignores a reply whose sender is not the address being verified, even when it is properly signed", async () => {
            const { authzUrl, mail, challenge } = await started();
            await client.post(challenge.url, {});
            await ingest(ca.baseUrl, ca.inboundSecret, await client.replyTo(mail, challenge.token, { from: "mallory@example.com" }));
            expect(await challengeStatus(authzUrl)).toMatchObject({ authz: "pending", challenge: "processing" });
            // Case in the address does not matter.
            await ingest(ca.baseUrl, ca.inboundSecret, await client.replyTo(mail, challenge.token, { from: mail.to.toUpperCase() }));
            expect(await challengeStatus(authzUrl)).toMatchObject({ authz: "valid" });
        });

        it("ignores replies for tokens it never issued, and mail that is not a reply at all", async () => {
            const { authzUrl, mail, challenge } = await started();
            await client.post(challenge.url, {});
            const stranger = { ...mail, subject: `ACME: ${"z".repeat(43)}`, tokenPart1: "z".repeat(43) };
            expect((await ingest(ca.baseUrl, ca.inboundSecret, await client.replyTo(stranger, challenge.token))).status).toBe(202);
            for (const junk of ["not an email at all", "", "From: a@example.com\r\n\r\nhello"]) {
                const response = await ingest(ca.baseUrl, ca.inboundSecret, Buffer.from(junk));
                expect([202, 400]).toContain(response.status);
            }
            expect(await challengeStatus(authzUrl)).toMatchObject({ authz: "pending", challenge: "processing" });
        });

        it("cannot be completed twice: replaying the same reply changes nothing", async () => {
            const { authzUrl, orderUrl, mail, challenge } = await started();
            await client.post(challenge.url, {});
            const reply = await client.replyTo(mail, challenge.token);
            await ingest(ca.baseUrl, ca.inboundSecret, reply);
            const first = (await client.post(authzUrl)).json;
            await ingest(ca.baseUrl, ca.inboundSecret, reply);
            expect((await client.post(authzUrl)).json).toEqual(first);
            expect((await client.post(orderUrl)).json.status).toBe("ready");
        });

        it("ignores a reply after the authorization expired", async () => {
            const { authzUrl, mail, challenge } = await started();
            await client.post(challenge.url, {});
            const realNow = ca.ctx.now;
            ca.ctx.now = () => new Date(Date.now() + 8 * 86400_000);
            try {
                await ingest(ca.baseUrl, ca.inboundSecret, await client.replyTo(mail, challenge.token));
                expect((await challengeStatus(authzUrl)).authz).toBe("expired");
            } finally {
                ca.ctx.now = realNow;
            }
        });

        it("keeps a challenge to its own account", async () => {
            const { challenge, authzUrl } = await started();
            const other = await AcmeTestClient.create(ca.baseUrl);
            await other.register();
            const url = challenge.url as string;
            expect((await other.post(url, {})).json.type).toBe("urn:ietf:params:acme:error:unauthorized");
            expect((await other.post(authzUrl)).json.type).toBe("urn:ietf:params:acme:error:unauthorized");
            const wrong = url.replace(/[^/]+$/, "wrongChallengeId00000000");
            const reply: Reply = await client.post(wrong, {});
            expect(reply.status).toBe(404);
        });
    });

    describe("the HTTP ingest route", () => {
        it("requires the bearer secret and answers nothing about what it did", async () => {
            const { mail, challenge } = await started();
            const raw = await client.replyTo(mail, challenge.token);
            const url = `${ca.baseUrl}/internal/mail/inbound`;
            const call = (headers: Record<string, string>, body: Buffer = raw) =>
                fetch(url, { method: "POST", headers: { "content-type": "message/rfc822", ...headers }, body: new Uint8Array(body) });
            expect((await call({})).status).toBe(401);
            expect((await call({ authorization: "Bearer wrong" })).status).toBe(401);
            expect((await call({ authorization: `Basic ${ca.inboundSecret}` })).status).toBe(401);
            expect((await call({ authorization: `Bearer ${ca.inboundSecret}` }, Buffer.alloc(0))).status).toBe(400);
            const ok = await call({ authorization: `Bearer ${ca.inboundSecret}`, "x-envelope-from": "a@example.com", "x-remote-address": "192.0.2.9" });
            expect(ok.status).toBe(202);
            expect(await ok.json()).toEqual({ accepted: true });
        });

        it("does not exist when no secret is configured", async () => {
            const bare = await startCa({ "acme:mail:inbound:http_secret": "" });
            try {
                const response = await fetch(`${bare.baseUrl}/internal/mail/inbound`, { method: "POST", headers: { authorization: "Bearer " }, body: "x" });
                expect(response.status).toBe(404);
            } finally {
                await bare.stop();
            }
        }, 60_000);
    });

    describe("the built-in SMTP receiver", () => {
        it("accepts the reply straight over SMTP and completes the challenge", async () => {
            const probe = net.createServer();
            const port: number = await new Promise((resolve) => probe.listen(0, "127.0.0.1", () => resolve((probe.address() as net.AddressInfo).port)));
            await new Promise((resolve) => probe.close(resolve));
            const smtp = await startCa({ "acme:mail:inbound:smtp:enabled": true, "acme:mail:inbound:smtp:host": "127.0.0.1", "acme:mail:inbound:smtp:port": port });
            try {
                const c = await AcmeTestClient.create(smtp.baseUrl);
                await c.register();
                const email = uniqueEmail("smtp");
                const order = await c.newOrder(email);
                const authz = await c.post(order.json.authorizations[0]);
                const challenge = authz.json.challenges[0];
                const mail = lastMail(smtp, email);
                const raw = await c.replyTo(mail, challenge.token);

                const transport = nodemailer.createTransport({ host: "127.0.0.1", port, secure: false, ignoreTLS: true } as any);
                const wrongRecipient = transport.sendMail({ raw, envelope: { from: email, to: ["someone-else@acme.rapidmx.test"] } });
                await expect(wrongRecipient).rejects.toThrow();
                await transport.sendMail({ raw, envelope: { from: email, to: ["acme-response@acme.rapidmx.test"] } });

                await c.post(challenge.url, {});
                expect((await c.post(order.json.authorizations[0])).json.status).toBe("valid");
            } finally {
                await smtp.stop();
            }
        }, 60_000);
    });
});
