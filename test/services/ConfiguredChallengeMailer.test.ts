///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { generateKeyPairSync } from "crypto";
import { mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import * as net from "net";
import { SMTPServer } from "smtp-server";
import { dkimVerify } from "mailauth/lib/dkim/verify.js";
import { MemoryChallengeMailer } from "../../src/lib/mail/index.js";
import { ConfiguredChallengeMailer } from "../../src/services/ConfiguredChallengeMailer.js";

const configOf = (values: Record<string, unknown>) => ({ get: (key: string) => values[key] });
const mail = { to: "user@example.com", tokenPart1: "A".repeat(43), from: "acme-challenge@acme.example.org", replyTo: "acme-response@acme.example.org" };

describe("ConfiguredChallengeMailer", () => {
    const originalEnv = process.env.NODE_ENV;
    let relay: SMTPServer;
    let port: number;
    const received: Buffer[] = [];
    const dkim = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const privateKey = dkim.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const txt = `v=DKIM1; k=rsa; p=${dkim.publicKey.export({ type: "spki", format: "der" }).toString("base64")}`;
    let dir: string;

    beforeAll(async () => {
        dir = mkdtempSync(join(tmpdir(), "acme-mailer-"));
        relay = new SMTPServer({
            authOptional: true,
            disabledCommands: ["STARTTLS", "AUTH"],
            onData(stream, _session, done) {
                const chunks: Buffer[] = [];
                stream.on("data", (chunk: Buffer) => chunks.push(chunk));
                stream.on("end", () => {
                    received.push(Buffer.concat(chunks));
                    done();
                });
            },
        });
        port = await new Promise((resolve) => {
            const probe = net.createServer();
            probe.listen(0, "127.0.0.1", () => {
                const p = (probe.address() as net.AddressInfo).port;
                probe.close(() => resolve(p));
            });
        });
        await new Promise<void>((resolve) => relay.listen(port, "127.0.0.1", resolve));
    });

    afterAll(async () => {
        await new Promise<void>((resolve) => relay.close(() => resolve()));
        rmSync(dir, { recursive: true, force: true });
        process.env.NODE_ENV = originalEnv;
    });

    afterEach(() => {
        process.env.NODE_ENV = originalEnv;
        received.length = 0;
    });

    const verify = async (raw: Buffer) =>
        (
            await dkimVerify(raw, {
                resolver: async (name: string, rr: string) => {
                    if (rr === "TXT" && name === "s1._domainkey.acme.example.org") {
                        return [[txt]];
                    }
                    throw Object.assign(new Error("nx"), { code: "ENOTFOUND" });
                },
            })
        ).results[0]?.status?.result;

    it("keeps the mail in memory in development when no relay is configured", async () => {
        process.env.NODE_ENV = "development";
        const mailer = new ConfiguredChallengeMailer(configOf({}));
        const sent = await mailer.send(mail);
        expect(sent.messageId).toMatch(/^<.+@acme\.example\.org>$/);
        expect(mailer["delegate"]).toBeInstanceOf(MemoryChallengeMailer);
    });

    it("refuses to send anywhere else without a relay", async () => {
        process.env.NODE_ENV = "production";
        await expect(new ConfiguredChallengeMailer(configOf({})).send(mail)).rejects.toThrow(/No SMTP relay is configured/);
        process.env.NODE_ENV = "staging";
        await expect(new ConfiguredChallengeMailer(configOf({})).send(mail)).rejects.toThrow(/No SMTP relay/);
    });

    it("sends through the relay given as host and port, DKIM-signed with a key read from a file", async () => {
        const keyPath = join(dir, "dkim.pem");
        writeFileSync(keyPath, privateKey);
        const mailer = new ConfiguredChallengeMailer(
            configOf({
                "acme:mail:smtp:host": "127.0.0.1",
                "acme:mail:smtp:port": port,
                "acme:mail:smtp:ignore_tls": true,
                "acme:mail:dkim:domain": "acme.example.org",
                "acme:mail:dkim:selector": "s1",
                "acme:mail:dkim:private_key_path": keyPath,
            }),
        );
        const sent = await mailer.send(mail);
        expect(received).toHaveLength(1);
        const text = received[0].toString("utf8");
        expect(text).toMatch(/^Subject: ACME: A{43}$/m);
        expect(text).toContain(`Message-ID: ${sent.messageId}`);
        expect(await verify(received[0])).toBe("pass");
    });

    it("sends through a relay URL, with a key given inline", async () => {
        const mailer = new ConfiguredChallengeMailer(
            configOf({
                "acme:mail:smtp:url": `smtp://127.0.0.1:${port}/?ignoreTLS=true`,
                "acme:mail:dkim:domain": "acme.example.org",
                "acme:mail:dkim:selector": "s1",
                "acme:mail:dkim:private_key": privateKey,
            }),
        );
        await mailer.send(mail);
        expect(await verify(received[0])).toBe("pass");
    });

    it("sends unsigned only when no DKIM key is configured (which the production guard forbids), and builds the transport once", async () => {
        const mailer = new ConfiguredChallengeMailer(configOf({ "acme:mail:smtp:host": "127.0.0.1", "acme:mail:smtp:port": port, "acme:mail:smtp:ignore_tls": true }));
        await mailer.send(mail);
        await mailer.send(mail);
        expect(received).toHaveLength(2);
        expect(received[0].toString("utf8")).not.toMatch(/^DKIM-Signature:/im);
        const delegate = mailer["delegate"];
        await mailer.send(mail);
        expect(mailer["delegate"]).toBe(delegate);
    });

    it("authenticates to the relay when a user is configured", async () => {
        const seen: Array<{ username?: string; password?: string }> = [];
        const authRelay = new SMTPServer({
            allowInsecureAuth: true,
            disabledCommands: ["STARTTLS"],
            authMethods: ["PLAIN", "LOGIN"],
            onAuth(auth, _session, done) {
                seen.push({ username: auth.username, password: auth.password });
                done(null, { user: auth.username });
            },
            onData(stream, _session, done) {
                stream.on("data", () => undefined);
                stream.on("end", () => done());
            },
        });
        const authPort: number = await new Promise((resolve) => authRelay.listen(0, "127.0.0.1", () => resolve((authRelay.server.address() as net.AddressInfo).port)));
        try {
            const mailer = new ConfiguredChallengeMailer(
                configOf({ "acme:mail:smtp:host": "127.0.0.1", "acme:mail:smtp:port": authPort, "acme:mail:smtp:user": "relay-user", "acme:mail:smtp:pass": "relay-pass", "acme:mail:smtp:secure": false, "acme:mail:smtp:ignore_tls": true }),
            );
            await mailer.send(mail);
            expect(seen).toEqual([{ username: "relay-user", password: "relay-pass" }]);
        } finally {
            await new Promise<void>((resolve) => authRelay.close(() => resolve()));
        }
    });
});
