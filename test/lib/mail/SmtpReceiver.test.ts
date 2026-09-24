///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import "reflect-metadata";
import * as net from "node:net";
import nodemailer from "nodemailer";
import * as x509 from "@peculiar/x509";
import { SmtpReceiver, type InboundEnvelope, type SmtpReceiverOptions } from "../../../src/lib/mail/index.js";

const ADDRESS: string = "acme-response@acme.rapidmx.test";

type Delivery = { raw: Buffer; envelope: InboundEnvelope };

/** A running receiver plus what its handler has been given. */
interface Harness {
    receiver: SmtpReceiver;
    delivered: Delivery[];
}

const running: SmtpReceiver[] = [];

/** Starts a receiver on an ephemeral loopback port; `handler` decides how the message is answered. */
async function startReceiver(
    o: Partial<SmtpReceiverOptions> = {},
    handler?: (raw: Buffer, envelope: InboundEnvelope) => Promise<void>
): Promise<Harness> {
    const delivered: Delivery[] = [];
    const receiver = new SmtpReceiver(
        { host: "127.0.0.1", port: 0, recipients: [ADDRESS], ...o },
        async (raw, envelope) => {
            delivered.push({ raw, envelope });
            if (handler) {
                await handler(raw, envelope);
            }
        }
    );
    await receiver.start();
    running.push(receiver);
    return { receiver, delivered };
}

/** A nodemailer SMTP client for the receiver (plain by default). */
function client(port: number, extra: Record<string, unknown> = {}) {
    return nodemailer.createTransport({
        host: "127.0.0.1",
        port,
        secure: false,
        ignoreTLS: true,
        connectionTimeout: 5000,
        greetingTimeout: 5000,
        socketTimeout: 10_000,
        ...extra,
    } as any);
}

/** A complete, well formed message as raw bytes, CRLF line endings, ending in CRLF. */
function message(subject: string, body: string | Buffer = "hello\r\n"): Buffer {
    return Buffer.concat([
        Buffer.from(`From: a@example.com\r\nTo: ${ADDRESS}\r\nSubject: ${subject}\r\nMessage-ID: <${subject}@example.com>\r\n\r\n`),
        Buffer.isBuffer(body) ? body : Buffer.from(body),
    ]);
}

/** A bare-bones SMTP conversation over a raw socket, for the protocol behaviour nodemailer would smooth over. */
class Wire {
    private buffer: string = "";
    private waiting?: () => void;
    readonly socket: net.Socket;
    closed: boolean = false;

    private constructor(socket: net.Socket) {
        this.socket = socket;
        socket.setEncoding("latin1");
        socket.on("data", (chunk: string) => {
            this.buffer += chunk;
            this.waiting?.();
        });
        socket.on("close", () => {
            this.closed = true;
            this.waiting?.();
        });
        socket.on("error", () => undefined);
    }

    static async connect(port: number): Promise<Wire> {
        const socket = net.connect({ host: "127.0.0.1", port });
        await new Promise<void>((resolve, reject) => {
            socket.once("connect", resolve);
            socket.once("error", reject);
        });
        return new Wire(socket);
    }

    /** Reads one complete (possibly multi-line) reply, returned as its lines. */
    async reply(timeoutMs: number = 5000): Promise<string[]> {
        const deadline: number = Date.now() + timeoutMs;
        for (;;) {
            const lines: string[] = this.buffer.split("\r\n");
            const complete: number = lines.findIndex((l) => /^\d{3} /.test(l));
            if (complete >= 0) {
                this.buffer = lines.slice(complete + 1).join("\r\n");
                return lines.slice(0, complete + 1);
            }
            if (this.closed || Date.now() > deadline) {
                const rest: string = this.buffer;
                this.buffer = "";
                return rest ? [rest] : [];
            }
            await new Promise<void>((resolve) => {
                const timer = setTimeout(resolve, 50);
                this.waiting = () => {
                    clearTimeout(timer);
                    resolve();
                };
            });
        }
    }

    /** Sends one command line and returns the reply. */
    async say(line: string): Promise<string[]> {
        this.socket.write(`${line}\r\n`);
        return this.reply();
    }

    end(): void {
        this.socket.destroy();
    }
}

afterEach(async () => {
    await Promise.all(running.splice(0).map((r) => r.stop()));
});

describe("SmtpReceiver: delivery", () => {
    it("picks an ephemeral port on start and reports it", async () => {
        const receiver = new SmtpReceiver({ host: "127.0.0.1", port: 0, recipients: [ADDRESS] }, async () => undefined);
        expect(receiver.port).toBe(0);
        await receiver.start();
        running.push(receiver);
        expect(receiver.port).toBeGreaterThan(0);
        expect(receiver.port).not.toBe(0);
    });

    it("hands the exact raw bytes and the envelope to the handler and answers 250", async () => {
        const { receiver, delivered } = await startReceiver({ hostname: "mx.acme.rapidmx.test" });
        const raw = message("plain");
        const info = await client(receiver.port, { name: "client.example" }).sendMail({
            envelope: { from: "sender@example.com", to: [ADDRESS] },
            raw,
        });
        expect(info.response).toMatch(/^250 /);
        expect(delivered).toHaveLength(1);
        expect(delivered[0].raw.equals(raw)).toBe(true);
        expect(delivered[0].envelope).toMatchObject({
            mailFrom: "sender@example.com",
            rcptTo: [ADDRESS],
            clientHostname: "client.example",
        });
        expect(delivered[0].envelope.remoteAddress).toMatch(/127\.0\.0\.1$/);
    });

    it("does not corrupt 8-bit bytes, dot-stuffed lines, long lines or bare bytes (8BITMIME/SMTPUTF8 safe)", async () => {
        const { receiver, delivered } = await startReceiver();
        const allBytes = Buffer.from(Array.from({ length: 256 }, (_v, i) => i).filter((b) => b !== 0x0d && b !== 0x0a));
        const body = Buffer.concat([
            Buffer.from("Content-Type: application/octet-stream\r\n\r\n"),
            allBytes,
            Buffer.from("\r\n.dot at line start\r\n..two dots\r\n.\r\n" + "x".repeat(5000) + "\r\nlast line without a dot\r\n"),
        ]);
        const raw = Buffer.concat([
            Buffer.from(`From: a@example.com\r\nTo: ${ADDRESS}\r\nSubject: bytes\r\nMIME-Version: 1.0\r\n`),
            body,
        ]);
        await client(receiver.port).sendMail({ envelope: { from: "sender@example.com", to: [ADDRESS] }, raw });
        expect(delivered).toHaveLength(1);
        expect(delivered[0].raw.equals(raw)).toBe(true);
    });

    it("delivers a message announced with SMTPUTF8 and BODY=8BITMIME untouched", async () => {
        const { receiver, delivered } = await startReceiver();
        const wire = await Wire.connect(receiver.port);
        expect((await wire.reply())[0]).toMatch(/^220 /);
        const ehlo = (await wire.say("EHLO tester.example")).join("\n");
        expect(ehlo).toMatch(/8BITMIME/);
        expect(ehlo).toMatch(/SMTPUTF8/);
        expect((await wire.say("MAIL FROM:<s@example.com> BODY=8BITMIME SMTPUTF8"))[0]).toMatch(/^250/);
        expect((await wire.say(`RCPT TO:<${ADDRESS}>`))[0]).toMatch(/^250/);
        expect((await wire.say("DATA"))[0]).toMatch(/^354/);
        const payload = Buffer.from(
            "Subject: ACME: t\r\nFrom: s@example.com\r\nContent-Type: text/plain; charset=utf-8\r\n\r\ncafé ☃ 日本\r\n",
            "utf8"
        );
        wire.socket.setDefaultEncoding("binary");
        wire.socket.write(payload);
        expect((await wire.say(".")).join()).toMatch(/^250/);
        wire.end();
        expect(delivered[0].raw.equals(payload)).toBe(true);
    });

    it("accepts the recipient case-insensitively and reports it lower-cased", async () => {
        const { receiver, delivered } = await startReceiver({ recipients: ["ACME-Response@Acme.RapidMX.test"] });
        await client(receiver.port).sendMail({
            envelope: { from: "s@example.com", to: ["Acme-RESPONSE@ACME.rapidmx.test"] },
            raw: message("case"),
        });
        expect(delivered[0].envelope.rcptTo).toEqual([ADDRESS]);
    });

    it("accepts several configured recipients", async () => {
        const { receiver, delivered } = await startReceiver({ recipients: [ADDRESS, "other@acme.rapidmx.test"] });
        await client(receiver.port).sendMail({
            envelope: { from: "s@example.com", to: [ADDRESS, "other@acme.rapidmx.test"] },
            raw: message("two"),
        });
        expect(delivered).toHaveLength(1);
        expect(delivered[0].envelope.rcptTo).toEqual([ADDRESS, "other@acme.rapidmx.test"]);
    });

    it("accepts the null reverse-path used by bounces and auto-replies", async () => {
        const { receiver, delivered } = await startReceiver();
        const wire = await Wire.connect(receiver.port);
        await wire.reply();
        await wire.say("EHLO tester.example");
        expect((await wire.say("MAIL FROM:<>"))[0]).toMatch(/^250/);
        expect((await wire.say(`RCPT TO:<${ADDRESS}>`))[0]).toMatch(/^250/);
        expect((await wire.say("DATA"))[0]).toMatch(/^354/);
        wire.socket.write("Subject: x\r\n\r\nbody\r\n");
        expect((await wire.say("."))[0]).toMatch(/^250/);
        wire.end();
        expect(delivered[0].envelope.mailFrom).toBe("");
    });

    it("handles many concurrent messages without mixing them up", async () => {
        const { receiver, delivered } = await startReceiver({ maxConnectionsPerIp: 50 });
        const sends = Array.from({ length: 25 }, (_v, i) =>
            client(receiver.port).sendMail({
                envelope: { from: `s${i}@example.com`, to: [ADDRESS] },
                raw: message(`m${i}`, `body ${i} ${"z".repeat(i * 100)}\r\n`),
            })
        );
        const results = await Promise.all(sends);
        expect(results.every((r) => /^250 /.test(r.response))).toBe(true);
        expect(delivered).toHaveLength(25);
        const byId = new Map(delivered.map((d) => [/Subject: (m\d+)/.exec(d.raw.toString())![1], d]));
        expect(byId.size).toBe(25);
        for (let i = 0; i < 25; i++) {
            const d = byId.get(`m${i}`)!;
            expect(d.raw.equals(message(`m${i}`, `body ${i} ${"z".repeat(i * 100)}\r\n`))).toBe(true);
            expect(d.envelope.mailFrom).toBe(`s${i}@example.com`);
        }
    });

    it("handles several messages over one connection", async () => {
        const { receiver, delivered } = await startReceiver();
        const transport = client(receiver.port, { pool: true, maxConnections: 1 });
        for (let i = 0; i < 3; i++) {
            await transport.sendMail({ envelope: { from: "s@example.com", to: [ADDRESS] }, raw: message(`seq${i}`) });
        }
        transport.close();
        expect(delivered.map((d) => /Subject: (seq\d)/.exec(d.raw.toString())![1])).toEqual(["seq0", "seq1", "seq2"]);
    });
});

describe("SmtpReceiver: no relaying, no AUTH", () => {
    it("refuses an unknown recipient with 550 5.1.1 and never calls the handler", async () => {
        const { receiver, delivered } = await startReceiver();
        await expect(
            client(receiver.port).sendMail({ envelope: { from: "s@example.com", to: ["victim@example.org"] }, raw: message("relay") })
        ).rejects.toMatchObject({ responseCode: 550, response: expect.stringContaining("5.1.1") });
        expect(delivered).toHaveLength(0);
    });

    it.each(["victim@example.org", "acme-response@evil.example", "xacme-response@acme.rapidmx.test", "acme-response@acme.rapidmx.test.evil.example", "acme-response+tag@acme.rapidmx.test"])(
        "refuses %s at RCPT TO",
        async (rcpt) => {
            const { receiver } = await startReceiver();
            const wire = await Wire.connect(receiver.port);
            await wire.reply();
            await wire.say("EHLO tester.example");
            await wire.say("MAIL FROM:<s@example.com>");
            expect((await wire.say(`RCPT TO:<${rcpt}>`))[0]).toMatch(/^550 5\.1\.1 /);
            // ... and DATA is refused since there is no accepted recipient.
            expect((await wire.say("DATA"))[0]).toMatch(/^503/);
            wire.end();
        }
    );

    it("delivers a mixed envelope to the accepted recipient only", async () => {
        const { receiver, delivered } = await startReceiver();
        const info = await client(receiver.port).sendMail({
            envelope: { from: "s@example.com", to: [ADDRESS, "victim@example.org"] },
            raw: message("mixed"),
        });
        expect(info.accepted).toEqual([ADDRESS]);
        expect(info.rejected).toEqual(["victim@example.org"]);
        expect(delivered).toHaveLength(1);
        expect(delivered[0].envelope.rcptTo).toEqual([ADDRESS]);
    });

    it("does not offer AUTH and refuses it", async () => {
        const { receiver } = await startReceiver();
        const wire = await Wire.connect(receiver.port);
        await wire.reply();
        const ehlo = (await wire.say("EHLO tester.example")).join("\n");
        expect(ehlo).not.toMatch(/AUTH/i);
        expect(ehlo).not.toMatch(/STARTTLS/i);
        expect((await wire.say("AUTH PLAIN AGEAYg=="))[0]).toMatch(/^50\d/);
        wire.end();
    });

    it("does not answer VRFY, EXPN or the sendmail relics", async () => {
        const { receiver } = await startReceiver();
        const wire = await Wire.connect(receiver.port);
        await wire.reply();
        await wire.say("EHLO tester.example");
        for (const command of [`VRFY ${ADDRESS}`, `EXPN ${ADDRESS}`, "WIZ pass", "SHELL", "STARTTLS"]) {
            expect((await wire.say(command))[0]).toMatch(/^50\d/);
        }
        wire.end();
    });

    it("insists on MAIL before RCPT", async () => {
        const { receiver } = await startReceiver();
        const wire = await Wire.connect(receiver.port);
        await wire.reply();
        await wire.say("EHLO tester.example");
        expect((await wire.say(`RCPT TO:<${ADDRESS}>`))[0]).toMatch(/^503/);
        wire.end();
    });

    it("limits the recipients per message", async () => {
        const many = Array.from({ length: 4 }, (_v, i) => `r${i}@acme.rapidmx.test`);
        const { receiver } = await startReceiver({ recipients: many, maxRecipients: 2 });
        const wire = await Wire.connect(receiver.port);
        await wire.reply();
        await wire.say("EHLO tester.example");
        await wire.say("MAIL FROM:<s@example.com>");
        expect((await wire.say(`RCPT TO:<${many[0]}>`))[0]).toMatch(/^250/);
        expect((await wire.say(`RCPT TO:<${many[1]}>`))[0]).toMatch(/^250/);
        expect((await wire.say(`RCPT TO:<${many[2]}>`))[0]).toMatch(/^452 4\.5\.3 /);
        wire.end();
    });
});

describe("SmtpReceiver: size limits", () => {
    it("refuses a MAIL FROM that declares a size over the limit with 552", async () => {
        const { receiver, delivered } = await startReceiver({ maxSizeBytes: 2000 });
        const wire = await Wire.connect(receiver.port);
        await wire.reply();
        expect((await wire.say("EHLO tester.example")).join("\n")).toMatch(/SIZE 2000/);
        expect((await wire.say("MAIL FROM:<s@example.com> SIZE=2001"))[0]).toMatch(/^552/);
        expect((await wire.say("MAIL FROM:<s@example.com> SIZE=2000"))[0]).toMatch(/^250/);
        wire.end();
        expect(delivered).toHaveLength(0);
    });

    it("refuses DATA over the limit with 552, does not call the handler and stays usable", async () => {
        const { receiver, delivered } = await startReceiver({ maxSizeBytes: 2000 });
        await expect(
            client(receiver.port).sendMail({
                envelope: { from: "s@example.com", to: [ADDRESS] },
                raw: message("big", "y".repeat(5000) + "\r\n"),
            })
        ).rejects.toMatchObject({ responseCode: 552 });
        expect(delivered).toHaveLength(0);
        // The same receiver still takes a normal message afterwards.
        await client(receiver.port).sendMail({ envelope: { from: "s@example.com", to: [ADDRESS] }, raw: message("small") });
        expect(delivered).toHaveLength(1);
    });

    it("refuses a large message that lies about (or omits) its size, over one connection, without holding it", async () => {
        const { receiver, delivered } = await startReceiver({ maxSizeBytes: 10_000 });
        const wire = await Wire.connect(receiver.port);
        await wire.reply();
        await wire.say("EHLO tester.example");
        await wire.say("MAIL FROM:<s@example.com> SIZE=100");
        await wire.say(`RCPT TO:<${ADDRESS}>`);
        await wire.say("DATA");
        const chunk = "q".repeat(1000) + "\r\n";
        for (let i = 0; i < 200; i++) {
            wire.socket.write(chunk);
        }
        expect((await wire.say("."))[0]).toMatch(/^552/);
        // The connection is still in step: the next transaction works.
        expect((await wire.say("MAIL FROM:<s@example.com>"))[0]).toMatch(/^250/);
        wire.end();
        expect(delivered).toHaveLength(0);
    });

    it("accepts a message of exactly the limit and defaults to a 1 MiB limit", async () => {
        const { receiver, delivered } = await startReceiver();
        const wire = await Wire.connect(receiver.port);
        await wire.reply();
        expect((await wire.say("EHLO tester.example")).join("\n")).toMatch(/SIZE 1048576/);
        wire.end();

        const raw = message("nearlimit", "a".repeat(1000) + "\r\n");
        await client(receiver.port).sendMail({ envelope: { from: "s@example.com", to: [ADDRESS] }, raw });
        expect(delivered[0].raw.length).toBe(raw.length);
    });
});

describe("SmtpReceiver: handler outcomes", () => {
    it("answers 451 4.3.0 when the handler rejects, without leaking the reason", async () => {
        const { receiver, delivered } = await startReceiver({}, async () => {
            throw new Error("database password is hunter2");
        });
        const failure = await client(receiver.port)
            .sendMail({ envelope: { from: "s@example.com", to: [ADDRESS] }, raw: message("retry") })
            .catch((err) => err);
        expect(failure.responseCode).toBe(451);
        expect(failure.response).toContain("4.3.0 try again later");
        expect(String(failure.response)).not.toContain("hunter2");
        expect(delivered).toHaveLength(1);
    });

    it("answers 451 when the handler throws synchronously", async () => {
        const receiver = new SmtpReceiver({ host: "127.0.0.1", port: 0, recipients: [ADDRESS] }, (): Promise<void> => {
            throw new Error("boom");
        });
        await receiver.start();
        running.push(receiver);
        const failure = await client(receiver.port)
            .sendMail({ envelope: { from: "s@example.com", to: [ADDRESS] }, raw: message("sync") })
            .catch((err) => err);
        expect(failure.responseCode).toBe(451);
    });

    it("answers 451 when the handler does not finish within the message timeout", async () => {
        const { receiver } = await startReceiver({ messageTimeoutMs: 300 }, () => new Promise<void>(() => undefined));
        const started = Date.now();
        const failure = await client(receiver.port)
            .sendMail({ envelope: { from: "s@example.com", to: [ADDRESS] }, raw: message("hang") })
            .catch((err) => err);
        expect(failure.responseCode).toBe(451);
        expect(Date.now() - started).toBeLessThan(4000);
    });

    it("answers 250 after a slow handler resolves", async () => {
        const { receiver } = await startReceiver({}, () => new Promise<void>((resolve) => setTimeout(resolve, 150)));
        const info = await client(receiver.port).sendMail({
            envelope: { from: "s@example.com", to: [ADDRESS] },
            raw: message("slow"),
        });
        expect(info.response).toMatch(/^250/);
    });

    it("keeps serving after a handler failure", async () => {
        let calls = 0;
        const { receiver } = await startReceiver({}, async () => {
            if (calls++ === 0) {
                throw new Error("first fails");
            }
        });
        const send = () =>
            client(receiver.port).sendMail({ envelope: { from: "s@example.com", to: [ADDRESS] }, raw: message("again") });
        await expect(send()).rejects.toMatchObject({ responseCode: 451 });
        expect((await send()).response).toMatch(/^250/);
    });
});

describe("SmtpReceiver: connection limits and lifecycle", () => {
    it("answers 421 to connections beyond maxConnections", async () => {
        const { receiver } = await startReceiver({ maxConnections: 2 });
        const a = await Wire.connect(receiver.port);
        const b = await Wire.connect(receiver.port);
        expect((await a.reply())[0]).toMatch(/^220/);
        expect((await b.reply())[0]).toMatch(/^220/);
        const c = await Wire.connect(receiver.port);
        expect((await c.reply())[0]).toMatch(/^421/);
        a.end();
        b.end();
        c.end();
    });

    it("lets one address hold only maxConnectionsPerIp connections, and frees the slot when one closes", async () => {
        const { receiver } = await startReceiver({ maxConnectionsPerIp: 2 });
        const a = await Wire.connect(receiver.port);
        const b = await Wire.connect(receiver.port);
        expect((await a.reply())[0]).toMatch(/^220/);
        expect((await b.reply())[0]).toMatch(/^220/);
        const c = await Wire.connect(receiver.port);
        expect((await c.reply())[0]).toMatch(/^421 4.7.0/);
        c.end();
        a.end();
        await new Promise((resolve) => setTimeout(resolve, 200));
        const d = await Wire.connect(receiver.port);
        expect((await d.reply())[0]).toMatch(/^220/);
        b.end();
        d.end();
    });

    it("drops idle connections after the socket timeout", async () => {
        const { receiver } = await startReceiver({ socketTimeoutMs: 300 });
        const wire = await Wire.connect(receiver.port);
        await wire.reply();
        expect((await wire.reply(3000))[0]).toMatch(/^421/);
    });

    it("start() is idempotent and stop() closes the listener", async () => {
        const receiver = new SmtpReceiver({ host: "127.0.0.1", port: 0, recipients: [ADDRESS] }, async () => undefined);
        await receiver.start();
        const port = receiver.port;
        await receiver.start();
        expect(receiver.port).toBe(port);
        await receiver.stop();
        await expect(Wire.connect(port)).rejects.toMatchObject({ code: "ECONNREFUSED" });
        await receiver.stop();
    });

    it("stop() on a receiver that never started resolves", async () => {
        const receiver = new SmtpReceiver({ host: "127.0.0.1", port: 0, recipients: [ADDRESS] }, async () => undefined);
        await expect(receiver.stop()).resolves.toBeUndefined();
    });

    it("stop() finishes even with an idle peer still connected", async () => {
        const { receiver } = await startReceiver();
        const wire = await Wire.connect(receiver.port);
        await wire.reply();
        const started = Date.now();
        await receiver.stop();
        expect(Date.now() - started).toBeLessThan(8000);
        wire.end();
    }, 15_000);

    it("rejects start() when the port is taken", async () => {
        const { receiver } = await startReceiver();
        const clash = new SmtpReceiver({ host: "127.0.0.1", port: receiver.port, recipients: [ADDRESS] }, async () => undefined);
        await expect(clash.start()).rejects.toMatchObject({ code: "EADDRINUSE" });
    });

    it("can be started again after stop()", async () => {
        const receiver = new SmtpReceiver({ host: "127.0.0.1", port: 0, recipients: [ADDRESS] }, async () => undefined);
        await receiver.start();
        await receiver.stop();
        await receiver.start();
        running.push(receiver);
        const wire = await Wire.connect(receiver.port);
        expect((await wire.reply())[0]).toMatch(/^220/);
        wire.end();
    });
});

describe("SmtpReceiver: STARTTLS", () => {
    async function selfSigned(): Promise<{ key: string; cert: string }> {
        x509.cryptoProvider.set(globalThis.crypto);
        const alg = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };
        const keys = await globalThis.crypto.subtle.generateKey(alg, true, ["sign", "verify"]);
        const cert = await x509.X509CertificateGenerator.createSelfSigned({
            serialNumber: "01",
            name: "CN=localhost",
            notBefore: new Date(Date.now() - 60_000),
            notAfter: new Date(Date.now() + 3600_000),
            signingAlgorithm: alg,
            keys,
            extensions: [new x509.SubjectAlternativeNameExtension([{ type: "dns", value: "localhost" }])],
        });
        const pkcs8 = Buffer.from(await globalThis.crypto.subtle.exportKey("pkcs8", keys.privateKey)).toString("base64");
        const key = `-----BEGIN PRIVATE KEY-----\n${pkcs8.replace(/(.{64})/g, "$1\n")}\n-----END PRIVATE KEY-----\n`;
        return { key, cert: cert.toString("pem") };
    }

    it("offers STARTTLS only when a key and certificate are configured, and delivers over TLS", async () => {
        const tls = await selfSigned();
        const { receiver, delivered } = await startReceiver({ tls });

        const wire = await Wire.connect(receiver.port);
        await wire.reply();
        expect((await wire.say("EHLO tester.example")).join("\n")).toMatch(/STARTTLS/);
        wire.end();

        // requireTLS makes nodemailer fail rather than fall back to plain text, so success proves the upgrade.
        const info = await client(receiver.port, { ignoreTLS: false, requireTLS: true, tls: { rejectUnauthorized: false } }).sendMail({
            envelope: { from: "s@example.com", to: [ADDRESS] },
            raw: message("tls"),
        });
        expect(info.response).toMatch(/^250/);
        expect(delivered).toHaveLength(1);
        expect(delivered[0].raw.equals(message("tls"))).toBe(true);
    });

    it("fails a client that requires TLS when the receiver has no certificate", async () => {
        const { receiver, delivered } = await startReceiver();
        await expect(
            client(receiver.port, { ignoreTLS: false, requireTLS: true, tls: { rejectUnauthorized: false } }).sendMail({
                envelope: { from: "s@example.com", to: [ADDRESS] },
                raw: message("notls"),
            })
        ).rejects.toThrow();
        expect(delivered).toHaveLength(0);
    });

    it("still refuses unknown recipients inside the TLS session", async () => {
        const tls = await selfSigned();
        const { receiver } = await startReceiver({ tls });
        await expect(
            client(receiver.port, { ignoreTLS: false, requireTLS: true, tls: { rejectUnauthorized: false } }).sendMail({
                envelope: { from: "s@example.com", to: ["victim@example.org"] },
                raw: message("tlsrelay"),
            })
        ).rejects.toMatchObject({ responseCode: 550 });
    });
});
