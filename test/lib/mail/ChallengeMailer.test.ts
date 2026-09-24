///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import {
    MemoryChallengeMailer,
    SmtpChallengeMailer,
    SmtpReceiver,
    challengeSubject,
    composeChallengeMessage,
    dkimAligned,
    parseInboundReply,
    type ChallengeMail,
    type InboundEnvelope,
} from "../../../src/lib/mail/index.js";
import { makeDkimKey, makeResolver } from "./helpers.js";

const TOKEN: string = "kZ3xQ0mWv9Jt2sLr7aYb1nCdEfGhIjKlMnOpQrStUvW";
const key = makeDkimKey("acme.rapidmx.test", "mail1");

const mail: ChallengeMail = {
    to: "alice@example.com",
    tokenPart1: TOKEN,
    from: "acme-challenge@acme.rapidmx.test",
    replyTo: "acme-response@acme.rapidmx.test",
};

/** Unfolded header lines of a raw message, keyed by lower-cased name (last one wins). */
function headers(raw: string): Map<string, string> {
    const head: string = raw.slice(0, raw.indexOf("\r\n\r\n")).replace(/\r\n[ \t]+/g, " ");
    const result = new Map<string, string>();
    for (const line of head.split("\r\n")) {
        const colon: number = line.indexOf(":");
        result.set(line.slice(0, colon).toLowerCase(), line.slice(colon + 1).trim());
    }
    return result;
}

describe("challengeSubject", () => {
    it("is `ACME: <token-part1>`", () => {
        expect(challengeSubject(TOKEN)).toBe(`ACME: ${TOKEN}`);
    });

    it.each(["", "a b", "abc\r\nBcc: evil@example.com", "tok\nen", "tok=en", "täken"])("rejects %j", (token) => {
        expect(() => challengeSubject(token)).toThrow();
    });
});

describe("MemoryChallengeMailer", () => {
    it("composes every RFC 8823 header and records the raw message", async () => {
        const mailer = new MemoryChallengeMailer();
        const before: number = Date.now();
        const { messageId } = await mailer.send(mail);

        expect(mailer.sent).toHaveLength(1);
        const sent = mailer.sent[0];
        expect(sent).toMatchObject({ ...mail, messageId, subject: `ACME: ${TOKEN}` });
        expect(messageId).toMatch(/^<[0-9a-f]{32}@acme\.rapidmx\.test>$/);

        const h = headers(sent.raw);
        expect(h.get("from")).toBe("acme-challenge@acme.rapidmx.test");
        expect(h.get("to")).toBe("alice@example.com");
        expect(h.get("reply-to")).toBe("acme-response@acme.rapidmx.test");
        expect(h.get("subject")).toBe(`ACME: ${TOKEN}`);
        expect(h.get("message-id")).toBe(messageId);
        expect(h.get("auto-submitted")).toBe("auto-generated; type=acme");
        expect(h.get("mime-version")).toBe("1.0");
        expect(h.get("content-type")).toMatch(/^text\/plain/);
        const date: number = Date.parse(h.get("date") ?? "");
        expect(date).toBeGreaterThan(before - 60_000);
        expect(date).toBeLessThan(Date.now() + 60_000);
        expect(h.has("dkim-signature")).toBe(false);
    });

    it("keeps everything but the token out of the body and says nothing useful to an attacker", async () => {
        const mailer = new MemoryChallengeMailer();
        await mailer.send(mail);
        const body: string = mailer.sent[0].raw.slice(mailer.sent[0].raw.indexOf("\r\n\r\n") + 4);
        expect(body).not.toContain(TOKEN);
        expect(body).not.toContain("BEGIN ACME RESPONSE");
        expect(body).toMatch(/no action is needed/i);
        expect(body).toMatch(/ignore/i);
        expect(mailer.sent[0].raw.split(TOKEN)).toHaveLength(2); // only the Subject carries the token, once
    });

    it("uses a supplied Message-ID, adding the angle brackets when they are missing", async () => {
        const mailer = new MemoryChallengeMailer();
        expect((await mailer.send({ ...mail, messageId: "<abc123@acme.rapidmx.test>" })).messageId).toBe(
            "<abc123@acme.rapidmx.test>"
        );
        expect((await mailer.send({ ...mail, messageId: "def456@acme.rapidmx.test" })).messageId).toBe(
            "<def456@acme.rapidmx.test>"
        );
        expect(headers(mailer.sent[1].raw).get("message-id")).toBe("<def456@acme.rapidmx.test>");
    });

    it("generates distinct Message-IDs", async () => {
        const mailer = new MemoryChallengeMailer();
        const a = await mailer.send(mail);
        const b = await mailer.send(mail);
        expect(a.messageId).not.toBe(b.messageId);
    });

    it("signs with DKIM when configured, and parseInboundReply can verify the signature", async () => {
        const mailer = new MemoryChallengeMailer({ dkim: key });
        const { messageId } = await mailer.send(mail);
        const raw: string = mailer.sent[0].raw;

        const signature: string = headers(raw).get("dkim-signature") ?? "";
        expect(signature).toContain("d=acme.rapidmx.test");
        expect(signature).toContain("s=mail1");
        expect(signature).toMatch(/h=[^;]*\bfrom\b/i);
        expect(signature).toMatch(/h=[^;]*auto-submitted/i);

        const resolver = makeResolver(key);
        const parsed = await parseInboundReply(raw, { resolver });
        expect(parsed.from).toBe("acme-challenge@acme.rapidmx.test");
        expect(parsed.messageId).toBe(messageId);
        expect(parsed.tokenPart1).toBe(TOKEN);
        expect(parsed.dkimDomains).toEqual(["acme.rapidmx.test"]);
        expect(dkimAligned(parsed, "strict")).toBe(true);
        expect(resolver.queries).toEqual(["TXT mail1._domainkey.acme.rapidmx.test"]);
    });

    it("a DKIM signature no longer verifies when the Subject is altered in transit", async () => {
        const mailer = new MemoryChallengeMailer({ dkim: key });
        await mailer.send(mail);
        const altered: string = mailer.sent[0].raw.replace(`ACME: ${TOKEN}`, "ACME: forged");
        const parsed = await parseInboundReply(altered, { resolver: makeResolver(key) });
        expect(parsed.tokenPart1).toBe("forged");
        expect(parsed.dkimDomains).toEqual([]);
    });

    it("accepts a From in a subdomain of the DKIM domain but not an unrelated one", async () => {
        const parent = makeDkimKey("rapidmx.test", "p1");
        const ok = new MemoryChallengeMailer({ dkim: parent });
        await ok.send(mail);
        const parsed = await parseInboundReply(ok.sent[0].raw, { resolver: makeResolver(parent) });
        expect(parsed.dkimDomains).toEqual(["rapidmx.test"]);
        expect(dkimAligned(parsed, "strict")).toBe(false);
        expect(dkimAligned(parsed, "relaxed")).toBe(true);

        const unrelated = new MemoryChallengeMailer({ dkim: makeDkimKey("other.example", "p1") });
        await expect(unrelated.send(mail)).rejects.toThrow(/DKIM signing domain/);
    });

    it("validates the DKIM configuration at construction without echoing the key", () => {
        expect(() => new MemoryChallengeMailer({ dkim: { ...key, privateKey: "not a key SECRET-MARKER" } })).toThrow(
            /valid PEM/
        );
        try {
            new MemoryChallengeMailer({ dkim: { ...key, privateKey: "not a key SECRET-MARKER" } });
        } catch (err: any) {
            expect(String(err.message)).not.toContain("SECRET-MARKER");
        }
        expect(() => new MemoryChallengeMailer({ dkim: { ...key, selector: "bad selector" } })).toThrow(/selector/);
        expect(() => new MemoryChallengeMailer({ dkim: { ...key, domain: "no_dots" } })).toThrow(/domain/);
    });
});

describe("header injection and address validation", () => {
    const bad: Array<[string, Partial<ChallengeMail>]> = [
        ["CRLF in to", { to: "alice@example.com\r\nBcc: victim@example.net" }],
        ["LF in to", { to: "alice@example.com\nBcc: victim@example.net" }],
        ["CRLF in from", { from: "a@acme.rapidmx.test\r\nX-Evil: 1" }],
        ["CRLF in replyTo", { replyTo: "r@acme.rapidmx.test\r\nX-Evil: 1" }],
        ["CRLF in tokenPart1", { tokenPart1: "abc\r\nX-Evil: 1" }],
        ["CRLF in messageId", { messageId: "<a@b.example>\r\nX-Evil: 1" }],
        ["messageId with a space", { messageId: "<a b@c.example>" }],
        ["display name", { to: "Alice <alice@example.com>" }],
        ["two recipients", { to: "alice@example.com,bob@example.com" }],
        ["semicolon list", { to: "alice@example.com;bob@example.com" }],
        ["quoted local part", { to: '"a b"@example.com' }],
        ["angle brackets", { to: "<alice@example.com>" }],
        ["no domain", { to: "alice@" }],
        ["no local part", { to: "@example.com" }],
        ["single-label domain", { to: "alice@localhost" }],
        ["IP literal", { to: "alice@[127.0.0.1]" }],
        ["double dot", { to: "al..ice@example.com" }],
        ["leading dot", { to: ".alice@example.com" }],
        ["a non-ASCII domain (it must be A-labels)", { to: "alice@exämple.com" }],
        ["a non-ASCII sender", { from: "acmé@acme.example.org" }],
        ["a control character in an internationalized local part", { to: "alicé@example.com" }],
        ["a zero-width character in an internationalized local part", { to: "al​icé@example.com" }],
        ["an overlong internationalized local part", { to: `${"é".repeat(33)}@example.com` }],
        ["shell metacharacter", { to: "a|b@example.com" }],
        ["empty", { to: "" }],
        ["overlong local part", { to: `${"a".repeat(65)}@example.com` }],
        ["trailing dot domain", { to: "alice@example.com." }],
    ];

    it.each(bad)("rejects %s and composes nothing", async (_name, override) => {
        const mailer = new MemoryChallengeMailer();
        await expect(mailer.send({ ...mail, ...override })).rejects.toThrow();
        expect(mailer.sent).toHaveLength(0);
    });

    it("addresses an internationalized recipient (RFC 6531) in UTF-8", async () => {
        const mailer = new MemoryChallengeMailer();
        const sent = await mailer.send({ ...mail, to: "用户+tag@xn--bcher-kva.example.com" });
        expect(sent.messageId).toMatch(/^<.+>$/);
        expect(mailer.sent).toHaveLength(1);
        // The header is RFC 6532 UTF-8 with the domain as U-labels; the SMTP envelope keeps the A-label form.
        expect(mailer.sent[0].raw).toContain("To: 用户+tag@bücher.example.com");
    });

    it("accepts ordinary plus-addressing and subdomains", async () => {
        const mailer = new MemoryChallengeMailer();
        await mailer.send({ ...mail, to: "first.last+tag@mail.example.co.uk" });
        expect(headers(mailer.sent[0].raw).get("to")).toBe("first.last+tag@mail.example.co.uk");
    });

    it("composeChallengeMessage returns CRLF-only line endings", async () => {
        const composed = await composeChallengeMessage(mail);
        const text: string = composed.raw.toString("latin1");
        expect(text).not.toMatch(/[^\r]\n/);
    });
});

describe("SmtpChallengeMailer", () => {
    let receiver: SmtpReceiver;
    const received: Array<{ raw: Buffer; envelope: InboundEnvelope }> = [];

    beforeAll(async () => {
        receiver = new SmtpReceiver(
            { port: 0, host: "127.0.0.1", recipients: ["alice@example.com"] },
            async (raw, envelope) => {
                received.push({ raw, envelope });
            }
        );
        await receiver.start();
    });

    afterAll(async () => {
        await receiver.stop();
    });

    it("relays the DKIM-signed message and reports its Message-ID", async () => {
        const mailer = new SmtpChallengeMailer({
            smtp: { host: "127.0.0.1", port: receiver.port, ignoreTLS: true },
            dkim: key,
            hostname: "acme.rapidmx.test",
        });
        const { messageId } = await mailer.send(mail);
        mailer.close();

        expect(received).toHaveLength(1);
        expect(received[0].envelope.mailFrom).toBe("acme-challenge@acme.rapidmx.test");
        expect(received[0].envelope.rcptTo).toEqual(["alice@example.com"]);
        const parsed = await parseInboundReply(received[0].raw, { resolver: makeResolver(key) });
        expect(parsed.messageId).toBe(messageId);
        expect(parsed.tokenPart1).toBe(TOKEN);
        expect(parsed.dkimDomains).toEqual(["acme.rapidmx.test"]);
    });

    it("accepts a connection URL", async () => {
        const mailer = new SmtpChallengeMailer({ smtp: { url: `smtp://127.0.0.1:${receiver.port}/?ignoreTLS=true` } });
        await mailer.send(mail);
        mailer.close();
        expect(received).toHaveLength(2);
    });

    it("fails when the relay refuses the recipient", async () => {
        const mailer = new SmtpChallengeMailer({ smtp: { host: "127.0.0.1", port: receiver.port, ignoreTLS: true } });
        await expect(mailer.send({ ...mail, to: "nobody@example.com" })).rejects.toThrow();
        mailer.close();
    });

    it("fails when the relay is unreachable", async () => {
        const mailer = new SmtpChallengeMailer({ smtp: { host: "127.0.0.1", port: 1, ignoreTLS: true } });
        await expect(mailer.send(mail)).rejects.toThrow();
        mailer.close();
    });
});
