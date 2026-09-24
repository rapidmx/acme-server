///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import {
    MAX_INBOUND_REPLY_BYTES,
    dkimAligned,
    parseInboundReply,
    type InboundReply,
} from "../../../src/lib/mail/index.js";
import {
    SAMPLE_DIGEST,
    composeGenuineReply,
    composeMessage,
    makeDkimKey,
    makeResolver,
    signWithMailauth,
} from "./helpers.js";

const TOKEN: string = "kZ3xQ0mWv9Jt2sLr7aYb1nCdEfGhIjKlMnOpQrStUvW";
const IDENTITY: string = "Alice@Example.com";
const REPLY_TO: string = "acme-response@acme.rapidmx.test";
const CHALLENGE_SUBJECT: string = `ACME: ${TOKEN}`;
const CHALLENGE_ID: string = "<c0ffee@acme.rapidmx.test>";

const aliceKey = makeDkimKey("example.com", "sel");
const evilKey = makeDkimKey("evil.example", "x");
const resolver = makeResolver(aliceKey, evilKey);

/** Builds a reply as `@rapidmx/restapi` does, signed by `aliceKey` unless told otherwise. */
function genuine(extra: { text?: string; digest?: string } = {}, key = aliceKey, headerFieldNames?: string) {
    return composeGenuineReply(
        {
            identity: IDENTITY,
            replyTo: REPLY_TO,
            challengeSubject: CHALLENGE_SUBJECT,
            challengeMessageId: CHALLENGE_ID,
            ...extra,
        },
        { key, headerFieldNames }
    );
}

/** A minimal hand-written message, for cases nodemailer would not produce. */
function handWritten(headers: string[], body: string): Buffer {
    return Buffer.from(`${headers.join("\r\n")}\r\n\r\n${body}`, "utf8");
}

describe("parseInboundReply: a genuine reply", () => {
    it("extracts the fields and lists the verified signing domain", async () => {
        const reply = await parseInboundReply(await genuine(), { resolver });
        expect(reply.from).toBe("alice@example.com");
        expect(reply.subject).toBe(`Re: ${CHALLENGE_SUBJECT}`);
        expect(reply.tokenPart1).toBe(TOKEN);
        expect(reply.digest).toBe(SAMPLE_DIGEST);
        expect(reply.inReplyTo).toEqual([CHALLENGE_ID]);
        expect(reply.messageId).toMatch(/^<.+@.+>$/);
        expect(reply.dkimDomains).toEqual(["example.com"]);
        expect(dkimAligned(reply, "strict")).toBe(true);
        expect(dkimAligned(reply, "relaxed")).toBe(true);
    });

    it("accepts a string as well as a Buffer", async () => {
        const reply = await parseInboundReply((await genuine()).toString("utf8"), { resolver });
        expect(reply.dkimDomains).toEqual(["example.com"]);
        expect(reply.digest).toBe(SAMPLE_DIGEST);
    });

    it("looks up only the signing domain's key record", async () => {
        const r = makeResolver(aliceKey);
        await parseInboundReply(await genuine(), { resolver: r });
        expect(r.queries).toEqual(["TXT sel._domainkey.example.com"]);
    });

    it("works with unsigned mail: everything parsed, no DKIM domains", async () => {
        const raw = await composeGenuineReply({
            identity: IDENTITY,
            replyTo: REPLY_TO,
            challengeSubject: CHALLENGE_SUBJECT,
            challengeMessageId: CHALLENGE_ID,
        });
        const reply = await parseInboundReply(raw, { resolver });
        expect(reply.digest).toBe(SAMPLE_DIGEST);
        expect(reply.dkimDomains).toEqual([]);
        expect(dkimAligned(reply, "relaxed")).toBe(false);
    });
});

describe("parseInboundReply: DKIM evidence", () => {
    it("reports no domain when the body was tampered with after signing", async () => {
        const raw = (await genuine()).toString("utf8").replace(SAMPLE_DIGEST, "Z".repeat(43));
        const reply = await parseInboundReply(raw, { resolver });
        expect(reply.digest).toBe("Z".repeat(43));
        expect(reply.dkimDomains).toEqual([]);
    });

    it("reports no domain when a signed header was changed after signing", async () => {
        const raw = (await genuine()).toString("utf8").replace("From: Alice", "From: Mallory");
        const reply = await parseInboundReply(raw, { resolver });
        expect(reply.dkimDomains).toEqual([]);
    });

    it("lists only the signer when another domain signed the message (d=evil.example)", async () => {
        const reply = await parseInboundReply(await genuine({}, evilKey), { resolver });
        expect(reply.from).toBe("alice@example.com");
        expect(reply.dkimDomains).toEqual(["evil.example"]);
        expect(dkimAligned(reply, "strict")).toBe(false);
        expect(dkimAligned(reply, "relaxed")).toBe(false);
    });

    it("lists both domains when a message carries two valid signatures", async () => {
        const raw = await composeMessage(
            { from: IDENTITY, to: REPLY_TO, subject: "Re: ACME: t", text: "x\n" },
            { key: [aliceKey, evilKey] }
        );
        expect((raw.toString().match(/^DKIM-Signature:/gim) ?? []).length).toBe(2);
        const reply = await parseInboundReply(raw, { resolver });
        expect([...reply.dkimDomains].sort()).toEqual(["evil.example", "example.com"]);
        expect(dkimAligned(reply, "strict")).toBe(true);
    });

    it("ignores a signature that does not cover the From header", async () => {
        const raw = await genuine({}, aliceKey, "To:Subject:Date:Message-ID");
        const reply = await parseInboundReply(raw, { resolver });
        expect(reply.from).toBe("alice@example.com");
        expect(reply.dkimDomains).toEqual([]);
        expect(dkimAligned(reply, "strict")).toBe(false);
    });

    it("ignores a signature whose key cannot be found", async () => {
        const reply = await parseInboundReply(await genuine(), { resolver: makeResolver() });
        expect(reply.digest).toBe(SAMPLE_DIGEST);
        expect(reply.dkimDomains).toEqual([]);
    });

    it("ignores a signature when the resolver throws something odd", async () => {
        const reply = await parseInboundReply(await genuine(), {
            resolver: async () => {
                throw new Error("SERVFAIL");
            },
        });
        expect(reply.dkimDomains).toEqual([]);
        expect(reply.tokenPart1).toBe(TOKEN);
    });

    it("ignores a signature when the published key is a different one", async () => {
        const other = makeDkimKey("example.com", "sel");
        const reply = await parseInboundReply(await genuine(), { resolver: makeResolver(other) });
        expect(reply.dkimDomains).toEqual([]);
    });

    it("does not trust a message with two From headers, whatever is signed", async () => {
        const signed = (await genuine()).toString("utf8");
        const doubled = signed.replace(/^From: .*$/m, (line) => `${line}\r\nFrom: ceo@example.com`);
        const reply = await parseInboundReply(doubled, { resolver });
        expect(reply.dkimDomains).toEqual([]);
    });

    it("does not trust a From header naming several addresses", async () => {
        const raw = handWritten(
            ["From: a@example.com, b@example.com", "Subject: ACME: abc", "Message-ID: <m@example.com>"],
            "hello\r\n"
        );
        const reply = await parseInboundReply(raw, { resolver });
        expect(reply.from).toBeUndefined();
        expect(reply.dkimDomains).toEqual([]);
    });

    it("dedupes signing domains", async () => {
        // The same signature appears twice.
        const signed = (await genuine()).toString("utf8");
        const sigEnd = signed.indexOf("\r\nFrom:");
        const sigBlock = signed.slice(0, sigEnd + 2);
        const reply = await parseInboundReply(sigBlock + signed, { resolver });
        expect(reply.dkimDomains).toEqual(["example.com"]);
    });
});

describe("parseInboundReply: subject and token", () => {
    it.each([
        ["ACME: abc_DEF-123", "abc_DEF-123"],
        ["Re: ACME: abc_DEF-123", "abc_DEF-123"],
        ["RE: ACME: abc_DEF-123", "abc_DEF-123"],
        ["Fwd: Re: ACME: abc_DEF-123", "abc_DEF-123"],
        ["AW: ACME:abc_DEF-123", "abc_DEF-123"],
        ["[External] Re: ACME: abc_DEF-123 (auto)", "abc_DEF-123"],
    ])("reads the token from %j", async (subject, token) => {
        const raw = handWritten([`From: a@example.com`, `Subject: ${subject}`], "x\r\n");
        expect((await parseInboundReply(raw)).tokenPart1).toBe(token);
    });

    it("reads a folded Subject header", async () => {
        const raw = handWritten(["From: a@example.com", "Subject: Re:", " ACME:", "\tabc_DEF-123"], "x\r\n");
        const reply = await parseInboundReply(raw);
        expect(reply.tokenPart1).toBe("abc_DEF-123");
        expect(reply.subject).toBe("Re: ACME: abc_DEF-123");
    });

    it("reads an RFC 2047 encoded Subject", async () => {
        const encoded = `=?UTF-8?B?${Buffer.from("Re: ACME: tok_en-1").toString("base64")}?=`;
        const reply = await parseInboundReply(handWritten(["From: a@example.com", `Subject: ${encoded}`], "x\r\n"));
        expect(reply.tokenPart1).toBe("tok_en-1");
    });

    it.each(["Hello", "ACME", "ACME:", "ACME: ", "NOTACME: abc", "Re: acme"])("finds no token in %j", async (subject) => {
        const raw = handWritten(["From: a@example.com", `Subject: ${subject}`], "x\r\n");
        expect((await parseInboundReply(raw)).tokenPart1).toBeUndefined();
    });

    it("reports an empty subject when there is none", async () => {
        const reply = await parseInboundReply(handWritten(["From: a@example.com"], "x\r\n"));
        expect(reply.subject).toBe("");
        expect(reply.tokenPart1).toBeUndefined();
    });

    it("splits multiple In-Reply-To ids and tolerates a missing header", async () => {
        const raw = handWritten(
            ["From: a@example.com", "In-Reply-To: <one@x.example> <two@y.example>", "Message-ID: <me@example.com>"],
            "x\r\n"
        );
        const reply = await parseInboundReply(raw);
        expect(reply.inReplyTo).toEqual(["<one@x.example>", "<two@y.example>"]);
        expect(reply.messageId).toBe("<me@example.com>");
        expect((await parseInboundReply(handWritten(["From: a@example.com"], "x\r\n"))).inReplyTo).toEqual([]);
    });

    it("lower-cases the From address and uses the addr-spec of a display-name form", async () => {
        const raw = handWritten(['From: "Alice A." <ALICE@Example.COM>', "Subject: ACME: t"], "x\r\n");
        expect((await parseInboundReply(raw)).from).toBe("alice@example.com");
    });
});

describe("parseInboundReply: the digest", () => {
    const block = (digest: string = SAMPLE_DIGEST): string =>
        `-----BEGIN ACME RESPONSE-----\r\n${digest}\r\n-----END ACME RESPONSE-----\r\n`;
    const parse = (headers: string[], body: string) =>
        parseInboundReply(handWritten(["From: a@example.com", "Subject: ACME: t", ...headers], body));

    it("reads a CRLF body with markers", async () => {
        expect((await parse([], block())).digest).toBe(SAMPLE_DIGEST);
    });

    it("reads an LF-only body", async () => {
        expect((await parse([], block().replace(/\r\n/g, "\n"))).digest).toBe(SAMPLE_DIGEST);
    });

    it("tolerates surrounding text, blank lines, indentation and trailing whitespace", async () => {
        const body = `Hi,\r\n\r\nhere you go:\r\n\r\n   -----BEGIN ACME RESPONSE-----   \r\n\r\n  ${SAMPLE_DIGEST}  \r\n-----END ACME RESPONSE-----\t\r\n\r\nBye\r\n`;
        expect((await parse([], body)).digest).toBe(SAMPLE_DIGEST);
    });

    it("tolerates `> ` quoting in every form", async () => {
        const body = `> -----BEGIN ACME RESPONSE-----\r\n>${SAMPLE_DIGEST}\r\n> > -----END ACME RESPONSE-----\r\n`;
        expect((await parse([], body)).digest).toBe(SAMPLE_DIGEST);
        const spaced = `On Monday, someone wrote:\r\n> -----BEGIN ACME RESPONSE-----\r\n> ${SAMPLE_DIGEST}\r\n> -----END ACME RESPONSE-----\r\n`;
        expect((await parse([], spaced)).digest).toBe(SAMPLE_DIGEST);
    });

    it("decodes quoted-printable before looking for the markers", async () => {
        const qp = block().replace(/-/g, "=2D").replace(/\r\n/g, "\r\n");
        const reply = await parse(["Content-Type: text/plain; charset=utf-8", "Content-Transfer-Encoding: quoted-printable"], qp);
        expect(reply.digest).toBe(SAMPLE_DIGEST);
    });

    it("decodes a quoted-printable soft line break inside the digest", async () => {
        const body = `-----BEGIN ACME RESPONSE-----\r\n${SAMPLE_DIGEST.slice(0, 20)}=\r\n${SAMPLE_DIGEST.slice(20)}\r\n-----END ACME RESPONSE-----\r\n`;
        const reply = await parse(["Content-Transfer-Encoding: quoted-printable"], body);
        expect(reply.digest).toBe(SAMPLE_DIGEST);
    });

    it("decodes a base64 body", async () => {
        const reply = await parse(
            ["Content-Transfer-Encoding: base64"],
            Buffer.from(block()).toString("base64").replace(/(.{76})/g, "$1\r\n")
        );
        expect(reply.digest).toBe(SAMPLE_DIGEST);
    });

    it("reads the text/plain part of a multipart/alternative message", async () => {
        const raw = await composeMessage({
            from: "a@example.com",
            to: REPLY_TO,
            subject: "Re: ACME: t",
            text: block(),
            html: "<p>-----BEGIN ACME RESPONSE-----</p><p>" + "Y".repeat(43) + "</p><p>-----END ACME RESPONSE-----</p>",
        });
        expect(raw.toString()).toContain("multipart/alternative");
        expect((await parseInboundReply(raw)).digest).toBe(SAMPLE_DIGEST);
    });

    it("finds the text part when it is not the first part of multipart/mixed", async () => {
        const raw = await composeMessage({
            from: "a@example.com",
            to: REPLY_TO,
            subject: "Re: ACME: t",
            text: block(),
            attachments: [{ filename: "note.bin", content: Buffer.from("hello") }],
        });
        expect(raw.toString()).toContain("multipart/mixed");
        expect((await parseInboundReply(raw)).digest).toBe(SAMPLE_DIGEST);
    });

    it("ignores an HTML-only message", async () => {
        const raw = await composeMessage({
            from: "a@example.com",
            to: REPLY_TO,
            subject: "Re: ACME: t",
            html: `<pre>${block()}</pre>`,
        });
        expect((await parseInboundReply(raw)).digest).toBeUndefined();
    });

    it("uses only the first marked block", async () => {
        const second = "Q".repeat(43);
        const reply = await parse([], block() + block(second));
        expect(reply.digest).toBe(SAMPLE_DIGEST);
        // ... even when the first one is malformed: a later block must not be able to take over.
        expect((await parse([], block("short") + block(second))).digest).toBeUndefined();
    });

    it.each([
        ["too short", SAMPLE_DIGEST.slice(1)],
        ["too long", SAMPLE_DIGEST + "A"],
        ["padded base64", SAMPLE_DIGEST.slice(0, 42) + "="],
        ["standard base64 alphabet", "+".repeat(43)],
        ["inner whitespace", `${SAMPLE_DIGEST.slice(0, 10)} ${SAMPLE_DIGEST.slice(11)}`],
        ["empty", ""],
    ])("drops a digest that is %s", async (_name, digest) => {
        expect((await parse([], block(digest))).digest).toBeUndefined();
    });

    it("has no digest without markers, with only one marker, or with the markers reversed", async () => {
        expect((await parse([], `${SAMPLE_DIGEST}\r\n`)).digest).toBeUndefined();
        expect((await parse([], `-----BEGIN ACME RESPONSE-----\r\n${SAMPLE_DIGEST}\r\n`)).digest).toBeUndefined();
        expect((await parse([], `${SAMPLE_DIGEST}\r\n-----END ACME RESPONSE-----\r\n`)).digest).toBeUndefined();
        expect(
            (await parse([], `-----END ACME RESPONSE-----\r\n${SAMPLE_DIGEST}\r\n-----BEGIN ACME RESPONSE-----\r\n`)).digest
        ).toBeUndefined();
    });

    it("does not read a digest spread over an unreasonable number of lines", async () => {
        const body = `-----BEGIN ACME RESPONSE-----\r\n${SAMPLE_DIGEST.split("").join("\r\n")}\r\n-----END ACME RESPONSE-----\r\n`;
        expect((await parse([], body)).digest).toBeUndefined();
    });

    it("does not accept marker look-alikes", async () => {
        const body = `----BEGIN ACME RESPONSE----\r\n${SAMPLE_DIGEST}\r\n----END ACME RESPONSE----\r\n`;
        expect((await parse([], body)).digest).toBeUndefined();
        const inline = `x -----BEGIN ACME RESPONSE----- ${SAMPLE_DIGEST} -----END ACME RESPONSE-----\r\n`;
        expect((await parse([], inline)).digest).toBeUndefined();
    });
});

describe("parseInboundReply: hostile and broken input", () => {
    it("returns an empty result for garbage", async () => {
        const reply = await parseInboundReply("this is not an e-mail at all");
        expect(reply.dkimDomains).toEqual([]);
        expect(reply.from).toBeUndefined();
        expect(reply.digest).toBeUndefined();
        expect(reply.tokenPart1).toBeUndefined();
    });

    it("returns an empty result for empty input", async () => {
        expect(await parseInboundReply(Buffer.alloc(0))).toEqual({ inReplyTo: [], subject: "", dkimDomains: [] });
    });

    it("never throws on binary input", async () => {
        for (let seed = 1; seed <= 20; seed++) {
            const bytes = Buffer.alloc(4096);
            let x = seed * 2654435761;
            for (let i = 0; i < bytes.length; i++) {
                x = (x * 1664525 + 1013904223) >>> 0;
                bytes[i] = x >>> 24;
            }
            const reply = await parseInboundReply(bytes);
            expect(reply.dkimDomains).toEqual([]);
        }
    });

    it("never throws on mail with broken structure", async () => {
        const cases: string[] = [
            "From: a@example.com\r\nContent-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\nbroken",
            "From: <<<>>>\r\nSubject: ACME: x\r\n\r\n",
            "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh=AAAA; b=AAAA\r\nFrom: a@example.com\r\n\r\nbody",
            "DKIM-Signature: garbage\r\nFrom: a@example.com\r\n\r\nbody",
            "\r\n\r\n\r\n",
            "From: a@example.com\r\nSubject: =?UTF-8?B?????=\r\n\r\nx",
        ];
        for (const raw of cases) {
            const reply = await parseInboundReply(raw, { resolver });
            expect(reply.dkimDomains).toEqual([]);
        }
    });

    it("throws for input over the size limit and accepts input at it", async () => {
        await expect(parseInboundReply(Buffer.alloc(MAX_INBOUND_REPLY_BYTES + 1, 0x61))).rejects.toThrow(/limit/);
        const header = "From: a@example.com\r\nSubject: ACME: t\r\n\r\n";
        const atLimit = Buffer.concat([
            Buffer.from(header),
            Buffer.alloc(MAX_INBOUND_REPLY_BYTES - header.length, 0x61),
        ]);
        expect(atLimit.length).toBe(MAX_INBOUND_REPLY_BYTES);
        expect((await parseInboundReply(atLimit)).tokenPart1).toBe("t");
    });

    it("makes no DNS queries for mail without signatures", async () => {
        const r = makeResolver();
        await parseInboundReply(handWritten(["From: a@example.com", "Subject: ACME: t"], "x\r\n"), { resolver: r });
        expect(r.queries).toEqual([]);
    });

    /** A plain unsigned reply, for the tests that sign it in unusual ways. */
    const unsignedReply = (text?: string): Promise<Buffer> =>
        composeGenuineReply({
            identity: IDENTITY,
            replyTo: REPLY_TO,
            challengeSubject: CHALLENGE_SUBJECT,
            challengeMessageId: CHALLENGE_ID,
            ...(text !== undefined ? { text } : {}),
        });

    it("does not count a signature with a truncated body length (l=) that leaves content unsigned", async () => {
        // The signature covers only the first bytes of the body, so anything appended afterwards still verifies.
        const signed = await signWithMailauth(await unsignedReply("hello\r\n"), aliceKey, { maxBodyLength: 5 });
        expect((await parseInboundReply(signed, { resolver })).dkimDomains).toEqual([]);
        const appended = Buffer.concat([
            signed,
            Buffer.from(`-----BEGIN ACME RESPONSE-----\r\n${"Q".repeat(43)}\r\n-----END ACME RESPONSE-----\r\n`),
        ]);
        const tampered = await parseInboundReply(appended, { resolver });
        expect(tampered.digest).toBe("Q".repeat(43));
        expect(tampered.dkimDomains).toEqual([]);
    });

    it("counts a signature with an l= tag that covers the whole body", async () => {
        const unsigned = await unsignedReply();
        const bodyLength = unsigned.length - unsigned.indexOf("\r\n\r\n") - 4;
        const signed = await signWithMailauth(unsigned, aliceKey, { maxBodyLength: bodyLength });
        expect(signed.toString()).toContain(`l=${bodyLength}`);
        expect((await parseInboundReply(signed, { resolver })).dkimDomains).toEqual(["example.com"]);
    });

    it("does not count an rsa-sha1 signature (RFC 8301)", async () => {
        const signed = await signWithMailauth(await unsignedReply(), aliceKey, { algorithm: "rsa-sha1" });
        expect(signed.toString()).toContain("a=rsa-sha1");
        expect((await parseInboundReply(signed, { resolver })).dkimDomains).toEqual([]);
    });

    it("does not count an expired signature", async () => {
        const signed = await signWithMailauth(await unsignedReply(), aliceKey, {
            signTime: new Date(Date.now() - 7200_000),
            expires: new Date(Date.now() - 3600_000),
        });
        expect(signed.toString()).toMatch(/x=\d+/);
        expect((await parseInboundReply(signed, { resolver })).dkimDomains).toEqual([]);
    });

    it("refuses a message with a second From header even though the signature still verifies", async () => {
        const signed = await signWithMailauth(await unsignedReply(), aliceKey, {
            headerList: ["from", "to", "subject", "message-id", "in-reply-to"],
        });
        expect((await parseInboundReply(signed, { resolver })).dkimDomains).toEqual(["example.com"]);
        // A From header added above the signed one does not disturb the (bottom-up) verifier, but the message now has
        // two From headers and a mail client might display the other one.
        const forged = Buffer.concat([Buffer.from("From: ceo@example.com\r\n"), signed]);
        const reply = await parseInboundReply(forged, { resolver });
        expect(reply.dkimDomains).toEqual([]);
    });
});

describe("dkimAligned", () => {
    const reply = (from: string | undefined, dkimDomains: string[]): InboundReply => ({
        inReplyTo: [],
        subject: "",
        dkimDomains,
        ...(from ? { from } : {}),
    });

    it.each([
        // from, domains, strict, relaxed
        ["a@example.com", ["example.com"], true, true],
        ["a@example.com", ["EXAMPLE.COM"], true, true],
        ["a@example.com", ["example.com."], true, true],
        ["a@Example.Com", ["example.com"], true, true],
        ["a@mail.example.com", ["example.com"], false, true],
        ["a@deep.mail.example.com", ["example.com"], false, true],
        ["a@example.com", ["mail.example.com"], false, false],
        ["a@example.com", ["evil.example"], false, false],
        ["a@example.com", ["notexample.com"], false, false],
        ["a@notexample.com", ["example.com"], false, false],
        ["a@example.com", ["evil.example", "example.com"], true, true],
        ["a@example.com", [], false, false],
        ["a@example.com.evil.example", ["example.com"], false, false],
        ["a@example.com", ["com"], false, false],
        ["a@foo.com", ["com"], false, false],
        [undefined, ["example.com"], false, false],
    ] as Array<[string | undefined, string[], boolean, boolean]>)(
        "%s with d=%j: strict=%s relaxed=%s",
        (from, domains, strict, relaxed) => {
            expect(dkimAligned(reply(from, domains), "strict")).toBe(strict);
            expect(dkimAligned(reply(from, domains), "relaxed")).toBe(relaxed);
        }
    );

    it("is false for a From without a domain", () => {
        expect(dkimAligned(reply("nodomain", ["example.com"]), "relaxed")).toBe(false);
    });
});

describe("internationalized senders (RFC 6531)", () => {
    it("aligns a From written with U-labels to a signature whose d= is the Punycode domain, whichever way the verifier reads it", async () => {
        const { composeGenuineReply, makeDkimKey, makeResolver } = await import("./helpers.js");
        const { parseInboundReply, dkimAligned } = await import("../../../src/lib/mail/index.js");
        const key = makeDkimKey("xn--bcher-kva.com");
        for (const from of ["用户@bücher.com", "用户@xn--bcher-kva.com", "user@bücher.com", "user@xn--bcher-kva.com"]) {
            const raw = await composeGenuineReply(
                { identity: from, replyTo: "r@acme.example.org", challengeSubject: `ACME: ${"A".repeat(43)}`, challengeMessageId: "<x@y>", digest: "0".repeat(43) },
                { key },
            );
            const reply = await parseInboundReply(raw, { resolver: makeResolver(key) });
            expect(reply.dkimDomains, from).toEqual(["xn--bcher-kva.com"]);
            expect(dkimAligned(reply, "strict"), from).toBe(true);
        }
    });

    it("does not align a signature by a different domain, however the From is spelled", async () => {
        const { composeGenuineReply, makeDkimKey, makeResolver } = await import("./helpers.js");
        const { parseInboundReply, dkimAligned } = await import("../../../src/lib/mail/index.js");
        const key = makeDkimKey("example.com");
        const raw = await composeGenuineReply(
            { identity: "用户@bücher.com", replyTo: "r@acme.example.org", challengeSubject: `ACME: ${"A".repeat(43)}`, challengeMessageId: "<x@y>", digest: "0".repeat(43) },
            { key },
        );
        const reply = await parseInboundReply(raw, { resolver: makeResolver(key) });
        expect(dkimAligned(reply, "strict")).toBe(false);
    });
});
