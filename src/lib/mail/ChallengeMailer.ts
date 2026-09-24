///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { createPrivateKey, randomBytes } from "node:crypto";
import nodemailer, { type Transporter } from "nodemailer";

/**
 * One RFC 8823 `email-reply-00` challenge e-mail the CA has to send.
 *
 * Only `tokenPart1` is ever put on the wire (in the Subject): `token-part2` and the account key thumbprint stay on the
 * server, which is what makes a reply a proof that the *mailbox owner* read the message.
 */
export interface ChallengeMail {
    /** The mailbox being validated (the `email` identifier's value). */
    to: string;
    /** RFC 8823 `token-part1`, base64url. Disclosed to the mailbox only, in the Subject. */
    tokenPart1: string;
    /** The challenge object's `from` and the message's From address. */
    from: string;
    /** Where the applicant must send the reply (the CA's inbound mailbox). */
    replyTo: string;
    /** An explicit Message-ID (with or without the angle brackets); generated in the From domain when absent. */
    messageId?: string;
}

/**
 * What the ACME layer needs from an outbound mail path, so tests and alternative back ends (an HTTP mail API, say) can
 * stand in for SMTP.
 */
export interface ChallengeMailTransport {
    /**
     * Sends one challenge e-mail.
     *
     * @returns The Message-ID the message carries (with angle brackets, exactly as in the header) - the value the
     * applicant will quote in `In-Reply-To`.
     */
    send(mail: ChallengeMail): Promise<{ messageId: string }>;
}

/** DKIM signing material for the challenge mail (RFC 8823: the challenge e-mail MUST be DKIM-signed). */
export interface ChallengeDkimOptions {
    /** The signing domain (`d=`); must be the From domain or a parent of it. */
    domain: string;
    /** The selector (`s=`); the public key lives at `<selector>._domainkey.<domain>`. */
    selector: string;
    /** RSA private key, PEM (PKCS#1 or PKCS#8). Never logged. */
    privateKey: string;
}

/** Outbound relay settings, either as a nodemailer URL or as discrete fields. */
export interface ChallengeSmtpOptions {
    /** `smtp://` / `smtps://` connection URL; takes precedence over the discrete fields. */
    url?: string;
    host?: string;
    port?: number;
    /** Implicit TLS (port 465 style). */
    secure?: boolean;
    auth?: { user: string; pass: string };
    /** Never upgrade to TLS (only ever appropriate for a relay on the same host/pod). */
    ignoreTLS?: boolean;
}

/** Options of `SmtpChallengeMailer`. */
export interface SmtpChallengeMailerOptions {
    smtp: ChallengeSmtpOptions;
    dkim?: ChallengeDkimOptions;
    /** The name announced in EHLO. */
    hostname?: string;
}

/** Options of `MemoryChallengeMailer`: the same signing knobs, so a test can produce a genuinely signed message. */
export interface MemoryChallengeMailerOptions {
    dkim?: ChallengeDkimOptions;
    hostname?: string;
}

/** A challenge message, composed but not sent. */
export interface ComposedChallenge {
    /** The complete RFC 5322 message, CRLF line endings, DKIM-signed when a key was configured. */
    raw: Buffer;
    /** The Message-ID header value, with angle brackets. */
    messageId: string;
    subject: string;
}

/** `token-part1` is 256 random bits base64url encoded, but the alphabet is the only thing that matters for safety. */
const TOKEN_PATTERN: RegExp = /^[A-Za-z0-9_-]{1,512}$/;
const LOCAL_PART_PATTERN: RegExp = /^[A-Za-z0-9._%+=&'/!#*^~-]{1,64}$/;
/** An internationalized local part (RFC 6531): the ASCII set plus any non-ASCII character that is not a control, format, separator, private-use or unassigned code point. */
const LOCAL_PART_UTF8_PATTERN: RegExp = /^(?:[A-Za-z0-9._%+=&'/!#*^~-]|[^\p{ASCII}\p{C}\p{Z}])+$/u;
const DOMAIN_LABEL_PATTERN: RegExp = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;
const SELECTOR_PATTERN: RegExp = /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,61}[A-Za-z0-9])?$/;
const MESSAGE_ID_PATTERN: RegExp = /^<[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,128}@[A-Za-z0-9.-]{1,253}>$/;

/**
 * The header fields covered by the DKIM signature. Nodemailer's default list plus `Auto-Submitted`, so the
 * "this was sent by software" marker cannot be stripped or forged in transit without breaking the signature.
 */
const SIGNED_HEADERS: string =
    "From:Sender:Reply-To:Subject:Date:Message-ID:To:Cc:MIME-Version:Content-Type:Content-Transfer-Encoding:" +
    "In-Reply-To:References:Auto-Submitted";

/** The body of the challenge mail. Deliberately says nothing that helps anybody but the mailbox's software. */
const BODY_TEXT: string = [
    "This is an automated message from a certificate authority.",
    "",
    "Someone, or some software, asked for an S/MIME e-mail certificate for this mailbox. Software that requested one",
    "on your behalf answers this message by itself, so no action is needed from a person.",
    "",
    "If you did not ask for a certificate, you can ignore and delete this message. No certificate is issued for",
    "this address unless the message is answered from this mailbox.",
    "",
].join("\r\n");

/** Returns the lower-cased domain of a validated mailbox. */
function domainOf(mailbox: string): string {
    return mailbox.slice(mailbox.lastIndexOf("@") + 1).toLowerCase();
}

/**
 * Validates a bare `local@domain` mailbox and returns it unchanged.
 *
 * This CA sends mail to addresses that strangers name, so the check is intentionally narrower than RFC 5322: ASCII
 * only (except the recipient's local part, which may be internationalized per RFC 6531 - the domain is always A-labels, and
 * nodemailer then uses SMTPUTF8 with a relay that offers it), no quoted local parts, no comments, display names, angle brackets, whitespace or control characters (which
 * also closes header and SMTP command injection), a multi-label domain (never `user@localhost`), and a local part
 * without the characters that shell-based delivery agents treat specially.
 *
 * @param value The candidate mailbox.
 * @param label Names the field in the error message.
 * @throws If `value` is not a plain, safe mailbox.
 */
function requireMailbox(value: unknown, label: string, allowUtf8: boolean = false): string {
    if (typeof value !== "string" || value.length === 0 || value.length > 320) {
        throw new Error(`Invalid ${label}: not a usable e-mail address.`);
    }
    const at: number = value.lastIndexOf("@");
    const local: string = value.slice(0, at);
    const domain: string = value.slice(at + 1);
    const labels: string[] = domain.split(".");
    if (
        at <= 0 ||
        !(allowUtf8 ? LOCAL_PART_UTF8_PATTERN.test(local) && Buffer.byteLength(local, "utf8") <= 64 : LOCAL_PART_PATTERN.test(local)) ||
        local.startsWith(".") ||
        local.endsWith(".") ||
        local.includes("..") ||
        domain.length > 253 ||
        labels.length < 2 ||
        !labels.every((l) => DOMAIN_LABEL_PATTERN.test(l))
    ) {
        throw new Error(`Invalid ${label}: not a usable e-mail address.`);
    }
    return value;
}

/** Normalizes and validates a supplied Message-ID, wrapping it in angle brackets when they are missing. */
function requireMessageId(value: string): string {
    const bracketed: string = value.startsWith("<") ? value : `<${value}>`;
    if (!MESSAGE_ID_PATTERN.test(bracketed)) {
        throw new Error("Invalid messageId.");
    }
    return bracketed;
}

/**
 * The Subject of an RFC 8823 challenge e-mail: `ACME: <token-part1>`.
 *
 * @param tokenPart1 The base64url token part.
 * @throws If the token contains anything outside the base64url alphabet (which would also be a header injection
 * vector), or is empty.
 */
export function challengeSubject(tokenPart1: string): string {
    if (typeof tokenPart1 !== "string" || !TOKEN_PATTERN.test(tokenPart1)) {
        throw new Error("Invalid tokenPart1: must be a non-empty base64url string.");
    }
    return `ACME: ${tokenPart1}`;
}

/**
 * Checks the DKIM options early, so a broken configuration fails at start-up and not with the first applicant.
 * Error messages never include the key.
 */
function validateDkim(dkim: ChallengeDkimOptions): void {
    const labels: string[] = typeof dkim.domain === "string" ? dkim.domain.split(".") : [];
    if (labels.length < 2 || !labels.every((l) => DOMAIN_LABEL_PATTERN.test(l))) {
        throw new Error("Invalid DKIM domain.");
    }
    if (typeof dkim.selector !== "string" || !SELECTOR_PATTERN.test(dkim.selector)) {
        throw new Error("Invalid DKIM selector.");
    }
    try {
        createPrivateKey(dkim.privateKey);
    } catch {
        throw new Error("The DKIM private key is not a valid PEM private key.");
    }
}

/**
 * Builds the challenge message: validates every input, composes it with nodemailer and DKIM-signs it.
 *
 * Both `SmtpChallengeMailer` and `MemoryChallengeMailer` go through this one function so that what the tests capture is
 * byte-for-byte what would have been relayed.
 *
 * Headers (RFC 8823 section 3.1): From, To, Reply-To, Subject `ACME: <token-part1>`, Message-ID, Date, MIME-Version,
 * `Auto-Submitted: auto-generated; type=acme` and a text/plain body.
 *
 * @throws On any invalid input (CR/LF or other unsafe characters included) - nothing is composed in that case.
 */
export async function composeChallengeMessage(
    mail: ChallengeMail,
    o: { dkim?: ChallengeDkimOptions; hostname?: string } = {}
): Promise<ComposedChallenge> {
    const from: string = requireMailbox(mail.from, "from");
    const to: string = requireMailbox(mail.to, "to", true);
    const replyTo: string = requireMailbox(mail.replyTo, "replyTo");
    const subject: string = challengeSubject(mail.tokenPart1);
    const fromDomain: string = domainOf(from);
    const messageId: string =
        mail.messageId !== undefined
            ? requireMessageId(mail.messageId)
            : `<${randomBytes(16).toString("hex")}@${fromDomain}>`;

    if (o.dkim && fromDomain !== o.dkim.domain.toLowerCase() && !fromDomain.endsWith(`.${o.dkim.domain.toLowerCase()}`)) {
        // A signature by an unrelated domain would verify but never align with the From address: fail loudly.
        throw new Error("The DKIM signing domain is neither the From domain nor a parent of it.");
    }

    const composer: Transporter = nodemailer.createTransport({
        streamTransport: true,
        buffer: true,
        newline: "windows",
        name: o.hostname,
        ...(o.dkim
            ? {
                  dkim: {
                      domainName: o.dkim.domain,
                      keySelector: o.dkim.selector,
                      privateKey: o.dkim.privateKey,
                      headerFieldNames: SIGNED_HEADERS,
                  },
              }
            : {}),
    } as any);

    const info: any = await composer.sendMail({
        from,
        to,
        replyTo,
        subject,
        messageId,
        headers: { "Auto-Submitted": "auto-generated; type=acme" },
        text: BODY_TEXT,
        envelope: { from, to: [to] },
    });
    return { raw: info.message as Buffer, messageId, subject };
}

/**
 * Sends RFC 8823 challenge e-mails through an SMTP relay, DKIM-signed.
 *
 * The message is composed and signed first (`composeChallengeMessage()`) and only then handed to the relay as a raw
 * message, so what is signed is exactly what is sent. The SMTP envelope sender is the challenge From address, so
 * bounces come back to a mailbox the CA operates.
 *
 * @author Jean-Philippe Steinmetz
 */
export class SmtpChallengeMailer implements ChallengeMailTransport {
    private readonly transporter: Transporter;
    private readonly dkim?: ChallengeDkimOptions;
    private readonly hostname?: string;

    constructor(o: SmtpChallengeMailerOptions) {
        if (o.dkim) {
            validateDkim(o.dkim);
        }
        this.dkim = o.dkim;
        this.hostname = o.hostname;
        this.transporter = nodemailer.createTransport({
            ...(o.smtp.url ? { url: o.smtp.url } : {}),
            ...(o.smtp.host !== undefined ? { host: o.smtp.host } : {}),
            ...(o.smtp.port !== undefined ? { port: o.smtp.port } : {}),
            ...(o.smtp.secure !== undefined ? { secure: o.smtp.secure } : {}),
            ...(o.smtp.auth ? { auth: o.smtp.auth } : {}),
            ...(o.smtp.ignoreTLS !== undefined ? { ignoreTLS: o.smtp.ignoreTLS } : {}),
            ...(o.hostname ? { name: o.hostname } : {}),
            // A hung relay must not hold a request (the ACME authorization fetch) open indefinitely.
            connectionTimeout: 15_000,
            greetingTimeout: 15_000,
            socketTimeout: 30_000,
        } as any);
    }

    /**
     * Composes, signs and relays one challenge e-mail.
     *
     * @throws On invalid input, or when the relay refuses or cannot be reached (the caller decides whether to retry).
     */
    public async send(mail: ChallengeMail): Promise<{ messageId: string }> {
        const composed: ComposedChallenge = await composeChallengeMessage(mail, {
            dkim: this.dkim,
            hostname: this.hostname,
        });
        const info: any = await this.transporter.sendMail({
            envelope: { from: mail.from, to: [mail.to] },
            raw: composed.raw,
        });
        if (Array.isArray(info?.rejected) && info.rejected.length > 0) {
            throw new Error("The mail relay rejected the recipient of the challenge e-mail.");
        }
        return { messageId: composed.messageId };
    }

    /** Releases the transporter's resources (idle sockets); the mailer must not be used afterwards. */
    public close(): void {
        this.transporter.close();
    }
}

/**
 * A `ChallengeMailTransport` that only records what it would have sent, for tests and for running the service
 * without a relay. `sent` holds the composed raw message so a test (or a stub inbound path) can act as the mailbox.
 *
 * @author Jean-Philippe Steinmetz
 */
export class MemoryChallengeMailer implements ChallengeMailTransport {
    /** Every message accepted so far, oldest first. */
    public readonly sent: Array<ChallengeMail & { messageId: string; subject: string; raw: string }> = [];

    private readonly dkim?: ChallengeDkimOptions;
    private readonly hostname?: string;

    constructor(o: MemoryChallengeMailerOptions = {}) {
        if (o.dkim) {
            validateDkim(o.dkim);
        }
        this.dkim = o.dkim;
        this.hostname = o.hostname;
    }

    /** Validates and composes the message exactly as the SMTP mailer would, then records it instead of sending. */
    public async send(mail: ChallengeMail): Promise<{ messageId: string }> {
        const composed: ComposedChallenge = await composeChallengeMessage(mail, {
            dkim: this.dkim,
            hostname: this.hostname,
        });
        this.sent.push({
            ...mail,
            messageId: composed.messageId,
            subject: composed.subject,
            raw: composed.raw.toString("utf8"),
        });
        return { messageId: composed.messageId };
    }
}
