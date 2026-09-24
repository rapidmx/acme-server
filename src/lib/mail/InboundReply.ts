///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { simpleParser, type ParsedMail } from "mailparser";
import { dkimVerify } from "mailauth/lib/dkim/verify.js";
import { domainToASCII } from "node:url";

/**
 * What the ACME layer needs to know about a reply to a challenge e-mail (RFC 8823 section 3.2).
 *
 * Nothing here is trusted by itself: `from` and `digest` are claims by whoever sent the mail. It is `dkimDomains`
 * (checked with `dkimAligned()`) that says which domain vouched for the message.
 */
export interface InboundReply {
    /** The Message-ID header, with angle brackets. */
    messageId?: string;
    /** Every message id in In-Reply-To, with angle brackets. */
    inReplyTo: string[];
    /** Lower-cased addr-spec of the From header; undefined when there is not exactly one From address. */
    from?: string;
    /** The decoded, unfolded Subject (empty when absent). */
    subject: string;
    /** `token-part1`, taken from a Subject matching `ACME: <token>` (any `Re:`/`Fwd:` style prefix is fine). */
    tokenPart1?: string;
    /** The base64url SHA-256 between the ACME RESPONSE markers of the first text part; only when well formed. */
    digest?: string;
    /** `d=` of every DKIM-Signature that verified AND signed the From header (lower-case, no duplicates). */
    dkimDomains: string[];
}

/** Resolves DNS names for DKIM key lookups; identical to the `resolver` option of `mailauth`. */
export type DnsTxtResolver = (name: string, rr: string) => Promise<unknown>;

/** Largest message `parseInboundReply()` will look at; a reply is a few hundred bytes of text. */
export const MAX_INBOUND_REPLY_BYTES: number = 2 * 1024 * 1024;

/** Upper bound on the time spent on DNS lookups and signature checks for one message. */
const VERIFY_TIMEOUT_MS: number = 15_000;

const BEGIN_MARKER: string = "-----BEGIN ACME RESPONSE-----";
const END_MARKER: string = "-----END ACME RESPONSE-----";
const DIGEST_PATTERN: RegExp = /^[A-Za-z0-9_-]{43}$/;
const SUBJECT_TOKEN_PATTERN: RegExp = /\bACME:\s*([A-Za-z0-9_-]+)/i;

/** A reply carrying nothing usable: what a message that cannot be parsed is reported as. */
function emptyReply(): InboundReply {
    return { inReplyTo: [], subject: "", dkimDomains: [] };
}

/**
 * Lower-cases a domain, drops one trailing dot and converts U-labels to A-labels, so an internationalized From domain aligns
 * with a `d=` written in Punycode (DKIM signing domains are A-labels) whichever spelling the sender's software used.
 */
function normalizeDomain(domain: string): string {
    const plain: string = domain.trim().toLowerCase().replace(/\.$/, "");
    return domainToASCII(plain) || plain;
}

/**
 * An address in a form two parsers can be compared in: local part lower-cased and NFC, domain as A-labels. The MIME parser and
 * the DKIM verifier may spell the same internationalized address differently (U-labels vs Punycode); they must still be
 * recognized as reading the same From.
 */
function comparableAddress(address: string): string {
    const at: number = address.lastIndexOf("@");
    if (at < 0) {
        return address.trim().toLowerCase();
    }
    return `${address.slice(0, at).trim().toLowerCase().normalize("NFC")}@${normalizeDomain(address.slice(at + 1))}`;
}

/**
 * Extracts the digest from a text body: the lines between the first `BEGIN ACME RESPONSE` and the following
 * `END ACME RESPONSE` marker, each stripped of surrounding whitespace and reply quoting (`> `).
 *
 * Tolerant of CRLF, indentation and quoting; strict about the result - a digest that is not exactly 43 base64url
 * characters is dropped, and only the first marked block counts so a later block cannot override it.
 */
function extractDigest(text: string): string | undefined {
    const lines: string[] = text.split(/\r\n|\r|\n/).map((line) => line.replace(/^[\s>]*/, "").trim());
    const begin: number = lines.indexOf(BEGIN_MARKER);
    if (begin < 0) {
        return undefined;
    }
    const end: number = lines.indexOf(END_MARKER, begin + 1);
    if (end < 0 || end - begin > 5) {
        return undefined;
    }
    // A mail client may wrap a long line, so the block is joined; the length check below keeps that honest.
    const digest: string = lines.slice(begin + 1, end).join("");
    return DIGEST_PATTERN.test(digest) ? digest : undefined;
}

/** Most DKIM-Signature headers a message may carry and still be verified: real mail has one to three, and each costs a DNS query. */
const MAX_DKIM_SIGNATURES: number = 8;

/** How many DKIM-Signature headers are in the header block of `raw`. */
function countDkimSignatures(raw: Buffer): number {
    const crlf: number = raw.indexOf(Buffer.from([13, 10, 13, 10]));
    const lf: number = raw.indexOf(Buffer.from([10, 10]));
    const limit: number = crlf >= 0 && (lf < 0 || crlf < lf) ? crlf : lf >= 0 ? lf : raw.length;
    return (raw.subarray(0, limit).toString("latin1").match(/^dkim-signature:/gim) ?? []).length;
}

/** Splits an In-Reply-To value into its message ids. */
function parseMessageIds(value: unknown): string[] {
    const text: string = Array.isArray(value) ? value.join(" ") : typeof value === "string" ? value : "";
    const bracketed: string[] = text.match(/<[^<>\s]+>/g) ?? [];
    return bracketed.length > 0 ? bracketed : text.split(/\s+/).filter((token) => token.length > 0);
}

/** Runs `work` but gives up after `ms` (the result is then `undefined`), so a stalled resolver cannot stall the inbound path. */
async function withTimeout<T>(work: Promise<T>, ms: number): Promise<T | undefined> {
    let timer: NodeJS.Timeout | undefined;
    try {
        return await Promise.race([
            work,
            new Promise<undefined>((resolve) => {
                timer = setTimeout(() => resolve(undefined), ms);
            }),
        ]);
    } finally {
        clearTimeout(timer);
    }
}

/**
 * The signing domains of the DKIM signatures on `raw` that count as evidence of who sent the message: verified,
 * covering the From header (RFC 6376 section 5.4 requires it; a signature that leaves From out proves nothing about
 * the visible sender), current, not SHA-1 (RFC 8301) and covering the entire body (no `l=` truncation, which would
 * let an attacker append content to a signed message).
 *
 * The From header the verifier saw must be the same single address the MIME parser saw - a parser differential is a
 * classic way to make a signature cover one From while the application reads another.
 */
async function verifiedSigningDomains(
    raw: Buffer,
    from: string | undefined,
    o: { resolver?: DnsTxtResolver; sender?: string }
): Promise<string[]> {
    if (!from) {
        return [];
    }
    const outcome: any = await withTimeout(
        dkimVerify(raw, { resolver: o.resolver as any, sender: o.sender, minBitLength: 1024 }),
        VERIFY_TIMEOUT_MS
    );
    if (!outcome || !Array.isArray(outcome.results)) {
        return [];
    }
    const headerFrom: string[] = Array.isArray(outcome.headerFrom) ? outcome.headerFrom : [];
    if (headerFrom.length !== 1 || comparableAddress(String(headerFrom[0])) !== comparableAddress(from)) {
        return [];
    }

    const domains: string[] = [];
    for (const result of outcome.results) {
        if (result?.status?.result !== "pass" || !result.signingDomain || result.signatureTimeValid === false) {
            continue;
        }
        const signedHeaders: string[] = String(result.signingHeaders?.keys ?? "")
            .split(":")
            .map((name) => name.trim().toLowerCase());
        if (!signedHeaders.includes("from")) {
            continue;
        }
        if (/sha1$/i.test(String(result.algo ?? ""))) {
            continue;
        }
        if (result.canonBodyLengthLimited === true && (result.status.underSized ?? 0) > 0) {
            continue;
        }
        const domain: string = normalizeDomain(String(result.signingDomain));
        if (!domains.includes(domain)) {
            domains.push(domain);
        }
    }
    return domains;
}

/**
 * Parses a reply to a challenge e-mail and verifies its DKIM signatures.
 *
 * Never throws on malformed mail - the result then simply has what could be read and no `dkimDomains`. It does throw
 * for input larger than `MAX_INBOUND_REPLY_BYTES`, because refusing to parse (and so to buffer) unbounded data is a
 * decision for the caller, who should answer the sender with a rejection instead of a validation failure. The only
 * network access is through `o.resolver` (default: the system resolver, for DKIM key records).
 *
 * @param raw The complete RFC 5322 message.
 * @param o.resolver DNS TXT resolver, injectable for tests and for a validating/caching resolver in production.
 * @param o.sender The SMTP envelope sender, when known (used only by the verifier for its own bookkeeping).
 * @param o.ip Reserved for the SMTP client address; DKIM does not use it, so it is accepted and ignored.
 * @param o.skipDkim Parse only: `dkimDomains` is empty and no DNS lookup is made. Lets a caller look the token up first and
 * pay for DKIM verification (one DNS query per signature) only for a message that names a live challenge.
 * @throws If `raw` exceeds `MAX_INBOUND_REPLY_BYTES`.
 */
export async function parseInboundReply(
    raw: Buffer | string,
    o: { resolver?: DnsTxtResolver; sender?: string; ip?: string; skipDkim?: boolean } = {}
): Promise<InboundReply> {
    const buffer: Buffer = typeof raw === "string" ? Buffer.from(raw, "utf8") : raw;
    if (buffer.length > MAX_INBOUND_REPLY_BYTES) {
        throw new Error(`Inbound message exceeds the ${MAX_INBOUND_REPLY_BYTES} byte limit.`);
    }

    let parsed: ParsedMail;
    try {
        parsed = await simpleParser(buffer, {
            skipHtmlToText: true,
            skipImageLinks: true,
            skipTextToHtml: true,
            skipTextLinks: true,
        });
    } catch {
        return emptyReply();
    }

    const fromAddresses: string[] = (parsed.from?.value ?? [])
        .map((entry) => (entry.address ?? "").trim().toLowerCase())
        .filter((address) => address.length > 0);
    const from: string | undefined = fromAddresses.length === 1 ? fromAddresses[0] : undefined;
    const subject: string = typeof parsed.subject === "string" ? parsed.subject : "";
    const tokenPart1: string | undefined = SUBJECT_TOKEN_PATTERN.exec(subject)?.[1];
    const digest: string | undefined = typeof parsed.text === "string" ? extractDigest(parsed.text) : undefined;

    let dkimDomains: string[] = [];
    if (!o.skipDkim && countDkimSignatures(buffer) <= MAX_DKIM_SIGNATURES) {
        try {
            dkimDomains = await verifiedSigningDomains(buffer, from, o);
        } catch {
            dkimDomains = [];
        }
    }

    return {
        ...(parsed.messageId ? { messageId: parsed.messageId } : {}),
        inReplyTo: parseMessageIds(parsed.inReplyTo),
        ...(from ? { from } : {}),
        subject,
        ...(tokenPart1 ? { tokenPart1 } : {}),
        ...(digest ? { digest } : {}),
        dkimDomains,
    };
}

/**
 * Whether the DKIM evidence on `reply` ties it to the domain of its From address.
 *
 * In `strict` mode some signing domain must equal the From domain (RFC 8823's expectation). In `relaxed` mode the
 * From domain may also be a subdomain of a signing domain. A signing domain must have at least two labels, so a bare
 * TLD never aligns; there is no public-suffix list here, which is acceptable because a signature by `d=example.co.uk`
 * still needs a key published under that exact name.
 *
 * @returns False when the reply has no (single) From address or no verified signature.
 */
export function dkimAligned(reply: InboundReply, mode: "strict" | "relaxed"): boolean {
    if (!reply.from) {
        return false;
    }
    const at: number = reply.from.lastIndexOf("@");
    if (at < 0) {
        return false;
    }
    const fromDomain: string = normalizeDomain(reply.from.slice(at + 1));
    if (!fromDomain) {
        return false;
    }
    return reply.dkimDomains.some((entry) => {
        const domain: string = normalizeDomain(entry);
        if (domain === fromDomain) {
            return true;
        }
        return mode === "relaxed" && domain.includes(".") && fromDomain.endsWith(`.${domain}`);
    });
}
