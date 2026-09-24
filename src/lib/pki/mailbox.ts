///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { domainToASCII, domainToUnicode } from "node:url";

/** `id-on-SmtpUTF8Mailbox` (RFC 8398 section 3): the otherName that carries an internationalized mailbox in a certificate. */
export const SMTP_UTF8_MAILBOX_OID = "1.3.6.1.5.5.7.8.9";

/** The longest local part, in UTF-8 octets (RFC 5321 section 4.5.3.1.1). */
const MAX_LOCAL_OCTETS = 64;

const ASCII_ATEXT = /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+$/;
/** A non-ASCII code point that may appear in an internationalized local part: not a control, format (bidi, zero-width), separator, private-use or unassigned character. */
const UTF8_NON_ASCII = /^[^\p{C}\p{Z}]+$/u;
const DOMAIN_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * A mailbox in every form the CA needs it in.
 *
 * Which form goes into a certificate is decided by RFC 8399 section 2: a mailbox whose local part is plain ASCII is an
 * `rfc822Name` (IA5String) with the domain as A-labels, even when the domain is an IDN; only a mailbox with a non-ASCII local
 * part needs the `SmtpUTF8Mailbox` otherName of RFC 8398, whose UTF8String holds the domain as U-labels.
 */
export interface Mailbox {
    /** `rfc822` (ASCII local part) or `smtputf8` (non-ASCII local part). */
    form: "rfc822" | "smtputf8";
    /** The local part, NFC-normalized, case as given. */
    local: string;
    /** The domain as A-labels (Punycode), lower case: what DNS, SMTP envelopes and rfc822Name use. */
    asciiDomain: string;
    /** The domain as U-labels, NFC: what `SmtpUTF8Mailbox` carries. Equal to `asciiDomain` for an ASCII-only domain. */
    unicodeDomain: string;
    /** `local@asciiDomain`: the canonical identity of the mailbox, used for orders, look-ups and the SMTP envelope. */
    canonical: string;
    /** The string the certificate carries: `canonical` for `rfc822`, `local@unicodeDomain` for `smtputf8`. */
    certificateName: string;
    /** `canonical` lower-cased and NFC again: the key for rate limits and case-insensitive comparison. */
    key: string;
}

/**
 * Validates an e-mail address, ASCII or internationalized (RFC 6531 / 8398 / 8399), and returns its canonical forms.
 *
 * The rules are deliberately narrow: a dot-atom local part (no quoted strings, comments or display names) made of ASCII
 * `atext` and non-ASCII characters that are not control, format, separator, private-use or unassigned code points; NFC only
 * (a decomposed spelling is refused rather than silently rewritten, because the address the mailbox owner replies from
 * must be the address in the certificate); at most 64 UTF-8 octets; a fully qualified domain of at least two labels whose
 * IDNA conversion is lossless (compatibility mappings such as full-width letters are refused, not applied).
 *
 * @param input The candidate, as the client sent it (U-labels or A-labels in the domain).
 * @returns The mailbox, or `undefined` when it is not acceptable.
 */
export function canonicalMailbox(input: unknown): Mailbox | undefined {
    if (typeof input !== "string" || input.length < 3 || input.length > 320) {
        return undefined;
    }
    const at: number = input.lastIndexOf("@");
    if (at <= 0 || at !== input.indexOf("@")) {
        return undefined;
    }
    const local: string = input.slice(0, at);
    const rawDomain: string = input.slice(at + 1);
    if (local !== local.normalize("NFC") || Buffer.byteLength(local, "utf8") > MAX_LOCAL_OCTETS) {
        return undefined;
    }
    if (local.startsWith(".") || local.endsWith(".") || local.includes("..")) {
        return undefined;
    }
    for (const part of local.split(".")) {
        if (part.length === 0) {
            return undefined;
        }
        for (const character of part) {
            const ok: boolean = character.codePointAt(0)! < 0x80 ? ASCII_ATEXT.test(character) : UTF8_NON_ASCII.test(character);
            if (!ok) {
                return undefined;
            }
        }
    }

    const lowered: string = rawDomain.toLowerCase();
    if (lowered.length === 0 || lowered.startsWith(".") || lowered.endsWith(".") || lowered.includes("..")) {
        return undefined;
    }
    const asciiDomain: string = domainToASCII(lowered);
    if (asciiDomain === "" || asciiDomain.length > 253) {
        return undefined;
    }
    const labels: string[] = asciiDomain.split(".");
    if (labels.length < 2 || !labels.every((label) => DOMAIN_LABEL.test(label)) || /^[0-9]+$/.test(labels[labels.length - 1])) {
        return undefined;
    }
    const unicodeDomain: string = domainToUnicode(asciiDomain).normalize("NFC");
    // Lossless: what was sent must be exactly the A-label form or exactly the U-label form of the same name.
    if (lowered !== asciiDomain && lowered.normalize("NFC") !== unicodeDomain) {
        return undefined;
    }
    // A label that claims to be Punycode must decode to something (domainToUnicode leaves an invalid one as it was).
    if (labels.some((label) => label.startsWith("xn--")) && unicodeDomain === asciiDomain) {
        return undefined;
    }

    const form: Mailbox["form"] = /[^\p{ASCII}]/u.test(local) ? "smtputf8" : "rfc822";
    const canonical = `${local}@${asciiDomain}`;
    return {
        form,
        local,
        asciiDomain,
        unicodeDomain,
        canonical,
        certificateName: form === "smtputf8" ? `${local}@${unicodeDomain}` : canonical,
        key: canonical.toLowerCase().normalize("NFC"),
    };
}

/** DER encoding of a UTF8String: the value of `SmtpUTF8Mailbox`. */
export function derUtf8String(text: string): Uint8Array {
    const bytes: Buffer = Buffer.from(text, "utf8");
    let header: number[];
    if (bytes.length < 0x80) {
        header = [0x0c, bytes.length];
    } else if (bytes.length < 0x100) {
        header = [0x0c, 0x81, bytes.length];
    } else {
        header = [0x0c, 0x82, bytes.length >> 8, bytes.length & 0xff];
    }
    return new Uint8Array(Buffer.concat([Buffer.from(header), bytes]));
}

/**
 * Reads a DER UTF8String (definite length, the whole input), as carried in `SmtpUTF8Mailbox`.
 *
 * @returns The text, or `undefined` when the bytes are not exactly one well-formed UTF8String.
 */
export function readDerUtf8String(der: Uint8Array): string | undefined {
    if (der.length < 2 || der[0] !== 0x0c) {
        return undefined;
    }
    let length: number = der[1];
    let offset = 2;
    if (length & 0x80) {
        const count: number = length & 0x7f;
        if (count < 1 || count > 2 || der.length < 2 + count) {
            return undefined;
        }
        length = 0;
        for (let i = 0; i < count; i++) {
            length = (length << 8) | der[2 + i];
        }
        offset = 2 + count;
        if (length < 0x80) {
            return undefined;
        }
    }
    if (offset + length !== der.length) {
        return undefined;
    }
    try {
        return new TextDecoder("utf-8", { fatal: true }).decode(der.subarray(offset));
    } catch {
        return undefined;
    }
}
