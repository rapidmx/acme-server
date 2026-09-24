///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { canonicalMailbox, Mailbox } from "../pki/mailbox.js";
import { AcmeProblem } from "./AcmeProblem.js";

/** An ACME identifier as it appears in orders and authorizations. */
export interface AcmeIdentifier {
    type: "email";
    value: string;
}

/** A validated e-mail identifier. */
export interface EmailIdentifier {
    /** `local@domain` with the domain as lower-case A-labels and the local part NFC-normalized – what the order and authorization carry. */
    address: string;
    local: string;
    /** The domain as A-labels: what DNS look-ups, CAA and the SMTP envelope use. */
    domain: string;
    /** The domain as U-labels (the same as `domain` for an ASCII domain). */
    unicodeDomain: string;
    /** The whole address lower-cased: the key for rate limits, look-ups and the From comparison. */
    normalized: string;
    /** Whether the local part is non-ASCII, so the certificate carries an SmtpUTF8Mailbox (RFC 8398) instead of an rfc822Name. */
    smtpUtf8: boolean;
}

/**
 * Top-level domains that can never be a real mailbox host. Refused up front so a stranger cannot make this CA send mail
 * into (or resolve names under) private and reserved namespaces.
 */
export const DEFAULT_FORBIDDEN_TLDS: readonly string[] = ["test", "example", "invalid", "localhost", "local", "internal", "onion", "arpa", "lan", "home", "corp"];

/** The most labels a mail domain may have: no real mailbox host has more, and it bounds the CAA names climbed per order. */
const MAX_DOMAIN_LABELS = 12;

/**
 * Validates and normalizes an `email` identifier value (RFC 8823 §3), ASCII or internationalized (RFC 6531).
 *
 * Deliberately narrower than RFC 5321: a plain dot-atom local part and a fully-qualified domain (U-labels or A-labels; stored
 * as A-labels). No quoted local parts, comments, IP literals or single-label domains, none of which a mailbox owner using this
 * CA has. A non-ASCII local part is fine and gets an `SmtpUTF8Mailbox` in the certificate; it must be NFC (see
 * `canonicalMailbox()`), and the domain's IDNA conversion must be lossless.
 *
 * @throws `malformed` for a syntactically invalid value, `rejectedIdentifier` for a reserved domain or an IP address.
 */
export function parseEmailIdentifier(value: unknown, forbiddenTlds: readonly string[] = DEFAULT_FORBIDDEN_TLDS): EmailIdentifier {
    if (typeof value !== "string" || value.length === 0) {
        throw AcmeProblem.malformed("The identifier value must be an e-mail address.");
    }
    if (value.length > 320 || value.trim() !== value) {
        throw new AcmeProblem("malformed", "The e-mail address is too long or has surrounding whitespace.");
    }
    const at: number = value.lastIndexOf("@");
    if (at > 0 && /.[0-9]+$/.test(value.slice(at + 1))) {
        throw new AcmeProblem("rejectedIdentifier", "IP addresses are not accepted as the domain of an e-mail address.");
    }
    const mailbox: Mailbox | undefined = canonicalMailbox(value);
    if (!mailbox) {
        throw new AcmeProblem(
            "malformed",
            "The identifier is not a plain local@domain e-mail address (a non-ASCII local part must be NFC-normalized, and the domain a valid fully-qualified name).",
        );
    }
    const labels: string[] = mailbox.asciiDomain.split(".");
    if (labels.length > MAX_DOMAIN_LABELS) {
        throw new AcmeProblem("malformed", "The domain of the e-mail address has too many labels.");
    }
    const tld: string = labels[labels.length - 1];
    if (forbiddenTlds.includes(tld)) {
        throw new AcmeProblem("rejectedIdentifier", `The top-level domain '.${tld}' is reserved and cannot receive certificates.`);
    }
    return {
        address: mailbox.canonical,
        local: mailbox.local,
        domain: mailbox.asciiDomain,
        unicodeDomain: mailbox.unicodeDomain,
        normalized: mailbox.key,
        smtpUtf8: mailbox.form === "smtputf8",
    };
}

/**
 * Whether two addresses are the same mailbox, the way the From-header check compares them: case-insensitive, NFC, and a domain
 * spelled as U-labels or A-labels is the same domain. Values that are not valid addresses compare as trimmed lower-case text.
 */
export function sameAddress(a: string, b: string): boolean {
    const x: Mailbox | undefined = canonicalMailbox(a.trim());
    const y: Mailbox | undefined = canonicalMailbox(b.trim());
    if (x && y) {
        return x.key === y.key;
    }
    return a.trim().toLowerCase() === b.trim().toLowerCase();
}
