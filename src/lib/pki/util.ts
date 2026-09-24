///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import * as crypto from "node:crypto";

/** The largest serial number we ever issue or look up, in octets (RFC 5280 s4.1.2.2 allows 20). */
export const MAX_SERIAL_OCTETS = 20;

/**
 * Copies any binary view into a fresh, exactly-sized `Uint8Array`.
 *
 * @param data An ArrayBuffer or any typed-array/DataView.
 */
export function toBytes(data: ArrayBuffer | ArrayBufferView): Uint8Array {
    if (data instanceof ArrayBuffer) {
        return new Uint8Array(data.slice(0));
    }
    return new Uint8Array(data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength));
}

/**
 * Copies bytes into a standalone `ArrayBuffer`, which is what the ASN.1 schema classes expect (a `Uint8Array` may be a
 * window on a larger, pooled buffer).
 *
 * @param data The bytes to copy.
 */
export function toArrayBuffer(data: Uint8Array): ArrayBuffer {
    return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
}

/**
 * Concatenates byte arrays.
 *
 * @param parts The arrays to join, in order.
 */
export function concatBytes(...parts: Uint8Array[]): Uint8Array {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let offset = 0;
    for (const p of parts) {
        out.set(p, offset);
        offset += p.length;
    }
    return out;
}

/**
 * Lower-case hexadecimal encoding.
 *
 * @param data The bytes to encode.
 */
export function bytesToHex(data: Uint8Array): string {
    return Buffer.from(data.buffer, data.byteOffset, data.byteLength).toString("hex");
}

/**
 * Compares two byte strings without an early exit, so that comparing a secret against attacker input does not leak
 * where the first difference is. Lengths are not secret and may differ.
 *
 * @param a The first byte string.
 * @param b The second byte string.
 */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) {
        return false;
    }
    return crypto.timingSafeEqual(a, b);
}

/**
 * Removes the fractional seconds from a date. X.509, CRL and OCSP times are whole seconds (DER forbids fractions in
 * GeneralizedTime), so every timestamp is floored before it is either written or reported back to a caller; that way
 * the value returned by the library is the value inside the artefact.
 *
 * @param date The date to floor.
 */
export function floorToSecond(date: Date): Date {
    return new Date(Math.floor(date.getTime() / 1000) * 1000);
}

/**
 * PEM-encodes DER.
 *
 * @param der The DER bytes.
 * @param label The PEM label, e.g. `CERTIFICATE`, `X509 CRL`.
 */
export function derToPem(der: Uint8Array, label: string): string {
    const b64 = Buffer.from(der.buffer, der.byteOffset, der.byteLength).toString("base64");
    const lines = b64.match(/.{1,64}/g) ?? [];
    return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

/** One PEM block found in a text. */
export interface PemBlock {
    label: string;
    der: Uint8Array;
}

/**
 * Extracts every PEM block of a text, strictly: the base64 alphabet and padding are validated instead of letting
 * Node silently skip garbage.
 *
 * @param text A PEM file's contents.
 */
export function pemBlocks(text: string): PemBlock[] {
    const blocks: PemBlock[] = [];
    const re = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
        const body = m[2].replace(/\s+/g, "");
        if (!/^[A-Za-z0-9+/]*={0,2}$/.test(body) || body.length % 4 !== 0) {
            throw new Error(`Invalid base64 in PEM block ${m[1]}`);
        }
        blocks.push({ label: m[1], der: new Uint8Array(Buffer.from(body, "base64")) });
    }
    return blocks;
}

/**
 * Decodes the first PEM block of a text (or the first one with the given label).
 *
 * @param pem The PEM text.
 * @param label When set, only a block with exactly this label matches.
 * @throws Error when there is no matching block or its base64 is invalid.
 */
export function pemToDer(pem: string, label?: string): Uint8Array {
    const block = pemBlocks(pem).find((b) => label === undefined || b.label === label);
    if (!block) {
        throw new Error(label ? `No PEM block labelled ${label}` : "No PEM block found");
    }
    return block.der;
}

/**
 * SHA-256 as lower-case hex (the fingerprint format used everywhere in this service).
 *
 * @param data The bytes to hash.
 */
export function sha256Hex(data: Uint8Array): string {
    return crypto.createHash("sha256").update(data).digest("hex");
}

/**
 * A raw digest.
 *
 * @param algorithm One of the digests OCSP CertIDs may use.
 * @param data The bytes to hash.
 */
export function digest(algorithm: "sha1" | "sha256" | "sha384" | "sha512", data: Uint8Array): Uint8Array {
    return new Uint8Array(crypto.createHash(algorithm).update(data).digest());
}

/**
 * Unpadded base64url (RFC 4648 s5), the encoding ACME uses everywhere.
 *
 * @param data The bytes to encode.
 */
export function b64url(data: Uint8Array): string {
    return Buffer.from(data.buffer, data.byteOffset, data.byteLength).toString("base64url");
}

/**
 * Strict base64url decoding: only the URL-safe alphabet, no padding, no whitespace, and only the canonical encoding
 * (non-zero trailing bits are rejected), because a value that decodes leniently is a value two parties can disagree on.
 *
 * @param s The encoded string.
 * @throws Error when `s` is not canonical unpadded base64url.
 */
export function fromB64url(s: string): Uint8Array {
    if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) {
        throw new Error("Invalid base64url");
    }
    const bytes = new Uint8Array(Buffer.from(s, "base64url"));
    if (b64url(bytes) !== s) {
        throw new Error("Non-canonical base64url");
    }
    return bytes;
}

/**
 * Generates a certificate serial number: 20 random octets from the OS CSPRNG with the top bit cleared (so the DER
 * INTEGER is positive and needs no padding octet, giving 159 bits of entropy) and a non-zero first octet (so the
 * encoded length is always exactly 20 and the hex form always 40 characters). The Baseline Requirements ask for at least
 * 64 bits of CSPRNG output; 159 makes a collision or a guess irrelevant.
 */
export function randomSerial(): Uint8Array {
    for (;;) {
        const bytes = new Uint8Array(crypto.randomBytes(MAX_SERIAL_OCTETS));
        bytes[0] &= 0x7f;
        if (bytes[0] !== 0) {
            return bytes;
        }
    }
}

/**
 * Canonical hexadecimal form of a serial number: the INTEGER's content octets with any leading zero octets (the DER
 * sign padding) removed, lower-case, no separators. This is the form used as a database key, in `/certs/<serial>`
 * and in every lookup callback.
 *
 * @param content The DER INTEGER content octets (or a plain big-endian magnitude).
 * @returns The hex string, or `undefined` when the value is not a valid positive serial (empty, zero, negative, or over 20 octets).
 */
export function serialBytesToHex(content: Uint8Array): string | undefined {
    if (content.length === 0 || (content[0] & 0x80) !== 0) {
        // Empty, or a negative INTEGER (which would otherwise alias the positive value with the same bytes)
        return undefined;
    }
    let start = 0;
    while (start < content.length && content[start] === 0) {
        start++;
    }
    const magnitude = content.subarray(start);
    if (magnitude.length === 0 || magnitude.length > MAX_SERIAL_OCTETS) {
        return undefined;
    }
    return bytesToHex(magnitude);
}

/**
 * The inverse of {@link serialBytesToHex}: DER INTEGER content octets (with a `00` sign octet when the top bit is set)
 * for a canonical serial hex string.
 *
 * @param hex Even-length hex, 1 to 20 octets, not all zero.
 * @throws Error for anything that is not a valid positive serial.
 */
export function serialHexToDerContent(hex: string): Uint8Array {
    if (typeof hex !== "string" || !/^([0-9a-fA-F]{2}){1,21}$/.test(hex)) {
        throw new Error("Invalid serial number");
    }
    const bytes = new Uint8Array(Buffer.from(hex, "hex"));
    let start = 0;
    while (start < bytes.length && bytes[start] === 0) {
        start++;
    }
    const magnitude = bytes.subarray(start);
    if (magnitude.length === 0 || magnitude.length > MAX_SERIAL_OCTETS) {
        throw new Error("Invalid serial number");
    }
    return magnitude[0] & 0x80 ? concatBytes(Uint8Array.of(0), magnitude) : magnitude.slice();
}

const MAILBOX_ATEXT = /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+$/;
const DOMAIN_LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * Validates an e-mail address as this CA is willing to certify it and returns its canonical form (the domain
 * lower-cased; the local part is case-sensitive per RFC 5321 and left alone).
 *
 * The accepted grammar is intentionally narrower than RFC 5322: ASCII only (no SMTPUTF8 yet), a dot-atom local part of
 * at most 64 octets (the SMTP limit, and the X.520 upper bound if it ever lands in a CN), no quoted local parts, no
 * comments, no IP-address literals, a fully qualified LDH domain (at least two labels, no numeric TLD) of at most 253
 * octets and an overall length of at most 254. Anything else is rejected rather than "cleaned up", because the
 * address ends up in a certificate that a stranger will trust.
 *
 * @param email The address to check.
 * @returns The canonical address, or `undefined` when it is not acceptable.
 */
export function parseMailbox(email: string): string | undefined {
    if (typeof email !== "string" || email.length < 3 || email.length > 254) {
        return undefined;
    }
    const at = email.lastIndexOf("@");
    if (at <= 0 || at !== email.indexOf("@")) {
        return undefined;
    }
    const local = email.slice(0, at);
    const domain = email.slice(at + 1).toLowerCase();
    if (local.length > 64 || !MAILBOX_ATEXT.test(local.replace(/\./g, "a"))) {
        return undefined;
    }
    if (local.startsWith(".") || local.endsWith(".") || local.includes("..")) {
        return undefined;
    }
    if (domain.length > 253) {
        return undefined;
    }
    const labels = domain.split(".");
    if (labels.length < 2 || !labels.every((l) => DOMAIN_LABEL.test(l))) {
        return undefined;
    }
    if (/^[0-9]+$/.test(labels[labels.length - 1])) {
        return undefined;
    }
    return `${local}@${domain}`;
}
