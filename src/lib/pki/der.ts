///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { concatBytes } from "./util.js";

/**
 * A deliberately tiny DER encoder for the handful of primitives that are not X.509 structures and therefore have no
 * home in the `@peculiar/asn1-*` schemas: the PKCS #8 encryption envelope for a private key at rest and the
 * arbitrary-precision INTEGER of a CRL number. Every X.509 / CRL / OCSP structure is still assembled with the ASN.1
 * schema classes; this module never builds one.
 */

/**
 * Encodes a DER definite length.
 *
 * @param length The number of content octets.
 */
export function derLength(length: number): Uint8Array {
    if (!Number.isSafeInteger(length) || length < 0) {
        throw new RangeError("Invalid DER length");
    }
    if (length < 0x80) {
        return Uint8Array.of(length);
    }
    const bytes: number[] = [];
    let remaining = length;
    while (remaining > 0) {
        bytes.unshift(remaining & 0xff);
        remaining = Math.floor(remaining / 256);
    }
    return Uint8Array.of(0x80 | bytes.length, ...bytes);
}

/**
 * Encodes a tag-length-value triple.
 *
 * @param tag The (single octet) identifier.
 * @param content The value octets.
 */
export function derTlv(tag: number, content: Uint8Array): Uint8Array {
    return concatBytes(Uint8Array.of(tag), derLength(content.length), content);
}

/**
 * Encodes a SEQUENCE.
 *
 * @param parts The already-encoded members.
 */
export function derSequence(...parts: Uint8Array[]): Uint8Array {
    return derTlv(0x30, concatBytes(...parts));
}

/**
 * Encodes an OCTET STRING.
 *
 * @param content The value octets.
 */
export function derOctetString(content: Uint8Array): Uint8Array {
    return derTlv(0x04, content);
}

/** Encodes a NULL. */
export function derNull(): Uint8Array {
    return Uint8Array.of(0x05, 0x00);
}

/**
 * Encodes a non-negative INTEGER of arbitrary size in minimal DER form (a `00` octet is prepended when the top bit
 * would otherwise make the value negative).
 *
 * @param value The value; must be non-negative.
 */
export function derInteger(value: bigint): Uint8Array {
    if (value < 0n) {
        throw new RangeError("Only non-negative INTEGERs are supported");
    }
    let hex = value.toString(16);
    if (hex.length % 2 === 1) {
        hex = "0" + hex;
    }
    let content: Uint8Array = Uint8Array.from(Buffer.from(hex, "hex"));
    if (content[0] & 0x80) {
        content = concatBytes(Uint8Array.of(0), content);
    }
    return derTlv(0x02, content);
}

/**
 * Encodes an OBJECT IDENTIFIER from its dotted form.
 *
 * @param dotted For example `1.2.840.113549.1.5.13`.
 */
export function derOid(dotted: string): Uint8Array {
    const arcs = dotted.split(".").map((a) => {
        if (!/^(0|[1-9][0-9]*)$/.test(a)) {
            throw new RangeError(`Invalid OID ${dotted}`);
        }
        return BigInt(a);
    });
    if (arcs.length < 2 || arcs[0] > 2n || (arcs[0] < 2n && arcs[1] >= 40n)) {
        throw new RangeError(`Invalid OID ${dotted}`);
    }
    const encodeArc = (arc: bigint): number[] => {
        const out = [Number(arc & 0x7fn)];
        let rest = arc >> 7n;
        while (rest > 0n) {
            out.unshift(Number(rest & 0x7fn) | 0x80);
            rest >>= 7n;
        }
        return out;
    };
    const body: number[] = [...encodeArc(arcs[0] * 40n + arcs[1])];
    for (const arc of arcs.slice(2)) {
        body.push(...encodeArc(arc));
    }
    return derTlv(0x06, Uint8Array.from(body));
}
