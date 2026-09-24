///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { digest, serialBytesToHex } from "./util.js";

/** A parsed DER tag-length-value position inside a byte array. */
export interface Tlv {
    tag: number;
    /** Offset of the identifier octet. */
    start: number;
    /** Offset of the first content octet. */
    contentStart: number;
    /** Offset one past the last content octet. */
    end: number;
}

/**
 * Reads one DER TLV (definite length, single-octet tag) at an offset.
 *
 * @param bytes The buffer.
 * @param offset Where the TLV starts.
 * @throws Error when the encoding is truncated or uses an unsupported form.
 */
export function readTlv(bytes: Uint8Array, offset: number): Tlv {
    if (offset + 2 > bytes.length) {
        throw new Error("Truncated DER");
    }
    const tag = bytes[offset];
    if ((tag & 0x1f) === 0x1f) {
        throw new Error("Unsupported DER tag");
    }
    let length = bytes[offset + 1];
    let contentStart = offset + 2;
    if (length & 0x80) {
        const count = length & 0x7f;
        if (count === 0 || count > 4 || contentStart + count > bytes.length) {
            throw new Error("Unsupported DER length");
        }
        length = 0;
        for (let i = 0; i < count; i++) {
            length = length * 256 + bytes[contentStart + i];
        }
        contentStart += count;
    }
    const end = contentStart + length;
    if (end > bytes.length) {
        throw new Error("Truncated DER");
    }
    return { tag, start: offset, contentStart, end };
}

/**
 * The TLVs directly inside a constructed TLV.
 *
 * @param bytes The buffer.
 * @param parent The parent TLV.
 */
export function childrenOf(bytes: Uint8Array, parent: Tlv): Tlv[] {
    const out: Tlv[] = [];
    let offset = parent.contentStart;
    while (offset < parent.end) {
        const child = readTlv(bytes, offset);
        out.push(child);
        offset = child.end;
    }
    return out;
}

/** The raw pieces of a DER certificate that hashes and comparisons must use byte for byte. */
export interface CertificateParts {
    /** The `tbsCertificate` TLV, whole. */
    tbs: Uint8Array;
    /** The serial number INTEGER's content octets. */
    serial: Uint8Array;
    /** The issuer Name TLV, whole, exactly as encoded in the certificate. */
    issuer: Uint8Array;
    /** The subject Name TLV, whole, exactly as encoded in the certificate. */
    subject: Uint8Array;
    /** The SubjectPublicKeyInfo TLV, whole. */
    spki: Uint8Array;
}

/**
 * Locates the serial, issuer, subject and public key inside a DER certificate without re-encoding anything. An OCSP
 * `issuerNameHash` and a certificate's `issuer` field are byte-exact comparisons; taking the bytes from the
 * certificate itself removes any dependence on a parser's re-serialization.
 *
 * @param der The DER certificate.
 * @throws Error when the structure is not a certificate.
 */
export function certificateParts(der: Uint8Array): CertificateParts {
    const cert = readTlv(der, 0);
    if (cert.tag !== 0x30 || cert.end !== der.length) {
        throw new Error("Not a DER certificate");
    }
    const tbsTlv = childrenOf(der, cert)[0];
    if (!tbsTlv || tbsTlv.tag !== 0x30) {
        throw new Error("Not a DER certificate");
    }
    const fields = childrenOf(der, tbsTlv);
    let i = fields[0]?.tag === 0xa0 ? 1 : 0;
    const serial = fields[i++];
    i++; // signature AlgorithmIdentifier
    const issuer = fields[i++];
    i++; // validity
    const subject = fields[i++];
    const spki = fields[i++];
    if (!serial || serial.tag !== 0x02 || !issuer || !subject || !spki || spki.tag !== 0x30) {
        throw new Error("Not a DER certificate");
    }
    const slice = (t: Tlv) => der.slice(t.start, t.end);
    return {
        tbs: slice(tbsTlv),
        serial: der.slice(serial.contentStart, serial.end),
        issuer: slice(issuer),
        subject: slice(subject),
        spki: slice(spki),
    };
}

/**
 * The contents of the `subjectPublicKey` BIT STRING of a SubjectPublicKeyInfo (without the unused-bits octet): what the
 * RFC 5280 key identifier and the RFC 6960 `issuerKeyHash` are computed over.
 *
 * @param spki DER SubjectPublicKeyInfo.
 */
export function spkiKeyBits(spki: Uint8Array): Uint8Array {
    const seq = readTlv(spki, 0);
    const parts = childrenOf(spki, seq);
    const bits = parts[1];
    if (seq.tag !== 0x30 || !bits || bits.tag !== 0x03 || bits.end - bits.contentStart < 1 || spki[bits.contentStart] !== 0) {
        throw new Error("Not a SubjectPublicKeyInfo");
    }
    return spki.slice(bits.contentStart + 1, bits.end);
}

/**
 * The RFC 5280 s4.2.1.2 method (1) key identifier: SHA-1 of the subject public key bits.
 *
 * @param spki DER SubjectPublicKeyInfo.
 */
export function keyIdentifierOf(spki: Uint8Array): Uint8Array {
    return digest("sha1", spkiKeyBits(spki));
}

/**
 * Canonical serial hex of a DER certificate (see `serialBytesToHex`).
 *
 * @param der The DER certificate.
 */
export function certificateSerialHex(der: Uint8Array): string {
    const hex = serialBytesToHex(certificateParts(der).serial);
    if (hex === undefined) {
        throw new Error("Certificate has an unsupported serial number");
    }
    return hex;
}
