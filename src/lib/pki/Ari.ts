///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { x509 } from "./runtime.js";
import { certificateParts } from "./certutil.js";
import { OID } from "./oids.js";
import { b64url, fromB64url, serialBytesToHex, toBytes } from "./util.js";

/**
 * The ARI certificate identifier of a certificate (RFC 9773 s4.1): the unpadded base64url of the
 * `authorityKeyIdentifier` key identifier, a dot, and the unpadded base64url of the DER `INTEGER` *content* octets of
 * the serial number (no tag, no length), exactly as they appear in the certificate. The pair identifies a certificate
 * without the client having to send it and without the server having to trust anything the client sends.
 *
 * @param cert The (issued) certificate.
 * @throws Error when the certificate has no authorityKeyIdentifier key identifier.
 */
export function ariCertId(cert: x509.X509Certificate): string {
    const aki = cert.getExtension<x509.AuthorityKeyIdentifierExtension>(OID.authorityKeyIdentifier);
    if (!aki || !aki.keyId) {
        throw new Error("The certificate has no authorityKeyIdentifier keyIdentifier, so it has no ARI certificate id");
    }
    const serial = certificateParts(toBytes(cert.rawData)).serial;
    return `${b64url(new Uint8Array(Buffer.from(aki.keyId, "hex")))}.${b64url(serial)}`;
}

/**
 * Parses an ARI certificate identifier strictly: exactly two canonical unpadded base64url segments, a key identifier of
 * 1-64 octets, and a serial that is a minimally-encoded, positive DER INTEGER value of at most 20 significant octets.
 * Anything else (padding, extra segments, a non-minimal integer such as a redundant `00`) is not an identifier this CA
 * ever produced and yields `undefined`, so the caller can answer 404.
 *
 * @param id The identifier from the request path.
 * @returns The key identifier and the canonical serial hex (see `serialBytesToHex`), or `undefined`.
 */
export function parseAriCertId(id: string): { authorityKeyId: Uint8Array; serialHex: string } | undefined {
    if (typeof id !== "string" || id.length > 256) {
        return undefined;
    }
    const parts = id.split(".");
    if (parts.length !== 2) {
        return undefined;
    }
    let authorityKeyId: Uint8Array;
    let serial: Uint8Array;
    try {
        authorityKeyId = fromB64url(parts[0]);
        serial = fromB64url(parts[1]);
    } catch {
        return undefined;
    }
    if (authorityKeyId.length < 1 || authorityKeyId.length > 64 || serial.length < 1 || serial.length > 21) {
        return undefined;
    }
    if (serial.length > 1 && serial[0] === 0 && (serial[1] & 0x80) === 0) {
        return undefined; // redundant leading zero: not DER
    }
    const serialHex = serialBytesToHex(serial);
    if (serialHex === undefined) {
        return undefined;
    }
    return { authorityKeyId, serialHex };
}
