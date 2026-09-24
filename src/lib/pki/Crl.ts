///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import "./runtime.js";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import {
    AuthorityKeyIdentifier,
    CertificateList,
    CRLReason,
    Extension,
    KeyIdentifier,
    Name,
    RevokedCertificate,
    TBSCertList,
    Time,
} from "@peculiar/asn1-x509";
import { derInteger } from "./der.js";
import type { Issuer } from "./Issuer.js";
import { OID } from "./oids.js";
import { signatureAlgorithmIdentifier, signChecked } from "./Signer.js";
import { derToPem, floorToSecond, serialBytesToHex, serialHexToDerContent, toArrayBuffer } from "./util.js";

/** One revoked certificate. */
export interface RevokedEntry {
    /** Canonical serial hex (see `serialBytesToHex`). */
    serialHex: string;
    /** When it was revoked. */
    revokedAt: Date;
    /** RFC 5280 CRLReason code; 0 or absent means unspecified. */
    reason?: number;
}

/** The longest interval between `thisUpdate` and `nextUpdate` (Baseline Requirements: 10 days for subscriber CRLs). */
export const MAX_CRL_VALIDITY_DAYS = 10;

/** CRLReason values allowed on a full CRL: everything except `unused` (7) and `removeFromCRL` (8, delta CRLs only). */
const ALLOWED_REASONS = new Set([1, 2, 3, 4, 5, 6, 9, 10]);
const ENTRY_LIMIT_BITS = 159n;

/**
 * Builds and signs a version 2 CRL for an issuer (RFC 5280 s5), through the issuer's {@link CaSigner}.
 *
 * Contents: issuer name copied byte for byte from the issuer certificate; `thisUpdate`/`nextUpdate` (mandatory here, at
 * most 10 days apart); one entry per revoked serial with an optional `reasonCode` (an unspecified reason is omitted
 * rather than written as 0, RFC 5280 s5.3.1); the `authorityKeyIdentifier` and `cRLNumber` extensions. With no revoked
 * certificates the `revokedCertificates` field is absent. Entries are ordered by revocation time then serial so the same
 * input always yields the same list. A duplicate serial, invalid reason or out-of-range number is an error, not
 * something to paper over: a CRL is the authoritative revocation record.
 *
 * @param issuer The issuer that signs the CRL.
 * @param o `number` the monotonically increasing CRL number; `thisUpdate`/`nextUpdate` the validity; `revoked` the entries.
 * @returns The DER and PEM (`X509 CRL`) forms.
 */
export async function buildCrl(
    issuer: Issuer,
    // eslint-disable-next-line id-denylist
    o: { number: bigint; thisUpdate: Date; nextUpdate: Date; revoked: RevokedEntry[] }
): Promise<{ der: Uint8Array; pem: string }> {
    if (typeof o.number !== "bigint" || o.number < 0n || o.number >= 1n << ENTRY_LIMIT_BITS) {
        throw new Error("The CRL number must be a non-negative integer below 2^159");
    }
    if (!(o.thisUpdate instanceof Date) || !(o.nextUpdate instanceof Date) || isNaN(o.thisUpdate.getTime()) || isNaN(o.nextUpdate.getTime())) {
        throw new Error("Invalid CRL dates");
    }
    const thisUpdate = floorToSecond(o.thisUpdate);
    const nextUpdate = floorToSecond(o.nextUpdate);
    if (nextUpdate.getTime() <= thisUpdate.getTime()) {
        throw new Error("nextUpdate must be after thisUpdate");
    }
    if (nextUpdate.getTime() - thisUpdate.getTime() > MAX_CRL_VALIDITY_DAYS * 86_400_000) {
        throw new Error(`nextUpdate may be at most ${MAX_CRL_VALIDITY_DAYS} days after thisUpdate`);
    }

    const seen = new Set<string>();
    const entries = o.revoked.map((r) => {
        const content = serialHexToDerContent(r.serialHex);
        const canonical = serialBytesToHex(content)!;
        if (seen.has(canonical)) {
            throw new Error(`Duplicate serial ${canonical} in the revoked list`);
        }
        seen.add(canonical);
        if (!(r.revokedAt instanceof Date) || isNaN(r.revokedAt.getTime())) {
            throw new Error(`Invalid revocation time for serial ${canonical}`);
        }
        if (r.reason !== undefined && r.reason !== 0 && !ALLOWED_REASONS.has(r.reason)) {
            throw new Error(`Invalid revocation reason ${r.reason}`);
        }
        return { canonical, content, revokedAt: floorToSecond(r.revokedAt), reason: r.reason };
    });
    entries.sort((a, b) => a.revokedAt.getTime() - b.revokedAt.getTime() || (a.canonical < b.canonical ? -1 : 1));

    const revokedCertificates = entries.map(
        (e) =>
            new RevokedCertificate({
                userCertificate: toArrayBuffer(e.content),
                revocationDate: new Time(e.revokedAt),
                crlEntryExtensions: e.reason
                    ? [
                          new Extension({
                              extnID: OID.cRLReason,
                              critical: false,
                              extnValue: new OctetString(AsnConvert.serialize(new CRLReason(e.reason))),
                          }),
                      ]
                    : undefined,
            })
    );

    const tbs = new TBSCertList({
        version: 1,
        signature: signatureAlgorithmIdentifier(issuer.signer.algorithm),
        issuer: AsnConvert.parse(issuer.subjectDer, Name),
        thisUpdate: new Time(thisUpdate),
        nextUpdate: new Time(nextUpdate),
        revokedCertificates: revokedCertificates.length > 0 ? revokedCertificates : undefined,
        crlExtensions: [
            new Extension({
                extnID: OID.authorityKeyIdentifier,
                critical: false,
                extnValue: new OctetString(
                    AsnConvert.serialize(new AuthorityKeyIdentifier({ keyIdentifier: new KeyIdentifier(issuer.keyId) }))
                ),
            }),
            new Extension({
                extnID: OID.cRLNumber,
                critical: false,
                extnValue: new OctetString(toArrayBuffer(derInteger(o.number))),
            }),
        ],
    });
    const tbsDer = new Uint8Array(AsnConvert.serialize(tbs));
    const signature = await signChecked(issuer.signer, tbsDer);
    const list = new CertificateList({
        tbsCertList: tbs,
        signatureAlgorithm: signatureAlgorithmIdentifier(issuer.signer.algorithm),
        signature: toArrayBuffer(signature),
    });
    const der = new Uint8Array(AsnConvert.serialize(list));
    return { der, pem: derToPem(der, "X509 CRL") };
}
