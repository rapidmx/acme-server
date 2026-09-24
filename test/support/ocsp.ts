///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { AlgorithmIdentifier } from "@peculiar/asn1-x509";
import { BasicOCSPResponse, CertID, OCSPRequest, OCSPResponse, Request, TBSRequest } from "@peculiar/asn1-ocsp";
import type { Issuer } from "../../src/lib/pki/index.js";

const SHA1 = "1.3.14.3.2.26";

/** A DER OCSP request for `serialHex` as issued by `issuer` (SHA-1 CertID, as RFC 5019 clients send). */
export function ocspRequest(issuer: Issuer, serialHex: string): Uint8Array {
    const padded: string = serialHex.length % 2 === 0 ? serialHex : `0${serialHex}`;
    const request = new OCSPRequest({
        tbsRequest: new TBSRequest({
            requestList: [
                new Request({
                    reqCert: new CertID({
                        hashAlgorithm: new AlgorithmIdentifier({ algorithm: SHA1 }),
                        issuerNameHash: new OctetString(issuer.nameHash("sha1")),
                        issuerKeyHash: new OctetString(issuer.keyHash("sha1")),
                        serialNumber: new Uint8Array(Buffer.from(padded, "hex")).buffer,
                    }),
                }),
            ],
        }),
    });
    return new Uint8Array(AsnConvert.serialize(request));
}

/** What an OCSP response says about the first certificate it covers. */
export interface OcspAnswer {
    /** 0 successful, 1 malformedRequest, 2 internalError, 3 tryLater, 5 sigRequired, 6 unauthorized. */
    responseStatus: number;
    status?: "good" | "revoked" | "unknown";
    revokedAt?: Date;
    reason?: number;
    basic?: BasicOCSPResponse;
    signature?: Uint8Array;
    tbs?: Uint8Array;
}

/** Parses a DER OCSP response. */
export function parseOcsp(der: Uint8Array): OcspAnswer {
    const response = AsnConvert.parse(der, OCSPResponse);
    const answer: OcspAnswer = { responseStatus: Number(response.responseStatus) };
    if (!response.responseBytes) {
        return answer;
    }
    const basic = AsnConvert.parse(response.responseBytes.response.buffer, BasicOCSPResponse);
    const single = basic.tbsResponseData.responses[0];
    answer.basic = basic;
    answer.tbs = new Uint8Array(AsnConvert.serialize(basic.tbsResponseData));
    answer.signature = new Uint8Array(basic.signature);
    if (single.certStatus.good !== undefined) {
        answer.status = "good";
    } else if (single.certStatus.revoked) {
        answer.status = "revoked";
        answer.revokedAt = single.certStatus.revoked.revocationTime;
        answer.reason = single.certStatus.revoked.revocationReason?.reason;
    } else {
        answer.status = "unknown";
    }
    return answer;
}
