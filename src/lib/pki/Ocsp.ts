///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import "./runtime.js";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import {
    BasicOCSPResponse,
    CertStatus,
    id_pkix_ocsp_basic,
    id_pkix_ocsp_nonce,
    KeyHash,
    OCSPRequest,
    OCSPResponse,
    OCSPResponseStatus,
    ResponderID,
    ResponseBytes,
    ResponseData,
    RevokedInfo,
    SingleResponse,
} from "@peculiar/asn1-ocsp";
import { CRLReason, Extension } from "@peculiar/asn1-x509";
import type { Issuer, IssuerRegistry } from "./Issuer.js";
import { OID } from "./oids.js";
import { signatureAlgorithmIdentifier, signChecked } from "./Signer.js";
import { floorToSecond, serialBytesToHex, toArrayBuffer } from "./util.js";

/**
 * What the responder needs to know about a certificate; supplied by the application (database lookup).
 * `unknown` means "this issuer never issued that serial".
 */
export type CertStatusLookup = (
    issuer: Issuer,
    serialHex: string
) => Promise<{ status: "good" | "revoked" | "unknown"; revokedAt?: Date; reason?: number }>;

/** The largest request (octets) that is parsed; a request for one certificate is about 80 octets (RFC 5019). */
const MAX_REQUEST_OCTETS = 8192;
/** The most certificates one request may ask about; RFC 5019 clients send exactly one. */
const MAX_CERTS_PER_REQUEST = 8;
/** The longest nonce extension value accepted (RFC 9654 asks responders to handle 32 octets; DER wrapping adds 2). */
const MAX_NONCE_OCTETS = 128;

const HASHES: Record<string, "sha1" | "sha256" | "sha384" | "sha512"> = {
    [OID.sha1]: "sha1",
    [OID.sha256]: "sha256",
    [OID.sha384]: "sha384",
    [OID.sha512]: "sha512",
};

/** An OCSPResponse that carries only a status (RFC 6960 s2.3). */
function statusOnly(status: OCSPResponseStatus): Uint8Array {
    return new Uint8Array(AsnConvert.serialize(new OCSPResponse({ responseStatus: status })));
}

/**
 * The OCSP responder (RFC 6960, with the RFC 5019 lightweight profile's conventions): parses a DER OCSPRequest,
 * looks each certificate up and returns a signed DER OCSPResponse. Transport (GET base64 / POST body, headers, caching)
 * is the caller's job.
 *
 * Behaviour: the response is signed directly by the issuing CA's key (via its {@link CaSigner}, no delegated
 * responder certificate) and identifies the responder by key hash; it echoes the request's CertIDs and any nonce; the
 * validity window is `thisUpdate = now` to `now + validityHours`. A request for an issuer this registry does not
 * serve is answered `unauthorized`, one that does not parse (or is oversized, or asks for more than 8 certificates or
 * carries an unknown critical extension) `malformedRequest`, any failure inside (lookup, signing) `internalError`. A
 * serial that is not a valid positive serial, or that the lookup does not know, is `unknown` (never `good`).
 *
 * @author Jean-Philippe Steinmetz
 */
export class OcspResponder {
    readonly #registry: IssuerRegistry;
    readonly #lookup: CertStatusLookup;
    readonly #validityMs: number;
    readonly #now: () => Date;
    readonly #onError?: (err: unknown) => void;

    /**
     * @param registry The issuers whose certificates are answered for.
     * @param lookup Resolves a serial to its status.
     * @param o `validityHours` how long a response is valid (default 24, at most 240 = 10 days); `now` a clock (tests); `onError`
     * is told about internal errors (which are otherwise only visible as `internalError` responses).
     */
    public constructor(
        registry: IssuerRegistry,
        lookup: CertStatusLookup,
        o?: { validityHours?: number; now?: () => Date; onError?: (err: unknown) => void }
    ) {
        const hours = o?.validityHours ?? 24;
        if (!(hours > 0) || hours > 240) {
            throw new Error("validityHours must be greater than 0 and at most 240");
        }
        this.#registry = registry;
        this.#lookup = lookup;
        this.#validityMs = Math.round(hours * 3_600_000);
        this.#now = o?.now ?? (() => new Date());
        this.#onError = o?.onError;
    }

    /**
     * Answers a request.
     *
     * @param requestDer The DER OCSPRequest.
     * @returns A DER OCSPResponse; never throws.
     */
    public async respond(requestDer: Uint8Array): Promise<Uint8Array> {
        try {
            return await this.#respond(requestDer);
        } catch (err) {
            try {
                this.#onError?.(err);
            } catch {
                // a failing error hook must not change the answer
            }
            return statusOnly(OCSPResponseStatus.internalError);
        }
    }

    async #respond(requestDer: Uint8Array): Promise<Uint8Array> {
        if (!(requestDer instanceof Uint8Array) || requestDer.length === 0 || requestDer.length > MAX_REQUEST_OCTETS) {
            return statusOnly(OCSPResponseStatus.malformedRequest);
        }
        let request: OCSPRequest;
        try {
            request = AsnConvert.parse(requestDer, OCSPRequest);
        } catch {
            return statusOnly(OCSPResponseStatus.malformedRequest);
        }
        const tbs = request.tbsRequest;
        if (tbs.version !== 0 || tbs.requestList.length === 0 || tbs.requestList.length > MAX_CERTS_PER_REQUEST) {
            return statusOnly(OCSPResponseStatus.malformedRequest);
        }

        let nonce: Extension | undefined;
        for (const extension of tbs.requestExtensions ?? []) {
            if (extension.extnID === id_pkix_ocsp_nonce) {
                if (nonce || extension.extnValue.byteLength > MAX_NONCE_OCTETS) {
                    return statusOnly(OCSPResponseStatus.malformedRequest);
                }
                nonce = extension;
            } else if (extension.critical) {
                return statusOnly(OCSPResponseStatus.malformedRequest);
            }
        }

        // Every certificate must belong to one issuer we serve, because one signature covers the whole response.
        let issuer: Issuer | undefined;
        for (const item of tbs.requestList) {
            const id = item.reqCert;
            const hash = HASHES[id.hashAlgorithm.algorithm];
            const found = hash
                ? this.#registry.findByCertId(hash, new Uint8Array(id.issuerNameHash.buffer), new Uint8Array(id.issuerKeyHash.buffer))
                : undefined;
            if (!found || (issuer && issuer !== found)) {
                return statusOnly(OCSPResponseStatus.unauthorized);
            }
            issuer = found;
        }
        if (!issuer) {
            return statusOnly(OCSPResponseStatus.unauthorized);
        }

        const now = floorToSecond(this.#now());
        const nextUpdate = new Date(now.getTime() + this.#validityMs);
        const responses: SingleResponse[] = [];
        for (const item of tbs.requestList) {
            const serialHex = serialBytesToHex(new Uint8Array(item.reqCert.serialNumber));
            const answer = serialHex === undefined ? { status: "unknown" as const } : await this.#lookup(issuer, serialHex);
            const certStatus = new CertStatus();
            if (answer.status === "good") {
                certStatus.good = null;
            } else if (answer.status === "revoked") {
                if (!(answer.revokedAt instanceof Date) || isNaN(answer.revokedAt.getTime())) {
                    throw new Error("The status lookup reported 'revoked' without a revocation time");
                }
                certStatus.revoked = new RevokedInfo({
                    revocationTime: floorToSecond(answer.revokedAt),
                    revocationReason: answer.reason ? new CRLReason(answer.reason) : undefined,
                });
            } else if (answer.status === "unknown") {
                certStatus.unknown = null;
            } else {
                throw new Error("The status lookup returned an invalid status");
            }
            responses.push(new SingleResponse({ certID: item.reqCert, certStatus, thisUpdate: now, nextUpdate }));
        }

        const responseData = new ResponseData({
            responderID: new ResponderID({ byKey: new KeyHash(issuer.keyHash("sha1")) }),
            producedAt: now,
            responses,
            responseExtensions: nonce
                ? [new Extension({ extnID: id_pkix_ocsp_nonce, critical: false, extnValue: nonce.extnValue })]
                : undefined,
        });
        const signature = await signChecked(issuer.signer, new Uint8Array(AsnConvert.serialize(responseData)));
        const basic = new BasicOCSPResponse({
            tbsResponseData: responseData,
            signatureAlgorithm: signatureAlgorithmIdentifier(issuer.signer.algorithm),
            signature: toArrayBuffer(signature),
        });
        return new Uint8Array(
            AsnConvert.serialize(
                new OCSPResponse({
                    responseStatus: OCSPResponseStatus.successful,
                    responseBytes: new ResponseBytes({
                        responseType: id_pkix_ocsp_basic,
                        response: new OctetString(AsnConvert.serialize(basic)),
                    }),
                })
            )
        );
    }
}
