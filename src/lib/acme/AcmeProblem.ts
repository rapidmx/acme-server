///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////

/** The URN prefix of every ACME problem type (RFC 8555 §6.7). */
export const ACME_ERROR_PREFIX = "urn:ietf:params:acme:error:";

/**
 * The problem types this CA can answer with: RFC 8555 §6.7, plus `alreadyReplaced`/`badCertificateIdentifier`
 * from RFC 9773 (ARI).
 */
export type AcmeErrorType =
    | "accountDoesNotExist"
    | "alreadyReplaced"
    | "alreadyRevoked"
    | "badCSR"
    | "badCertificateIdentifier"
    | "badNonce"
    | "badPublicKey"
    | "badRevocationReason"
    | "badSignatureAlgorithm"
    | "caa"
    | "compound"
    | "connection"
    | "dns"
    | "externalAccountRequired"
    | "incorrectResponse"
    | "invalidContact"
    | "malformed"
    | "orderNotReady"
    | "rateLimited"
    | "rejectedIdentifier"
    | "serverInternal"
    | "tls"
    | "unauthorized"
    | "unsupportedContact"
    | "unsupportedIdentifier"
    | "userActionRequired";

/** The HTTP status each problem type is answered with unless the thrower says otherwise (Boulder's mapping). */
const DEFAULT_STATUS: Record<AcmeErrorType, number> = {
    accountDoesNotExist: 400,
    alreadyReplaced: 409,
    alreadyRevoked: 400,
    badCSR: 400,
    badCertificateIdentifier: 404,
    badNonce: 400,
    badPublicKey: 400,
    badRevocationReason: 400,
    badSignatureAlgorithm: 400,
    caa: 403,
    compound: 400,
    connection: 400,
    dns: 400,
    externalAccountRequired: 403,
    incorrectResponse: 400,
    invalidContact: 400,
    malformed: 400,
    orderNotReady: 403,
    rateLimited: 429,
    rejectedIdentifier: 400,
    serverInternal: 500,
    tls: 400,
    unauthorized: 403,
    unsupportedContact: 400,
    unsupportedIdentifier: 400,
    userActionRequired: 403,
};

/** The wire form of a problem document (RFC 7807 as profiled by RFC 8555 §6.7). */
export interface ProblemDocument {
    type: string;
    detail: string;
    status: number;
    subproblems?: Array<{ type: string; detail: string; identifier?: { type: string; value: string } }>;
    /** `badSignatureAlgorithm` only: the algorithms the server accepts (RFC 8555 §6.2). */
    algorithms?: string[];
}

/**
 * An error that is answered to an ACME client as an `application/problem+json` document.
 *
 * Anything thrown that is not an `AcmeProblem` is a bug (or an outage) and is answered as a bare `serverInternal` with no
 * detail, so internals never reach a client.
 *
 * @author Jean-Philippe Steinmetz
 */
export class AcmeProblem extends Error {
    /** The short problem type, e.g. `malformed` (the URN is `ACME_ERROR_PREFIX` + this). */
    public readonly errorType: AcmeErrorType;
    /** The HTTP status to answer with. */
    public readonly status: number;
    /** `Retry-After` in seconds, for a rate limit or a resource that is not ready yet. */
    public retryAfterSeconds?: number;
    /** A `Link: <url>;rel="help"` target that documents the problem (used by rate limits). */
    public helpUrl?: string;
    /** A `Location` header to send with the problem (a key change conflict points at the account that owns the key). */
    public location?: string;
    public subproblems?: ProblemDocument["subproblems"];
    public algorithms?: string[];

    constructor(errorType: AcmeErrorType, detail: string, status?: number) {
        super(detail);
        this.name = "AcmeProblem";
        this.errorType = errorType;
        this.status = status ?? DEFAULT_STATUS[errorType];
    }

    /** The full problem type URN. */
    public get type(): string {
        return `${ACME_ERROR_PREFIX}${this.errorType}`;
    }

    /** The problem document to serialize into the response body. */
    public toDocument(): ProblemDocument {
        const doc: ProblemDocument = { type: this.type, detail: this.message, status: this.status };
        if (this.subproblems) {
            doc.subproblems = this.subproblems;
        }
        if (this.algorithms) {
            doc.algorithms = this.algorithms;
        }
        return doc;
    }

    /** A `malformed` request (RFC 8555: the request message was malformed). */
    public static malformed(detail: string, status?: number): AcmeProblem {
        return new AcmeProblem("malformed", detail, status);
    }

    /** The client is not allowed to do this (wrong account, deactivated account, ...). */
    public static unauthorized(detail: string): AcmeProblem {
        return new AcmeProblem("unauthorized", detail);
    }

    /** A rate limit was hit. `retryAfterSeconds` is when a retry can succeed. */
    public static rateLimited(detail: string, retryAfterSeconds: number, helpUrl?: string): AcmeProblem {
        const problem: AcmeProblem = new AcmeProblem("rateLimited", detail);
        problem.retryAfterSeconds = Math.max(1, Math.ceil(retryAfterSeconds));
        problem.helpUrl = helpUrl;
        return problem;
    }

    /** Something went wrong on the server. The detail is deliberately generic. */
    public static internal(): AcmeProblem {
        return new AcmeProblem("serverInternal", "The server hit an internal error. Please try again later.");
    }
}
