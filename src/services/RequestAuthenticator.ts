///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import type { HttpRequest } from "@rapidrest/service-core";
import { AcmeProblem } from "../lib/acme/AcmeProblem.js";
import { JOSE_CONTENT_TYPE, jwkThumbprint, ParsedJws, parseJws, parsePayload, PublicJwk, verifyJwsSignature } from "../lib/acme/Jws.js";
import type { AcmeAccount } from "../models/AcmeAccount.js";
import type { AcmeContext } from "./AcmeContext.js";

/** Which key identification an endpoint accepts (RFC 8555 §6.2). */
export type KeyMode = "kid" | "jwk" | "either";

/** A request that passed JWS verification. */
export interface AuthenticatedRequest {
    /** The account, when the request identified itself with a `kid`. */
    account?: AcmeAccount;
    /** The key that signed: the account's, or the embedded `jwk`. */
    jwk: PublicJwk;
    thumbprint: string;
    /** `true` for a POST-as-GET (empty payload). */
    postAsGet: boolean;
    /** The JSON payload of a POST; `undefined` for a POST-as-GET. */
    payload?: Record<string, any>;
    parsed: ParsedJws;
}

/**
 * Turns an ACME POST into an authenticated request (RFC 8555 §6): checks the content type, the JWS structure and its
 * `url`, verifies the signature with the account key (`kid`) or the embedded key (`jwk`), consumes the nonce, and loads
 * the account.
 *
 * The order matters. The signature is verified **before** the nonce is consumed, so a forged request can never burn
 * another client's nonce, and the nonce is consumed **before** any state is touched, so a captured request replays once
 * at most (never).
 *
 * @author Jean-Philippe Steinmetz
 */
export class RequestAuthenticator {
    private readonly ctx: AcmeContext;

    constructor(ctx: AcmeContext) {
        this.ctx = ctx;
    }

    /**
     * Authenticates `req`.
     *
     * @param req The HTTP request.
     * @param mode `kid` for everything after registration, `jwk` for new-account, `either` for revoke-cert.
     * @param expectedUrlOverride The URL the JWS must name, when it is not just the request path.
     * @throws `AcmeProblem`: `malformed`, `badNonce`, `badSignatureAlgorithm`, `badPublicKey`, `accountDoesNotExist`,
     * `unauthorized`.
     */
    public async authenticate(req: HttpRequest, mode: KeyMode, expectedUrlOverride?: string): Promise<AuthenticatedRequest> {
        const contentType: string = String(req.headers["content-type"] ?? "").split(";")[0].trim().toLowerCase();
        if (contentType !== JOSE_CONTENT_TYPE) {
            throw AcmeProblem.malformed(`POST requests must have the Content-Type ${JOSE_CONTENT_TYPE}.`, 415);
        }
        const parsed: ParsedJws = parseJws(req.rawBody);
        // The path alone, unless the endpoint has a query string (the orders list): the framework parses it away.
        const expectedUrl: string = expectedUrlOverride ?? this.ctx.urls.forPath(req.path);
        if (parsed.header.url !== expectedUrl) {
            throw AcmeProblem.malformed(`The JWS url header '${parsed.header.url}' does not match the request URL '${expectedUrl}'.`);
        }
        if (mode === "kid" && parsed.header.kid === undefined) {
            throw AcmeProblem.malformed("This endpoint requires the JWS to identify the account with a kid, not an embedded jwk.");
        }
        if (mode === "jwk" && parsed.header.jwk === undefined) {
            throw AcmeProblem.malformed("This endpoint requires the JWS to carry the account key as an embedded jwk.");
        }

        let account: AcmeAccount | undefined;
        let jwk: PublicJwk;
        if (parsed.header.kid !== undefined) {
            const id: string | undefined = this.ctx.urls.accountIdFrom(parsed.header.kid);
            const found = id ? await this.ctx.accountRepo.findOne({ uid: id }) : null;
            if (!found) {
                throw new AcmeProblem("accountDoesNotExist", "No account exists at the JWS kid URL.");
            }
            account = found;
            jwk = found.jwk;
        } else {
            jwk = parsed.header.jwk!;
        }

        await verifyJwsSignature(parsed, jwk);
        if (!(await this.ctx.nonces.consume(parsed.header.nonce!))) {
            throw new AcmeProblem("badNonce", "The nonce is not valid: it was already used, it expired, or this server did not issue it. Retry with the nonce of this response.");
        }
        if (account && account.status !== "valid") {
            throw AcmeProblem.unauthorized(`The account is ${account.status}.`);
        }

        const payload: Record<string, any> | undefined = parsePayload(parsed.payloadText);
        return {
            account,
            jwk,
            thumbprint: account?.thumbprint ?? (await jwkThumbprint(jwk)),
            postAsGet: payload === undefined,
            payload,
            parsed,
        };
    }
}
