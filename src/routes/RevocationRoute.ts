///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { DocDecorators, HttpRequest, HttpResponse, RouteDecorators } from "@rapidrest/service-core";
import { AcmeProblem } from "../lib/acme/AcmeProblem.js";
import { AcmeResult, AcmeRoute } from "./AcmeRoute.js";
const { Description, Summary } = DocDecorators;
const { Get, Param, Post, Request, Response, Route } = RouteDecorators;

/** How long a client may cache renewal information before asking again (RFC 9773 recommends a few hours). */
const RENEWAL_INFO_RETRY_SECONDS = 6 * 3600;

/**
 * Revocation (RFC 8555 §7.6) and renewal information (RFC 9773).
 *
 * @author Jean-Philippe Steinmetz
 */
@Route("/acme")
@Description("ACME revocation and renewal information.")
export class RevocationRoute extends AcmeRoute {
    @Summary("Revoke a certificate")
    @Post("/revoke-cert")
    public async revoke(@Request req: HttpRequest, @Response res: HttpResponse): Promise<void> {
        await this.run(
            req,
            res,
            "endpointRevoke",
            async (): Promise<AcmeResult> => {
                const auth = await this.authenticate(req, "either");
                if (auth.payload === undefined) {
                    throw AcmeProblem.malformed("revoke-cert requires a JSON payload.");
                }
                await this.ctx.certificates.revoke({ account: auth.account, jwk: auth.jwk }, auth.payload);
                return { status: 200 };
            },
            { nonce: true },
        );
    }

    @Summary("Renewal information for a certificate")
    @Get("/renewal-info/:certId")
    public async renewalInfo(@Param("certId") certId: string, @Request req: HttpRequest, @Response res: HttpResponse): Promise<void> {
        await this.run(
            req,
            res,
            "endpointOther",
            async (): Promise<AcmeResult> => ({
                status: 200,
                body: await this.ctx.certificates.renewalInfo(certId),
                retryAfterSeconds: RENEWAL_INFO_RETRY_SECONDS,
                cacheControl: "public, max-age=0, no-cache",
            }),
            { nonce: false },
        );
    }
}
