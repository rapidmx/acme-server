///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { DocDecorators, HttpRequest, HttpResponse, RouteDecorators } from "@rapidrest/service-core";
import { AcmeProblem } from "../lib/acme/AcmeProblem.js";
import { Issuer } from "../lib/pki/index.js";
import { AcmeResult, AcmeRoute } from "./AcmeRoute.js";
const { Description, Summary } = DocDecorators;
const { Get, Param, Request, Response, Route } = RouteDecorators;

/**
 * The CRL endpoint: the newest CRL of an issuer, DER.
 *
 * @author Jean-Philippe Steinmetz
 */
@Route("/crl")
@Description("Certificate revocation lists.")
export class CrlRoute extends AcmeRoute {
    @Summary("Get the current CRL of an issuer")
    @Get("/:file")
    public async crl(@Param("file") file: string, @Request req: HttpRequest, @Response res: HttpResponse): Promise<void> {
        await this.run(
            req,
            res,
            "endpointOther",
            async (): Promise<AcmeResult> => {
                const match: RegExpExecArray | null = /^([a-z0-9][a-z0-9_-]{0,62})\.crl$/.exec(file);
                const issuer: Issuer | undefined = match ? this.ctx.registry.get(match[1]) : undefined;
                if (!issuer) {
                    throw AcmeProblem.malformed("No such CRL.", 404);
                }
                const crl = await this.ctx.crls.current(issuer);
                const remaining: number = Math.max(60, Math.floor((crl.nextUpdate.getTime() - this.ctx.now().getTime()) / 1000));
                return {
                    status: 200,
                    raw: Buffer.from(crl.der, "base64"),
                    contentType: "application/pkix-crl",
                    cacheControl: `public, max-age=${Math.min(remaining, 3600)}`,
                    headers: { "last-modified": crl.thisUpdate.toUTCString() },
                };
            },
            { nonce: false, plain: true },
        );
    }
}
