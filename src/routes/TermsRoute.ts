///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { DocDecorators, HttpRequest, HttpResponse, RouteDecorators } from "@rapidrest/service-core";
import { renderTerms } from "../lib/acme/InfoPages.js";
import { AcmeResult, AcmeRoute } from "./AcmeRoute.js";
const { Description, Summary } = DocDecorators;
const { Get, Request, Response, Route } = RouteDecorators;

/**
 * The terms of service (`meta.termsOfService` in the directory).
 *
 * @author Jean-Philippe Steinmetz
 */
@Route("/terms")
@Description("The terms of service.")
export class TermsRoute extends AcmeRoute {
    @Summary("Terms of service")
    @Get()
    public async get(@Request req: HttpRequest, @Response res: HttpResponse): Promise<void> {
        await this.run(
            req,
            res,
            "endpointOther",
            async (): Promise<AcmeResult> => ({
                status: 200,
                raw: renderTerms({ externalUrl: this.ctx.settings.externalUrl, caIdentities: this.ctx.settings.caaIdentities, website: this.ctx.settings.website }),
                contentType: "text/html; charset=utf-8",
                cacheControl: "public, max-age=3600",
            }),
            { nonce: false, plain: true },
        );
    }
}
