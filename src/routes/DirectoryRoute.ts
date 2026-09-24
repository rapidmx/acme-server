///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { DocDecorators, HttpRequest, HttpResponse, RouteDecorators } from "@rapidrest/service-core";
import { PROFILE_DESCRIPTIONS } from "../lib/acme/Profiles.js";
import { AcmeResult, AcmeRoute } from "./AcmeRoute.js";
const { Description, Summary } = DocDecorators;
const { Get, Head, Request, Response, Route } = RouteDecorators;

/**
 * The ACME directory (RFC 8555 §7.1.1): the one URL a client is configured with, from which it finds every other endpoint.
 *
 * @author Jean-Philippe Steinmetz
 */
@Route("/directory")
@Description("The ACME directory.")
export class DirectoryRoute extends AcmeRoute {
    private async directory(req: HttpRequest, res: HttpResponse): Promise<void> {
        await this.run(
            req,
            res,
            "endpointDirectory",
            async (): Promise<AcmeResult> => {
                const urls = this.ctx.urls;
                const settings = this.ctx.settings;
                return {
                    status: 200,
                    body: {
                        newNonce: urls.newNonce(),
                        newAccount: urls.newAccount(),
                        newOrder: urls.newOrder(),
                        revokeCert: urls.revokeCert(),
                        keyChange: urls.keyChange(),
                        renewalInfo: urls.renewalInfoBase(),
                        meta: {
                            termsOfService: settings.termsOfServiceUrl,
                            website: settings.website,
                            caaIdentities: settings.caaIdentities,
                            externalAccountRequired: false,
                            profiles: PROFILE_DESCRIPTIONS,
                        },
                    },
                    cacheControl: "public, max-age=0, no-cache",
                };
            },
            { nonce: false },
        );
    }

    @Summary("Get the ACME directory")
    @Get()
    public async get(@Request req: HttpRequest, @Response res: HttpResponse): Promise<void> {
        await this.directory(req, res);
    }

    @Summary("Head the ACME directory")
    @Head()
    public async head(@Request req: HttpRequest, @Response res: HttpResponse): Promise<void> {
        await this.directory(req, res);
    }
}
