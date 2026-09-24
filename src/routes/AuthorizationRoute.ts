///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { DocDecorators, HttpRequest, HttpResponse, RouteDecorators } from "@rapidrest/service-core";
import { AcmeProblem } from "../lib/acme/AcmeProblem.js";
import { AcmeAuthorization } from "../models/AcmeAuthorization.js";
import { AcmeResult, AcmeRoute } from "./AcmeRoute.js";
const { Description, Summary } = DocDecorators;
const { Param, Post, Request, Response, Route } = RouteDecorators;

/**
 * Authorizations and their `email-reply-00` challenge (RFC 8555 §7.5, RFC 8823).
 *
 * @author Jean-Philippe Steinmetz
 */
@Route("/acme")
@Description("ACME authorizations and challenges.")
export class AuthorizationRoute extends AcmeRoute {
    @Summary("Read (or deactivate) an authorization")
    @Post("/authz/:id")
    public async authorization(@Param("id") id: string, @Request req: HttpRequest, @Response res: HttpResponse): Promise<void> {
        await this.run(
            req,
            res,
            "endpointOther",
            async (): Promise<AcmeResult> => {
                const auth = await this.authenticate(req, "kid");
                let authz: AcmeAuthorization = await this.ctx.challenges.load(id, auth.account!.uid);
                if (auth.payload === undefined) {
                    // RFC 8823 §3: the verification e-mail is sent once the client has fetched the authorization.
                    authz = await this.ctx.challenges.sendChallengeMail(authz, auth.account!, this.ctx.ipSubject(req));
                } else if (auth.payload.status === "deactivated") {
                    authz = await this.ctx.challenges.deactivate(id, auth.account!);
                } else {
                    throw AcmeProblem.malformed("The only change a client can make to an authorization is to deactivate it.");
                }
                return { status: 200, body: this.ctx.challenges.resource(authz), location: this.ctx.urls.authorization(authz.uid) };
            },
            { nonce: true },
        );
    }

    @Summary("Tell the CA the challenge reply has been sent")
    @Post("/chall/:authzId/:challengeId")
    public async challenge(@Param("authzId") authzId: string, @Param("challengeId") challengeId: string, @Request req: HttpRequest, @Response res: HttpResponse): Promise<void> {
        await this.run(
            req,
            res,
            "endpointOther",
            async (): Promise<AcmeResult> => {
                const auth = await this.authenticate(req, "kid");
                let authz: AcmeAuthorization;
                if (auth.payload === undefined) {
                    authz = await this.ctx.challenges.load(authzId, auth.account!.uid);
                    if (authz.challenge.id !== challengeId) {
                        throw AcmeProblem.malformed("No such challenge.", 404);
                    }
                } else {
                    authz = await this.ctx.challenges.respond(authzId, challengeId, auth.account!);
                }
                return {
                    status: 200,
                    body: this.ctx.challenges.challengeResource(authz),
                    links: [`<${this.ctx.urls.authorization(authz.uid)}>;rel="up"`],
                };
            },
            { nonce: true },
        );
    }
}
