///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { DocDecorators, HttpRequest, HttpResponse, RouteDecorators } from "@rapidrest/service-core";
import { AcmeProblem } from "../lib/acme/AcmeProblem.js";
import { bearerMatches } from "../lib/acme/Bearer.js";
import { AcmeResult, AcmeRoute } from "./AcmeRoute.js";
const { Description, Summary } = DocDecorators;
const { Post, Request, Response, Route } = RouteDecorators;

/**
 * The HTTP ingest route for a mail bridge (Postfix or SES in front of the CA) that receives the applicants' reply e-mails
 * instead of the CA's own SMTP receiver: `POST /internal/mail/inbound` with the raw message as the body and
 * `Authorization: Bearer <acme.mail.inbound.http_secret>`. Answers 404 when no secret is configured.
 *
 * The answer never says what became of the message: the bridge only needs to know it was accepted.
 *
 * @author Jean-Philippe Steinmetz
 */
@Route("/internal/mail")
@Description("Ingests reply e-mails from a mail bridge.")
export class InboundMailRoute extends AcmeRoute {
    @Summary("Ingest a reply e-mail")
    @Post("/inbound")
    public async inbound(@Request req: HttpRequest, @Response res: HttpResponse): Promise<void> {
        await this.run(
            req,
            res,
            "endpointOther",
            async (): Promise<AcmeResult> => {
                const secret: string = this.ctx.settings.inboundHttpSecret;
                if (secret === "") {
                    throw AcmeProblem.malformed("Not found.", 404);
                }
                if (!bearerMatches(req, secret)) {
                    throw new AcmeProblem("unauthorized", "A bearer token is required.", 401);
                }
                const raw: Buffer | undefined = req.rawBody;
                if (!raw || raw.length === 0) {
                    throw AcmeProblem.malformed("The request body must be the raw e-mail message.");
                }
                const outcome = await this.ctx.challenges.handleInbound(raw, {
                    mailFrom: String(req.headers["x-envelope-from"] ?? ""),
                    remoteAddress: String(req.headers["x-remote-address"] ?? ""),
                });
                this.ctx.logger.debug(`Inbound mail via HTTP: ${outcome}.`);
                return { status: 202, body: { accepted: true } };
            },
            { nonce: false, plain: true },
        );
    }
}
