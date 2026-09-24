///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { DocDecorators, HttpRequest, HttpResponse, RouteDecorators } from "@rapidrest/service-core";
import { AcmeRoute } from "./AcmeRoute.js";
const { Description, Summary } = DocDecorators;
const { Get, Head, Request, Response, Route } = RouteDecorators;

/**
 * new-nonce (RFC 8555 §7.2): hands out a fresh anti-replay nonce. `HEAD` answers 200, `GET` 204, both with `Replay-Nonce`.
 *
 * @author Jean-Philippe Steinmetz
 */
@Route("/acme/new-nonce")
@Description("Issues a fresh anti-replay nonce.")
export class NonceRoute extends AcmeRoute {
    @Summary("Get a nonce")
    @Get()
    public async get(@Request req: HttpRequest, @Response res: HttpResponse): Promise<void> {
        await this.run(req, res, "endpointNonce", async () => ({ status: 204 }), { nonce: true });
    }

    @Summary("Head a nonce")
    @Head()
    public async head(@Request req: HttpRequest, @Response res: HttpResponse): Promise<void> {
        await this.run(req, res, "endpointNonce", async () => ({ status: 200 }), { nonce: true });
    }
}
