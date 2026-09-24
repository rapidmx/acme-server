///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { DocDecorators, HttpRequest, HttpResponse, RouteDecorators } from "@rapidrest/service-core";
import { renderRateLimits } from "../lib/acme/InfoPages.js";
import { DEFAULT_LIMITS } from "../lib/acme/RateLimits.js";
import { AcmeResult, AcmeRoute } from "./AcmeRoute.js";
const { Description, Summary } = DocDecorators;
const { Get, Request, Response, Route } = RouteDecorators;

/**
 * The rate-limit documentation every `rateLimited` problem links to, generated from the limits that are actually enforced.
 *
 * @author Jean-Philippe Steinmetz
 */
@Route("/rate-limits")
@Description("The rate limits.")
export class RateLimitsRoute extends AcmeRoute {
    @Summary("Rate limits")
    @Get()
    public async get(@Request req: HttpRequest, @Response res: HttpResponse): Promise<void> {
        await this.run(
            req,
            res,
            "endpointOther",
            async (): Promise<AcmeResult> =>
                String(req.headers["accept"] ?? "").includes("application/json")
                    ? { status: 200, body: DEFAULT_LIMITS, cacheControl: "public, max-age=3600" }
                    : { status: 200, raw: renderRateLimits(DEFAULT_LIMITS), contentType: "text/html; charset=utf-8", cacheControl: "public, max-age=3600" },
            { nonce: false, plain: true },
        );
    }
}
