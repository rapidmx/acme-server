///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import * as prom from "prom-client";
import { DocDecorators, HttpRequest, HttpResponse, RouteDecorators } from "@rapidrest/service-core";
import { AcmeProblem } from "../lib/acme/AcmeProblem.js";
import { bearerMatches } from "../lib/acme/Bearer.js";
import { AcmeResult, AcmeRoute } from "./AcmeRoute.js";
const { Description, Summary } = DocDecorators;
const { Get, Request, Response, Route } = RouteDecorators;

/**
 * Prometheus metrics. Guarded by a bearer secret (`acme.metrics_secret`) and absent (404) when none is configured: the metrics
 * of a CA are operational data, not for the internet. Scrape it from inside the cluster.
 *
 * @author Jean-Philippe Steinmetz
 */
@Route("/metrics")
@Description("Prometheus metrics.")
export class MetricsRoute extends AcmeRoute {
    @Summary("Prometheus metrics")
    @Get()
    public async get(@Request req: HttpRequest, @Response res: HttpResponse): Promise<void> {
        await this.run(
            req,
            res,
            "endpointOther",
            async (): Promise<AcmeResult> => {
                const secret: string = this.ctx.settings.metricsSecret;
                if (secret === "") {
                    throw AcmeProblem.malformed("Not found.", 404);
                }
                if (!bearerMatches(req, secret)) {
                    throw new AcmeProblem("unauthorized", "A bearer token is required.", 401);
                }
                return { status: 200, raw: await prom.register.metrics(), contentType: prom.register.contentType };
            },
            { nonce: false, plain: true },
        );
    }
}
