///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { DocDecorators, HttpRequest, HttpResponse, RouteDecorators } from "@rapidrest/service-core";
import { AcmeProblem } from "../lib/acme/AcmeProblem.js";
import { AcmeResult, AcmeRoute } from "./AcmeRoute.js";
const { Description, Summary } = DocDecorators;
const { Get, Param, Post, Request, Response, Route } = RouteDecorators;

/** The largest OCSP request accepted (RFC 5019 requests are around 100 bytes). */
const MAX_OCSP_REQUEST_BYTES = 8 * 1024;

/**
 * The OCSP responder endpoint (RFC 6960 Appendix A / RFC 5019): `POST` with an `application/ocsp-request` body, or `GET` with the
 * base64 of the request as the last path segment.
 *
 * @author Jean-Philippe Steinmetz
 */
@Route("/ocsp")
@Description("The OCSP responder.")
export class OcspRoute extends AcmeRoute {
    private async answer(requestDer: Uint8Array): Promise<AcmeResult> {
        const response: Uint8Array = await this.ctx.ocsp.respond(requestDer);
        return {
            status: 200,
            raw: Buffer.from(response),
            contentType: "application/ocsp-response",
            cacheControl: `public, max-age=${Math.min(this.ctx.settings.ocspValidityHours * 3600, 3600)}`,
        };
    }

    @Summary("Answer an OCSP request sent as a POST body")
    @Post()
    public async post(@Request req: HttpRequest, @Response res: HttpResponse): Promise<void> {
        await this.run(
            req,
            res,
            "endpointOther",
            async (): Promise<AcmeResult> => {
                const body: Buffer | undefined = req.rawBody;
                if (!body || body.length === 0 || body.length > MAX_OCSP_REQUEST_BYTES) {
                    throw AcmeProblem.malformed("The OCSP request is missing or too large.");
                }
                return await this.answer(new Uint8Array(body));
            },
            { nonce: false, plain: true },
        );
    }

    @Summary("Answer an OCSP request sent in the URL")
    @Get("/:request")
    public async get(@Param("request") request: string, @Request req: HttpRequest, @Response res: HttpResponse): Promise<void> {
        await this.run(
            req,
            res,
            "endpointOther",
            async (): Promise<AcmeResult> => {
                // Standard or URL-safe base64, with or without padding (clients differ).
                const normalized: string = String(request).replace(/ /g, "+");
                if (normalized.length === 0 || normalized.length > (MAX_OCSP_REQUEST_BYTES * 4) / 3 || !/^[A-Za-z0-9+/_-]+={0,2}$/.test(normalized)) {
                    throw AcmeProblem.malformed("The OCSP request is not valid base64.");
                }
                const der: Buffer = Buffer.from(normalized.replace(/-/g, "+").replace(/_/g, "/"), "base64");
                return await this.answer(new Uint8Array(der));
            },
            { nonce: false, plain: true },
        );
    }
}
