///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { DocDecorators, HttpRequest, HttpResponse, RouteDecorators } from "@rapidrest/service-core";
import { AcmeProblem } from "../lib/acme/AcmeProblem.js";
import { AcmeCertificate } from "../models/AcmeCertificate.js";
import { AcmeOrder } from "../models/AcmeOrder.js";
import { AcmeResult, AcmeRoute } from "./AcmeRoute.js";
const { Description, Summary } = DocDecorators;
const { Param, Post, Request, Response, Route } = RouteDecorators;

/**
 * Orders (RFC 8555 §7.4): placing one, reading it, finalizing it with a CSR, and downloading the certificate.
 *
 * @author Jean-Philippe Steinmetz
 */
@Route("/acme")
@Description("ACME orders and certificates.")
export class OrderRoute extends AcmeRoute {
    @Summary("new-order")
    @Post("/new-order")
    public async newOrder(@Request req: HttpRequest, @Response res: HttpResponse): Promise<void> {
        await this.run(
            req,
            res,
            "endpointNewOrder",
            async (): Promise<AcmeResult> => {
                const auth = await this.authenticate(req, "kid");
                if (auth.payload === undefined) {
                    throw AcmeProblem.malformed("new-order requires a JSON payload (POST-as-GET is not allowed here).");
                }
                const order: AcmeOrder = await this.ctx.orders.create(auth.account!, auth.payload, this.ctx.ipSubject(req));
                return { status: 201, body: this.ctx.orders.resource(order), location: this.ctx.urls.order(order.uid) };
            },
            { nonce: true },
        );
    }

    @Summary("Read an order")
    @Post("/order/:id")
    public async order(@Param("id") id: string, @Request req: HttpRequest, @Response res: HttpResponse): Promise<void> {
        await this.run(
            req,
            res,
            "endpointOther",
            async (): Promise<AcmeResult> => {
                const auth = await this.authenticate(req, "kid");
                const order: AcmeOrder = await this.ctx.orders.load(id, auth.account!.uid);
                return { status: 200, body: this.ctx.orders.resource(order), location: this.ctx.urls.order(order.uid) };
            },
            { nonce: true },
        );
    }

    @Summary("Finalize an order with a CSR")
    @Post("/order/:id/finalize")
    public async finalize(@Param("id") id: string, @Request req: HttpRequest, @Response res: HttpResponse): Promise<void> {
        await this.run(
            req,
            res,
            "endpointOther",
            async (): Promise<AcmeResult> => {
                const auth = await this.authenticate(req, "kid");
                if (auth.payload === undefined) {
                    throw AcmeProblem.malformed("finalize requires a JSON payload with the csr.");
                }
                const order: AcmeOrder = await this.ctx.orders.load(id, auth.account!.uid);
                const finalized: AcmeOrder = await this.ctx.orders.finalize(auth.account!, order, auth.payload.csr);
                return { status: 200, body: this.ctx.orders.resource(finalized), location: this.ctx.urls.order(finalized.uid) };
            },
            { nonce: true },
        );
    }

    @Summary("Download an issued certificate")
    @Post("/cert/:id")
    public async certificate(@Param("id") id: string, @Request req: HttpRequest, @Response res: HttpResponse): Promise<void> {
        await this.run(
            req,
            res,
            "endpointOther",
            async (): Promise<AcmeResult> => {
                const auth = await this.authenticate(req, "kid");
                if (!auth.postAsGet) {
                    throw AcmeProblem.malformed("Certificates are downloaded with a POST-as-GET (an empty payload).");
                }
                const cert: AcmeCertificate = await this.ctx.certificates.loadForAccount(id, auth.account!);
                return { status: 200, raw: this.ctx.certificates.chainPem(cert), contentType: "application/pem-certificate-chain" };
            },
            { nonce: true },
        );
    }
}
