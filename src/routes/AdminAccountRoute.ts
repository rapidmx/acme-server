///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { DocDecorators, HttpRequest, HttpResponse, RouteDecorators } from "@rapidrest/service-core";
import { AcmeProblem } from "../lib/acme/AcmeProblem.js";
import { AdminBaseRoute } from "./AdminBaseRoute.js";
const { Description, Summary } = DocDecorators;
const { Get, Param, Post, Request, Response, Route } = RouteDecorators;

/** An account id is 22 base64url characters; anything else cannot exist and never reaches the database. */
function accountId(value: string): string {
    if (!/^[A-Za-z0-9_-]{8,128}$/.test(value)) {
        throw AcmeProblem.malformed("No such account.", 404);
    }
    return value;
}

/**
 * Operator API: look at an ACME account and suspend it (or lift the suspension).
 *
 * - `GET /admin/accounts/:id`
 * - `POST /admin/accounts/:id/suspend` `{ note?, revokeCertificates?: boolean, reason? }`
 * - `POST /admin/accounts/:id/reinstate`
 *
 * @author Jean-Philippe Steinmetz
 */
@Route("/admin/accounts")
@Description("Operator API: manage ACME accounts.")
export class AdminAccountRoute extends AdminBaseRoute {
    @Summary("Get an account")
    @Get("/:id")
    public async get(@Param("id") id: string, @Request req: HttpRequest, @Response res: HttpResponse): Promise<void> {
        await this.adminRun(req, res, async () => ({ status: 200, body: await this.ctx.admin.getAccount(accountId(id)) }));
    }

    @Summary("Suspend an account")
    @Post("/:id/suspend")
    public async suspend(@Param("id") id: string, @Request req: HttpRequest, @Response res: HttpResponse): Promise<void> {
        await this.adminRun(req, res, async (operator) => {
            const body = this.jsonBody(req);
            const revoke: { reason: number } | undefined = body.revokeCertificates === true ? { reason: this.ctx.admin.parseReason(body.reason) } : undefined;
            return { status: 200, body: await this.ctx.admin.suspendAccount(accountId(id), this.ctx.admin.parseNote(body.note), operator, revoke) };
        });
    }

    @Summary("Lift the suspension of an account")
    @Post("/:id/reinstate")
    public async reinstate(@Param("id") id: string, @Request req: HttpRequest, @Response res: HttpResponse): Promise<void> {
        await this.adminRun(req, res, async (operator) => ({ status: 200, body: await this.ctx.admin.reinstateAccount(accountId(id), operator) }));
    }
}
