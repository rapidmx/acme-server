///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { DocDecorators, HttpRequest, HttpResponse, RouteDecorators } from "@rapidrest/service-core";
import { AcmeProblem } from "../lib/acme/AcmeProblem.js";
import { AcmeCertificate } from "../models/AcmeCertificate.js";
import { AdminBaseRoute } from "./AdminBaseRoute.js";
const { Description, Summary } = DocDecorators;
const { Get, Param, Post, Request, Response, Route } = RouteDecorators;

/** The first value of a query parameter (a repeated one is a client error, not something to guess about). */
function queryValue(req: HttpRequest, name: string): string | undefined {
    const value = req.query[name];
    if (Array.isArray(value)) {
        throw AcmeProblem.malformed(`${name} may be given only once.`);
    }
    return value === undefined || value === "" ? undefined : String(value);
}

/**
 * Operator API: search the certificates the CA issued and revoke them, one at a time or by selection. See `AdminBaseRoute` for how
 * callers are authenticated.
 *
 * - `GET /admin/certificates?email=&serial=&account=&spki=&status=&issuer=&limit=&cursor=`
 * - `GET /admin/certificates/:serial` (with the PEM)
 * - `POST /admin/certificates/:serial/revoke` `{ reason?, note? }`
 * - `POST /admin/revocations` `{ selector: { email | account | spki | serials }, reason?, note?, dryRun? }`
 *
 * @author Jean-Philippe Steinmetz
 */
@Route("/admin")
@Description("Operator API: search and revoke issued certificates.")
export class AdminCertificateRoute extends AdminBaseRoute {
    @Summary("Search issued certificates")
    @Get("/certificates")
    public async search(@Request req: HttpRequest, @Response res: HttpResponse): Promise<void> {
        await this.adminRun(req, res, async () => {
            const criteria = {
                email: queryValue(req, "email"),
                serial: queryValue(req, "serial"),
                account: queryValue(req, "account"),
                spki: queryValue(req, "spki"),
                status: queryValue(req, "status"),
                issuer: queryValue(req, "issuer"),
            };
            return { status: 200, body: await this.ctx.admin.search(criteria, queryValue(req, "limit"), queryValue(req, "cursor")) };
        });
    }

    @Summary("Get one issued certificate")
    @Get("/certificates/:serial")
    public async get(@Param("serial") serial: string, @Request req: HttpRequest, @Response res: HttpResponse): Promise<void> {
        await this.adminRun(req, res, async () => {
            const cert: AcmeCertificate = await this.ctx.admin.get(serial);
            return { status: 200, body: { ...this.ctx.admin.describe(cert), pem: this.ctx.certificates.chainPem(cert) } };
        });
    }

    @Summary("Revoke one certificate")
    @Post("/certificates/:serial/revoke")
    public async revoke(@Param("serial") serial: string, @Request req: HttpRequest, @Response res: HttpResponse): Promise<void> {
        await this.adminRun(req, res, async (operator) => {
            const body = this.jsonBody(req);
            const cert: AcmeCertificate = await this.ctx.admin.revoke(serial, this.ctx.admin.parseReason(body.reason), this.ctx.admin.parseNote(body.note), operator);
            return { status: 200, body: this.ctx.admin.describe(cert) };
        });
    }

    @Summary("Revoke every valid certificate a selector names")
    @Post("/revocations")
    public async revokeMany(@Request req: HttpRequest, @Response res: HttpResponse): Promise<void> {
        await this.adminRun(req, res, async (operator) => {
            const body = this.jsonBody(req);
            const result = await this.ctx.admin.revokeMany(
                body.selector,
                this.ctx.admin.parseReason(body.reason),
                this.ctx.admin.parseNote(body.note),
                operator,
                body.dryRun === true,
            );
            return { status: 200, body: result };
        });
    }
}
