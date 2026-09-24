///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import type { HttpRequest, HttpResponse } from "@rapidrest/service-core";
import { AcmeProblem } from "../lib/acme/AcmeProblem.js";
import { bearerMatches } from "../lib/acme/Bearer.js";
import { AcmeResult, AcmeRoute } from "./AcmeRoute.js";

/**
 * Base of the operator API routes (`/admin/*`): the one place that decides who may call them.
 *
 * The API is a single bearer secret (`acme.admin_secret`) with full power over what the CA has issued, so it is treated like the CA's
 * keys: it does not exist (404) without a secret, a wrong token is a 401 that also costs the caller's IP a token from a small
 * bucket (so it cannot be guessed at), the comparison is constant-time, and every action is logged with the optional `X-Operator`
 * label. It must be reached over the internal network only; the Helm chart never routes `/admin` publicly.
 *
 * @author Jean-Philippe Steinmetz
 */
export abstract class AdminBaseRoute extends AcmeRoute {
    /**
     * Runs an operator API handler after authenticating the caller.
     *
     * @param work Gets the validated operator label (or `undefined`).
     */
    protected async adminRun(req: HttpRequest, res: HttpResponse, work: (operator: string | undefined) => Promise<AcmeResult>): Promise<void> {
        await this.run(
            req,
            res,
            "endpointOther",
            async (): Promise<AcmeResult> => {
                const secret: string = this.ctx.settings.adminSecret;
                if (secret === "") {
                    throw AcmeProblem.malformed("Not found.", 404);
                }
                const ip: string = this.ctx.ipSubject(req);
                await this.ctx.limits.check("adminAuthFailuresPerIp", ip);
                if (!bearerMatches(req, secret)) {
                    await this.ctx.limits.spend("adminAuthFailuresPerIp", ip);
                    throw new AcmeProblem("unauthorized", "A bearer token is required.", 401);
                }
                return await work(this.ctx.admin.parseOperator(req.headers["x-operator"]));
            },
            { nonce: false, plain: true },
        );
    }

    /** The JSON object body of `req` (`{}` when there is none). */
    protected jsonBody(req: HttpRequest): Record<string, any> {
        if (!req.rawBody || req.rawBody.length === 0) {
            return {};
        }
        let value: unknown;
        try {
            value = JSON.parse(req.rawBody.toString("utf8"));
        } catch {
            throw AcmeProblem.malformed("The request body is not valid JSON.");
        }
        if (typeof value !== "object" || value === null || Array.isArray(value)) {
            throw AcmeProblem.malformed("The request body must be a JSON object.");
        }
        return value as Record<string, any>;
    }
}
