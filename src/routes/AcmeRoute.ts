///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { ObjectDecorators } from "@rapidrest/core";
import type { HttpRequest, HttpResponse } from "@rapidrest/service-core";
import { AcmeProblem } from "../lib/acme/AcmeProblem.js";
import type { LimitName } from "../lib/acme/RateLimits.js";
import { AcmeContext } from "../services/AcmeContext.js";
const { Inject, Logger } = ObjectDecorators;

/** How `AcmeRoute.run()` frames a response. */
export interface RunOptions {
    /** Send a `Replay-Nonce`. */
    nonce: boolean;
    /** Not an ACME endpoint: no directory `Link`, plain JSON errors. */
    plain?: boolean;
}

/** What an ACME handler produces; `AcmeRoute.run()` turns it into the HTTP response. */
export interface AcmeResult {
    status: number;
    /** A JSON body. */
    body?: unknown;
    /** A body that is sent as is, with `contentType`. */
    raw?: string | Buffer | Uint8Array;
    contentType?: string;
    /** The `Location` header (RFC 8555: the URL of a created resource, or the canonical URL of the resource). */
    location?: string;
    /** Further `Link` headers, complete (`<url>;rel="up"`). */
    links?: string[];
    /** `Retry-After` in seconds. */
    retryAfterSeconds?: number;
    /** Any other response headers. */
    headers?: Record<string, string>;
    /** `Cache-Control`. ACME resources are never cached; the public trust endpoints override this. */
    cacheControl?: string;
}

/**
 * Base of every route class of the CA: the response conventions RFC 8555 §6 requires of every ACME response, in one place.
 *
 * - A fresh `Replay-Nonce` on every response to a POST, including errors (§6.5), and on `new-nonce`.
 * - `Link: <directory>;rel="index"` on every ACME response.
 * - Errors as `application/problem+json` with the `urn:ietf:params:acme:error:` type, `Retry-After` and a `rel="help"` link for rate
 * limits (§6.7). Anything that is not an `AcmeProblem` is logged and answered as a bare `serverInternal`.
 * - The per-IP endpoint rate limit is spent before anything else happens.
 *
 * @author Jean-Philippe Steinmetz
 */
export abstract class AcmeRoute {
    @Inject(AcmeContext)
    protected ctx!: AcmeContext;

    @Logger
    protected logger: any;

    /**
     * Runs an ACME handler and writes its result.
     *
     * @param req The request.
     * @param res The response.
     * @param limit The endpoint rate limit to spend against the caller's IP first.
     * @param work The handler.
     * @param options `nonce`: send a `Replay-Nonce` (every POST, and new-nonce). `plain`: not an ACME endpoint (the public
     * trust endpoints): no directory `Link`, and errors as a small plain JSON document instead of a problem document.
     */
    protected async run(req: HttpRequest, res: HttpResponse, limit: LimitName, work: () => Promise<AcmeResult>, options: RunOptions): Promise<void> {
        try {
            if (!this.ctx?.ready) {
                throw AcmeProblem.internal();
            }
            await this.ctx.limits.spend(limit, this.ctx.ipSubject(req));
            const result: AcmeResult = await work();
            await this.write(res, result, options);
        } catch (err: any) {
            await this.writeError(res, err, options);
        }
    }

    private async write(res: HttpResponse, result: AcmeResult, options: RunOptions): Promise<void> {
        res.status(result.status);
        await this.commonHeaders(res, options);
        res.setHeader("cache-control", result.cacheControl ?? "no-store");
        if (result.location) {
            res.setHeader("location", result.location);
        }
        for (const link of result.links ?? []) {
            res.appendHeader("link", link);
        }
        if (result.retryAfterSeconds !== undefined) {
            res.setHeader("retry-after", Math.ceil(result.retryAfterSeconds));
        }
        for (const [name, value] of Object.entries(result.headers ?? {})) {
            res.setHeader(name, value);
        }
        if (result.raw !== undefined) {
            res.setHeader("content-type", result.contentType ?? "application/octet-stream");
            res.end(result.raw as any);
        } else if (result.body !== undefined) {
            res.setHeader("content-type", result.contentType ?? "application/json");
            res.end(JSON.stringify(result.body));
        } else {
            res.end();
        }
    }

    private async writeError(res: HttpResponse, err: unknown, options: RunOptions): Promise<void> {
        let problem: AcmeProblem;
        if (err instanceof AcmeProblem) {
            problem = err;
        } else {
            this.logger?.error(err);
            problem = AcmeProblem.internal();
        }
        res.status(problem.status);
        await this.commonHeaders(res, options);
        res.setHeader("cache-control", "no-store");
        res.setHeader("content-type", options.plain ? "application/json" : "application/problem+json");
        if (problem.retryAfterSeconds !== undefined) {
            res.setHeader("retry-after", problem.retryAfterSeconds);
        }
        if (problem.helpUrl) {
            res.appendHeader("link", `<${problem.helpUrl}>;rel="help"`);
        }
        if (problem.location) {
            res.setHeader("location", problem.location);
        }
        res.end(JSON.stringify(options.plain ? { error: problem.message } : problem.toDocument()));
    }

    /** The headers every ACME response carries: the directory link and, for POSTs, a fresh nonce. */
    private async commonHeaders(res: HttpResponse, options: RunOptions): Promise<void> {
        if (this.ctx?.ready && !options.plain) {
            res.appendHeader("link", `<${this.ctx.urls.directory()}>;rel="index"`);
            if (options.nonce) {
                try {
                    res.setHeader("replay-nonce", await this.ctx.nonces.issue());
                } catch (err) {
                    // Answering without a nonce is better than not answering; the client will fetch one from new-nonce.
                    this.logger?.error(err);
                }
            }
        }
    }

    /** Asks `ctx.auth` to authenticate a POST. */
    protected authenticate(req: HttpRequest, mode: "kid" | "jwk" | "either", expectedUrl?: string) {
        return this.ctx.auth.authenticate(req, mode, expectedUrl);
    }
}
