///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { DocDecorators, HttpRequest, HttpResponse, RouteDecorators } from "@rapidrest/service-core";
import { AcmeProblem } from "../lib/acme/AcmeProblem.js";
import { AcmeAccount } from "../models/AcmeAccount.js";
import { AcmeResult, AcmeRoute } from "./AcmeRoute.js";
const { Description, Summary } = DocDecorators;
const { Param, Post, Query, Request, Response, Route } = RouteDecorators;

/**
 * Accounts (RFC 8555 §7.3): registration, contact updates, deactivation, order lists and key rollover.
 *
 * @author Jean-Philippe Steinmetz
 */
@Route("/acme")
@Description("ACME accounts.")
export class AccountRoute extends AcmeRoute {
    @Summary("new-account")
    @Post("/new-acct")
    public async newAccount(@Request req: HttpRequest, @Response res: HttpResponse): Promise<void> {
        await this.run(
            req,
            res,
            "endpointNewAccount",
            async (): Promise<AcmeResult> => {
                const auth = await this.authenticate(req, "jwk");
                if (auth.payload === undefined) {
                    throw AcmeProblem.malformed("new-account requires a JSON payload (POST-as-GET is not allowed here).");
                }
                const { account, created } = await this.ctx.accounts.register(auth.jwk, auth.payload, this.ctx.ipSubject(req));
                return { status: created ? 201 : 200, body: this.ctx.accounts.resource(account), location: this.ctx.urls.account(account.uid) };
            },
            { nonce: true },
        );
    }

    /** The account `auth` names must be the one in the URL: an account only ever manages itself. */
    private requireSelf(id: string, account: AcmeAccount | undefined): AcmeAccount {
        if (!account || account.uid !== id) {
            throw AcmeProblem.unauthorized("The account URL does not belong to the account that signed the request.");
        }
        return account;
    }

    @Summary("Read, update or deactivate an account")
    @Post("/acct/:id")
    public async account(@Param("id") id: string, @Request req: HttpRequest, @Response res: HttpResponse): Promise<void> {
        await this.run(
            req,
            res,
            "endpointOther",
            async (): Promise<AcmeResult> => {
                const auth = await this.authenticate(req, "kid");
                let account: AcmeAccount = this.requireSelf(id, auth.account);
                if (auth.payload !== undefined) {
                    account = await this.ctx.accounts.update(account, auth.payload);
                }
                return { status: 200, body: this.ctx.accounts.resource(account), location: this.ctx.urls.account(account.uid) };
            },
            { nonce: true },
        );
    }

    @Summary("List the orders of an account")
    @Post("/acct/:id/orders")
    public async orders(@Param("id") id: string, @Query("cursor") cursorText: string | undefined, @Request req: HttpRequest, @Response res: HttpResponse): Promise<void> {
        await this.run(
            req,
            res,
            "endpointOther",
            async (): Promise<AcmeResult> => {
                const cursor: number = cursorText !== undefined && /^\d{1,9}$/.test(String(cursorText)) ? Number(cursorText) : 0;
                const base: string = this.ctx.urls.accountOrders(id);
                const auth = await this.authenticate(req, "kid", cursor > 0 ? `${base}?cursor=${cursor}` : base);
                this.requireSelf(id, auth.account);
                const page = await this.ctx.accounts.listOrders(id, cursor);
                return {
                    status: 200,
                    body: { orders: page.orders },
                    ...(page.next !== undefined ? { links: [`<${base}?cursor=${page.next}>;rel="next"`] } : {}),
                };
            },
            { nonce: true },
        );
    }

    @Summary("Roll the account key over")
    @Post("/key-change")
    public async keyChange(@Request req: HttpRequest, @Response res: HttpResponse): Promise<void> {
        await this.run(
            req,
            res,
            "endpointOther",
            async (): Promise<AcmeResult> => {
                const auth = await this.authenticate(req, "kid");
                const account: AcmeAccount = await this.ctx.accounts.changeKey(auth.account!, auth.payload, this.ctx.urls.keyChange());
                return { status: 200, body: this.ctx.accounts.resource(account), location: this.ctx.urls.account(account.uid) };
            },
            { nonce: true },
        );
    }
}
