///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { AcmeProblem } from "../lib/acme/AcmeProblem.js";
import { randomId } from "../lib/acme/Ids.js";
import { isDuplicateKey } from "../lib/acme/Util.js";
import { jwkThumbprint, normalizeJwk, parseJws, PublicJwk, verifyJwsSignature } from "../lib/acme/Jws.js";
import { AcmeAccount } from "../models/AcmeAccount.js";
import type { AcmeContext } from "./AcmeContext.js";

const MAX_CONTACTS = 5;
const CONTACT_ADDRESS = /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/;
const ORDERS_PAGE_SIZE = 50;

/**
 * Accounts (RFC 8555 §7.3): registration, contact updates, deactivation and key rollover.
 *
 * @author Jean-Philippe Steinmetz
 */
export class AccountService {
    private readonly ctx: AcmeContext;

    constructor(ctx: AcmeContext) {
        this.ctx = ctx;
    }

    /** The account resource (RFC 8555 §7.1.2) for `account`. */
    public resource(account: AcmeAccount): Record<string, unknown> {
        return {
            status: account.status,
            contact: account.contact,
            termsOfServiceAgreed: true,
            orders: this.ctx.urls.accountOrders(account.uid),
        };
    }

    /**
     * Validates `contact` URLs: `mailto:` only, a plain address, no header fields (`?subject=...`).
     *
     * @throws `unsupportedContact` for other schemes, `invalidContact` for a bad address.
     */
    public validateContacts(contact: unknown): string[] {
        if (contact === undefined) {
            return [];
        }
        if (!Array.isArray(contact) || contact.length > MAX_CONTACTS || contact.some((c) => typeof c !== "string")) {
            throw new AcmeProblem("invalidContact", `contact must be a list of at most ${MAX_CONTACTS} mailto: URLs.`);
        }
        return contact.map((entry: string) => {
            if (!/^mailto:/i.test(entry)) {
                throw new AcmeProblem("unsupportedContact", "Only mailto: contacts are supported.");
            }
            const address: string = entry.slice("mailto:".length);
            if (address.includes("?") || address.includes(",") || !CONTACT_ADDRESS.test(address)) {
                throw new AcmeProblem("invalidContact", "The mailto: contact must be a single plain e-mail address.");
            }
            return `mailto:${address}`;
        });
    }

    /**
     * new-account (RFC 8555 §7.3): finds the account of `jwk`, or creates it.
     *
     * @returns The account and whether it was just created (HTTP 201 vs 200).
     */
    public async register(jwk: PublicJwk, payload: Record<string, any>, ipSubject: string): Promise<{ account: AcmeAccount; created: boolean }> {
        const thumbprint: string = await jwkThumbprint(jwk);
        const existing: AcmeAccount | null = await this.ctx.accountRepo.findOne({ thumbprint });
        if (existing) {
            return { account: existing, created: false };
        }
        if (payload.onlyReturnExisting === true) {
            throw new AcmeProblem("accountDoesNotExist", "No account exists for this key.");
        }
        if (payload.termsOfServiceAgreed !== true) {
            throw new AcmeProblem("userActionRequired", `You must agree to the terms of service (${this.ctx.settings.termsOfServiceUrl}) by setting termsOfServiceAgreed to true.`);
        }
        const contact: string[] = this.validateContacts(payload.contact);
        await this.ctx.limits.spend("newAccountsPerIp", ipSubject);

        const now: Date = this.ctx.now();
        const account: AcmeAccount = new AcmeAccount({
            uid: randomId(),
            status: "valid",
            thumbprint,
            jwk,
            contact,
            termsOfServiceAgreedAt: now,
            dateCreated: now,
        });
        try {
            await this.ctx.accountRepo.save(account, { insertOnly: true });
        } catch (err) {
            if (isDuplicateKey(err)) {
                // Lost a race with the same key registering concurrently: that account is the answer.
                const winner: AcmeAccount | null = await this.ctx.accountRepo.findOne({ thumbprint });
                if (winner) {
                    return { account: winner, created: false };
                }
            }
            throw err;
        }
        this.ctx.logger.info(`Registered ACME account ${account.uid}.`);
        return { account, created: true };
    }

    /**
     * Updates an account (RFC 8555 §7.3.2/§7.3.6): new contacts, or deactivation.
     *
     * @throws `malformed` for a status other than `deactivated`.
     */
    public async update(account: AcmeAccount, payload: Record<string, any>): Promise<AcmeAccount> {
        if (payload.status !== undefined) {
            if (payload.status !== "deactivated") {
                throw AcmeProblem.malformed("The only status a client can set is 'deactivated'.");
            }
            return await this.deactivate(account);
        }
        if (payload.contact !== undefined) {
            const contact: string[] = this.validateContacts(payload.contact);
            await this.ctx.accountRepo.updateOne({ uid: account.uid }, { $set: { contact } });
            return { ...account, contact };
        }
        return account;
    }

    /** Deactivates the account and cancels its outstanding authorizations and orders (RFC 8555 §7.3.6). */
    public async deactivate(account: AcmeAccount): Promise<AcmeAccount> {
        await this.ctx.accountRepo.updateOne({ uid: account.uid }, { $set: { status: "deactivated" } });
        await this.ctx.authzRepo.updateMany({ accountUid: account.uid, status: "pending" }, { $set: { status: "deactivated" } });
        await this.ctx.orderRepo.updateMany(
            { accountUid: account.uid, status: { $in: ["pending", "ready"] } },
            { $set: { status: "invalid", error: { type: "urn:ietf:params:acme:error:unauthorized", detail: "The account was deactivated.", status: 403 } } },
        );
        this.ctx.logger.info(`Deactivated ACME account ${account.uid}.`);
        return { ...account, status: "deactivated" };
    }

    /**
     * Key rollover (RFC 8555 §7.3.5). `innerBody` is the payload of the outer JWS: an inner JWS signed with the *new* key
     * whose payload names the account and the old key.
     *
     * @throws `malformed` for a bad inner JWS, `unauthorized` when it names another account or key, and a `409` `malformed`
     * (its `location` is the account that owns the key) when the new key already belongs to an account.
     */
    public async changeKey(account: AcmeAccount, innerBody: Record<string, any> | undefined, outerUrl: string): Promise<AcmeAccount> {
        if (!innerBody) {
            throw AcmeProblem.malformed("The key-change payload must be a JWS.");
        }
        const parsed = parseJws(Buffer.from(JSON.stringify(innerBody)), { nonceRequired: false });
        if (parsed.header.jwk === undefined || parsed.header.kid !== undefined) {
            throw AcmeProblem.malformed("The inner JWS must carry the new key as an embedded jwk and no kid.");
        }
        if (parsed.header.url !== outerUrl) {
            throw AcmeProblem.malformed("The inner and outer JWS must have the same url.");
        }
        await verifyJwsSignature(parsed, parsed.header.jwk);

        let content: any;
        try {
            content = JSON.parse(parsed.payloadText);
        } catch {
            throw AcmeProblem.malformed("The inner JWS payload is not valid JSON.");
        }
        if (content?.account !== this.ctx.urls.account(account.uid)) {
            throw AcmeProblem.unauthorized("The inner JWS names a different account.");
        }
        const oldKey: PublicJwk = normalizeJwk(content?.oldKey);
        if ((await jwkThumbprint(oldKey)) !== account.thumbprint) {
            throw AcmeProblem.unauthorized("oldKey is not the current key of the account.");
        }

        const newKey: PublicJwk = parsed.header.jwk;
        const thumbprint: string = await jwkThumbprint(newKey);
        if (thumbprint === account.thumbprint) {
            throw AcmeProblem.malformed("The new key is the current key.");
        }
        try {
            await this.ctx.accountRepo.updateOne({ uid: account.uid }, { $set: { jwk: newKey, thumbprint } });
        } catch (err) {
            if (isDuplicateKey(err)) {
                const holder: AcmeAccount | null = await this.ctx.accountRepo.findOne({ thumbprint });
                const problem: AcmeProblem = AcmeProblem.malformed("The new key is already in use by another account.", 409);
                problem.location = holder ? this.ctx.urls.account(holder.uid) : undefined;
                throw problem;
            }
            throw err;
        }
        this.ctx.logger.info(`Rolled the key of ACME account ${account.uid}.`);
        return { ...account, jwk: newKey, thumbprint };
    }

    /** One page of the URLs of the account's orders, newest first (RFC 8555 §7.1.2.1). */
    public async listOrders(accountUid: string, cursor: number): Promise<{ orders: string[]; next?: number }> {
        const rows = await this.ctx.orderRepo
            .find({ accountUid }, { sort: { dateCreated: -1, uid: 1 }, skip: cursor, limit: ORDERS_PAGE_SIZE + 1, projection: { uid: 1 } })
            .toArray();
        const page = rows.slice(0, ORDERS_PAGE_SIZE);
        return {
            orders: page.map((row) => this.ctx.urls.order(row.uid)),
            ...(rows.length > ORDERS_PAGE_SIZE ? { next: cursor + ORDERS_PAGE_SIZE } : {}),
        };
    }
}
