///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { createPublicKey } from "crypto";
import { AcmeProblem } from "../lib/acme/AcmeProblem.js";
import { EmailIdentifier, parseEmailIdentifier } from "../lib/acme/Identifiers.js";
import { randomId, randomToken, sha256Hex } from "../lib/acme/Ids.js";
import { canonicalMailbox, fromB64url, parseAriCertId, PkiPolicyError, resolveCertificateType, validateCsr, ValidatedCsr } from "../lib/pki/index.js";
import { AcmeAccount } from "../models/AcmeAccount.js";
import { AcmeAuthorization } from "../models/AcmeAuthorization.js";
import type { AcmeCertificate } from "../models/AcmeCertificate.js";
import { AcmeOrder, CertificateTypeName } from "../models/AcmeOrder.js";
import type { AcmeContext } from "./AcmeContext.js";

/** How long a finished order/authorization record is kept before the database deletes it, after it expired. */
const RETENTION_DAYS = 30;
/** Pending authorizations one account may hold at once (Let's Encrypt: 300). */
const MAX_PENDING_AUTHORIZATIONS = 300;
const PROFILES: readonly CertificateTypeName[] = ["signing", "encryption", "signing-encryption"];

/** The order resource of RFC 8555 §7.1.3. */
export interface OrderResource {
    status: string;
    expires: string;
    identifiers: Array<{ type: string; value: string }>;
    authorizations: string[];
    finalize: string;
    certificate?: string;
    error?: { type: string; detail: string; status: number };
    profile?: string;
    replaces?: string;
}

/**
 * Orders (RFC 8555 §7.4): creating them, keeping their status in step with their authorizations, and finalizing them
 * into certificates.
 *
 * @author Jean-Philippe Steinmetz
 */
export class OrderService {
    private readonly ctx: AcmeContext;

    constructor(ctx: AcmeContext) {
        this.ctx = ctx;
    }

    /** The wire form of `order`. */
    public resource(order: AcmeOrder): OrderResource {
        return {
            status: order.status,
            expires: order.expires.toISOString(),
            identifiers: order.identifiers,
            authorizations: order.authorizationUids.map((id) => this.ctx.urls.authorization(id)),
            finalize: this.ctx.urls.finalize(order.uid),
            ...(order.certificateUid ? { certificate: this.ctx.urls.certificate(order.certificateUid) } : {}),
            ...(order.error ? { error: order.error } : {}),
            ...(order.profile ? { profile: order.profile } : {}),
            ...(order.replaces ? { replaces: order.replaces } : {}),
        };
    }

    /**
     * new-order (RFC 8555 §7.4): validates the request, applies the rate limits and DNS policy, and creates the order with
     * one authorization (and its `email-reply-00` challenge) per identifier.
     */
    public async create(account: AcmeAccount, payload: Record<string, any>, ipSubject: string): Promise<AcmeOrder> {
        if (payload.notBefore !== undefined || payload.notAfter !== undefined) {
            throw AcmeProblem.malformed("notBefore and notAfter are not supported: certificate validity is set by the CA.");
        }
        const identifiers: EmailIdentifier[] = this.parseIdentifiers(payload.identifiers);
        const profile: CertificateTypeName | undefined = this.parseProfile(payload.profile);

        for (const id of identifiers) {
            await this.ctx.limits.check("failedAuthorizations", `${account.uid}|${id.normalized}`);
        }
        const replaced: AcmeCertificate | undefined = await this.findReplaced(account, identifiers, payload.replaces);
        if (!replaced) {
            for (const id of identifiers) {
                await this.ctx.limits.check("certificatesPerEmail", id.normalized);
                await this.ctx.limits.check("certificatesPerDomain", id.domain);
            }
        }
        const pending: number = await this.ctx.authzRepo.count({ accountUid: account.uid, status: "pending", expires: { $gt: this.ctx.now() } });
        if (pending + identifiers.length > MAX_PENDING_AUTHORIZATIONS) {
            const help: string = `${this.ctx.settings.externalUrl}/rate-limits#pending-authorizations`;
            const retryAt: string = new Date(this.ctx.now().getTime() + 3_600_000).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
            throw AcmeProblem.rateLimited(`too many pending authorizations (${MAX_PENDING_AUTHORIZATIONS}) for this account, retry after ${retryAt}: see ${help}`, 3600, help);
        }
        await this.ctx.limits.spend("newOrdersPerAccount", account.uid);

        for (const id of identifiers) {
            await this.ctx.dns.assertDeliverable(id.domain);
            await this.ctx.dns.assertCaaPermits(id.domain);
        }

        const now: Date = this.ctx.now();
        const orderExpires: Date = new Date(now.getTime() + this.ctx.settings.orderExpiryHours * 3_600_000);
        const authzExpires: Date = new Date(now.getTime() + this.ctx.settings.authorizationExpiryHours * 3_600_000);
        const purgeAt: Date = new Date(Math.max(orderExpires.getTime(), authzExpires.getTime()) + RETENTION_DAYS * 86_400_000);

        const orderUid: string = randomId();
        const authorizations: AcmeAuthorization[] = identifiers.map((id) => {
            const tokenPart1: string = randomToken();
            return new AcmeAuthorization({
                uid: randomId(),
                accountUid: account.uid,
                orderUid,
                identifier: { type: "email", value: id.address },
                status: "pending",
                expires: authzExpires,
                challenge: {
                    id: randomId(),
                    type: "email-reply-00",
                    status: "pending",
                    token: randomToken(),
                    tokenPart1,
                    from: this.ctx.settings.mailFrom,
                },
                tokenHash: sha256Hex(tokenPart1),
                dateCreated: now,
                purgeAt,
            });
        });
        for (const authz of authorizations) {
            await this.ctx.authzRepo.save(authz, { insertOnly: true });
        }
        const order: AcmeOrder = new AcmeOrder({
            uid: orderUid,
            accountUid: account.uid,
            status: "pending",
            expires: orderExpires,
            identifiers: identifiers.map((id) => ({ type: "email", value: id.address })),
            authorizationUids: authorizations.map((a) => a.uid),
            dateCreated: now,
            purgeAt,
            ...(profile ? { profile } : {}),
            ...(replaced ? { replaces: payload.replaces } : {}),
        });
        await this.ctx.orderRepo.save(order, { insertOnly: true });
        return order;
    }

    private parseIdentifiers(value: unknown): EmailIdentifier[] {
        if (!Array.isArray(value) || value.length === 0) {
            throw AcmeProblem.malformed("identifiers must be a non-empty list.");
        }
        if (value.length > this.ctx.settings.maxIdentifiers) {
            throw AcmeProblem.malformed(`An order may contain at most ${this.ctx.settings.maxIdentifiers} identifier(s).`);
        }
        const parsed: EmailIdentifier[] = value.map((entry: any) => {
            if (typeof entry !== "object" || entry === null || entry.type !== "email") {
                throw new AcmeProblem("unsupportedIdentifier", "Only identifiers of type 'email' are supported.");
            }
            return parseEmailIdentifier(entry.value);
        });
        if (new Set(parsed.map((p) => p.normalized)).size !== parsed.length) {
            throw AcmeProblem.malformed("identifiers must not contain duplicates.");
        }
        return parsed;
    }

    private parseProfile(value: unknown): CertificateTypeName | undefined {
        if (value === undefined) {
            return undefined;
        }
        if (typeof value !== "string" || !PROFILES.includes(value as CertificateTypeName)) {
            throw AcmeProblem.malformed(`Unknown profile. Available profiles: ${PROFILES.join(", ")}.`);
        }
        return value as CertificateTypeName;
    }

    /**
     * The certificate an order claims to replace (RFC 9773 §5), when it really is a renewal: issued to this account for
     * exactly these addresses. Anything else (unknown, someone else's, a different set) is quietly treated as a plain order –
     * `replaces` is a hint for the CA, never a way to fail an order. A certificate that a live order already replaces is
     * `alreadyReplaced`.
     */
    private async findReplaced(account: AcmeAccount, identifiers: EmailIdentifier[], replaces: unknown): Promise<AcmeCertificate | undefined> {
        if (replaces === undefined) {
            return undefined;
        }
        const parsed = typeof replaces === "string" ? parseAriCertId(replaces) : undefined;
        if (!parsed) {
            throw AcmeProblem.malformed("replaces is not a valid certificate id.");
        }
        const cert: AcmeCertificate | undefined = await this.ctx.certificates.findByAri(parsed);
        if (!cert || cert.accountUid !== account.uid || identifiers.length !== 1 || cert.email !== identifiers[0].normalized) {
            return undefined;
        }
        const taken: AcmeOrder | null = await this.ctx.orderRepo.findOne({ replaces, status: { $in: ["pending", "ready", "processing", "valid"] } });
        if (taken) {
            throw new AcmeProblem("alreadyReplaced", "A live order already replaces this certificate.");
        }
        return cert;
    }

    /**
     * The current state of `order`: expired orders become invalid, and a pending order whose authorizations are all valid
     * becomes ready (or invalid if one of them failed). Persists what it changes.
     */
    public async refresh(order: AcmeOrder): Promise<AcmeOrder> {
        const now: Date = this.ctx.now();
        if ((order.status === "pending" || order.status === "ready") && order.expires <= now) {
            return await this.invalidate(order, { type: "urn:ietf:params:acme:error:malformed", detail: "The order expired before it was completed.", status: 400 });
        }
        if (order.status !== "pending" && order.status !== "ready") {
            return order;
        }
        // A ready order is checked too: an authorization deactivated (or failed) after the order became ready must stop it.
        const authzs: AcmeAuthorization[] = await this.ctx.authzRepo.find({ uid: { $in: order.authorizationUids } }).toArray();
        const failed: AcmeAuthorization | undefined = authzs.find((a) => ["invalid", "expired", "deactivated", "revoked"].includes(a.status));
        if (failed) {
            return await this.invalidate(order, {
                type: failed.challenge.error?.type ?? "urn:ietf:params:acme:error:unauthorized",
                detail: failed.challenge.error?.detail ?? `The authorization for ${failed.identifier.value} is ${failed.status}.`,
                status: failed.challenge.error?.status ?? 403,
            });
        }
        if (order.status === "pending" && authzs.length === order.authorizationUids.length && authzs.every((a) => a.status === "valid")) {
            const updated: AcmeOrder | null = await this.ctx.orderRepo.findOneAndUpdate({ uid: order.uid, status: "pending" }, { $set: { status: "ready" } });
            return updated ?? (await this.ctx.orderRepo.findOne({ uid: order.uid })) ?? order;
        }
        return order;
    }

    private async invalidate(order: AcmeOrder, error: { type: string; detail: string; status: number }): Promise<AcmeOrder> {
        const updated: AcmeOrder | null = await this.ctx.orderRepo.findOneAndUpdate(
            { uid: order.uid, status: { $in: ["pending", "ready"] } },
            { $set: { status: "invalid", error } },
        );
        return updated ?? (await this.ctx.orderRepo.findOne({ uid: order.uid })) ?? order;
    }

    /** Loads an order that belongs to `accountUid`, refreshed. */
    public async load(orderUid: string, accountUid: string): Promise<AcmeOrder> {
        const order: AcmeOrder | null = await this.ctx.orderRepo.findOne({ uid: orderUid });
        if (!order) {
            throw AcmeProblem.malformed("No such order.", 404);
        }
        if (order.accountUid !== accountUid) {
            throw AcmeProblem.unauthorized("The order belongs to a different account.");
        }
        return await this.refresh(order);
    }

    /**
     * finalize (RFC 8555 §7.4): validates the CSR against the order, applies the certificate rate limits, re-checks CAA,
     * signs, and answers with the now-valid order.
     *
     * The order moves `ready → processing` in one atomic update, so two concurrent finalize calls can never both issue. A
     * CSR the client can fix (`badCSR`, `badPublicKey`) or a rate limit puts the order back to `ready`; a CAA refusal
     * invalidates it.
     *
     * @param csrB64url The `csr` member of the finalize request: base64url DER.
     */
    public async finalize(account: AcmeAccount, order: AcmeOrder, csrB64url: unknown): Promise<AcmeOrder> {
        if (typeof csrB64url !== "string" || csrB64url.length === 0 || !/^[A-Za-z0-9_-]+$/.test(csrB64url)) {
            throw AcmeProblem.malformed("The finalize request needs a csr: the base64url DER of a PKCS#10 request.");
        }
        if (order.status !== "ready") {
            throw new AcmeProblem("orderNotReady", `The order is ${order.status}, not ready: every authorization must be valid before it is finalized.`);
        }
        // Finalize does real work (signature checks, a signature): cap how often one account can ask, valid or not.
        await this.ctx.limits.spend("finalizesPerAccount", account.uid);
        const claimed: AcmeOrder | null = await this.ctx.orderRepo.findOneAndUpdate(
            { uid: order.uid, status: "ready" },
            { $set: { status: "processing", processingSince: this.ctx.now() } },
        );
        if (!claimed) {
            throw new AcmeProblem("orderNotReady", "The order is already being finalized.");
        }

        let outcome: "ready" | "invalid" = "ready";
        try {
            const validated: ValidatedCsr = await this.validate(account, claimed, csrB64url);
            const emails: EmailIdentifier[] = claimed.identifiers.map((i) => parseEmailIdentifier(i.value));
            const type: CertificateTypeName = resolveCertificateType(validated.requestedType, claimed.profile);

            const renewal: boolean = claimed.replaces !== undefined;
            for (const email of emails) {
                await this.ctx.dns.assertCaaPermits(email.domain);
            }
            if (!renewal) {
                for (const email of emails) {
                    await this.ctx.limits.spend("certificatesPerEmail", email.normalized);
                    await this.ctx.limits.spend("certificatesPerDomain", email.domain);
                }
            }
            const certificate: AcmeCertificate = await this.ctx.certificates.issue({ account, order: claimed, email: emails[0], csr: validated, type });
            const done: AcmeOrder | null = await this.ctx.orderRepo.findOneAndUpdate(
                { uid: claimed.uid, status: "processing" },
                { $set: { status: "valid", certificateUid: certificate.uid, spkiSha256: validated.spkiSha256, certificateType: type }, $unset: { processingSince: "" } },
            );
            return done ?? claimed;
        } catch (err) {
            // A rule the PKI library enforces (the CSR's key usage against the order's profile) is the client's to fix.
            const problem: unknown = err instanceof PkiPolicyError ? new AcmeProblem(err.code, err.message) : err;
            if (problem instanceof AcmeProblem && problem.errorType === "caa") {
                outcome = "invalid";
            }
            throw problem;
        } finally {
            const stillProcessing: AcmeOrder | null = await this.ctx.orderRepo.findOne({ uid: claimed.uid, status: "processing" });
            // If the certificate was stored but the order update failed, the order is valid, not ready: going back to ready would
            // let a second finalize issue a second certificate for one order.
            const stored = stillProcessing ? await this.ctx.certRepo.findOne({ orderUid: claimed.uid }).catch(() => null) : null;
            if (stillProcessing && stored) {
                await this.ctx.orderRepo.updateOne(
                    { uid: claimed.uid, status: "processing" },
                    { $set: { status: "valid", certificateUid: stored.uid }, $unset: { processingSince: "" } },
                );
            } else if (stillProcessing) {
                await this.ctx.orderRepo.updateOne(
                    { uid: claimed.uid, status: "processing" },
                    outcome === "invalid"
                        ? { $set: { status: "invalid", error: { type: "urn:ietf:params:acme:error:caa", detail: "CAA forbids issuance.", status: 403 } }, $unset: { processingSince: "" } }
                        : { $set: { status: "ready" }, $unset: { processingSince: "" } },
                );
            }
        }
    }

    /** Parses the CSR and applies every policy that needs the order or the database. */
    private async validate(account: AcmeAccount, order: AcmeOrder, csrB64url: string): Promise<ValidatedCsr> {
        let validated: ValidatedCsr;
        try {
            validated = await validateCsr(fromB64url(csrB64url), { forbiddenSpkiSha256: [this.accountKeyHash(account)] });
        } catch (err) {
            if (err instanceof PkiPolicyError) {
                throw new AcmeProblem(err.code, err.message);
            }
            throw err;
        }
        const key = (address: string): string => canonicalMailbox(address)?.key ?? address.toLowerCase();
        const wanted: string[] = order.identifiers.map((i) => key(i.value)).sort();
        const got: string[] = validated.emails.map(key).sort();
        if (wanted.length !== got.length || wanted.some((value, i) => value !== got[i])) {
            throw new AcmeProblem("badCSR", "The CSR must request exactly the identifiers of the order (as rfc822Name or SmtpUTF8Mailbox subject alternative names).");
        }
        const compromised: AcmeCertificate | null = await this.ctx.certRepo.findOne({ spkiSha256: validated.spkiSha256, revocationReason: 1 });
        if (compromised) {
            throw new AcmeProblem("badPublicKey", "This public key was revoked as compromised and cannot be certified again.");
        }
        return validated;
    }

    /** SHA-256 (hex) of the SPKI of the account key, so a CSR cannot reuse it (RFC 8555 §11.1). */
    private accountKeyHash(account: AcmeAccount): string {
        const der: Buffer = createPublicKey({ key: account.jwk as any, format: "jwk" }).export({ type: "spki", format: "der" });
        return sha256Hex(der);
    }
}
