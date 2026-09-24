///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { AcmeProblem } from "../lib/acme/AcmeProblem.js";
import { MAX_BULK_REVOCATION, OPERATOR_REVOCATION_REASONS } from "../lib/acme/RevocationReasons.js";
import { normalizeSerial } from "../lib/acme/Util.js";
import { canonicalMailbox } from "../lib/pki/index.js";
import type { AcmeAccount } from "../models/AcmeAccount.js";
import type { AcmeCertificate } from "../models/AcmeCertificate.js";
import type { AcmeContext } from "./AcmeContext.js";

const MAX_NOTE_LENGTH = 500;
const MAX_LIST_LIMIT = 100;

/** A certificate as the admin API shows it (no private material exists to leak; the PEM is public anyway). */
export interface AdminCertificate {
    serial: string;
    status: string;
    email: string;
    type: string;
    issuer: string;
    account: string;
    order: string;
    notBefore: string;
    notAfter: string;
    issuedAt: string;
    spkiSha256: string;
    sha256Fingerprint: string;
    revokedAt?: string;
    reason?: number;
    revokedBy?: string;
    source?: string;
    note?: string;
}

/** What a bulk revocation selects certificates by; exactly one member. */
export interface RevocationSelector {
    email?: string;
    account?: string;
    spki?: string;
    serials?: string[];
}

/**
 * Operator-side certificate and account management: searching what the CA issued, revoking one certificate or a whole selection
 * (an address, an account, a compromised key), and suspending accounts. Everything goes through `CertificateService.markRevoked()`,
 * so an operator's revocation is indistinguishable, to the CRL and OCSP, from any other.
 *
 * @author Jean-Philippe Steinmetz
 */
export class AdminService {
    private readonly ctx: AcmeContext;

    constructor(ctx: AcmeContext) {
        this.ctx = ctx;
    }

    /** Parses an operator's reason: an RFC 5280 code or its name. Defaults to `unspecified`. */
    public parseReason(value: unknown): number {
        if (value === undefined || value === null) {
            return 0;
        }
        const code: number | undefined = typeof value === "string" ? OPERATOR_REVOCATION_REASONS[value] : typeof value === "number" ? value : undefined;
        if (code === undefined || !Object.values(OPERATOR_REVOCATION_REASONS).includes(code)) {
            throw AcmeProblem.malformed(`reason must be one of ${Object.entries(OPERATOR_REVOCATION_REASONS).map(([name, n]) => `${name} (${n})`).join(", ")}.`);
        }
        return code;
    }

    /** Validates the operator's free-text note. */
    public parseNote(value: unknown): string | undefined {
        if (value === undefined || value === null || value === "") {
            return undefined;
        }
        // eslint-disable-next-line no-control-regex
        if (typeof value !== "string" || value.length > MAX_NOTE_LENGTH || /[\x00-\x08\x0b-\x1f\x7f]/.test(value)) {
            throw AcmeProblem.malformed(`note must be plain text of at most ${MAX_NOTE_LENGTH} characters.`);
        }
        return value.trim();
    }

    /** Validates an `X-Operator` label: who is acting, for the record. Anything odd is dropped, never trusted. */
    public parseOperator(value: unknown): string | undefined {
        const text: string = typeof value === "string" ? value.trim() : "";
        return /^[\w@.+ -]{1,64}$/.test(text) ? text : undefined;
    }

    /** The admin view of `cert`. */
    public describe(cert: AcmeCertificate): AdminCertificate {
        return {
            serial: cert.serial,
            status: cert.status,
            email: cert.email,
            type: cert.certificateType,
            issuer: cert.issuerId,
            account: cert.accountUid,
            order: cert.orderUid,
            notBefore: cert.notBefore.toISOString(),
            notAfter: cert.notAfter.toISOString(),
            issuedAt: cert.dateCreated.toISOString(),
            spkiSha256: cert.spkiSha256,
            sha256Fingerprint: cert.sha256Fingerprint,
            ...(cert.revokedAt ? { revokedAt: cert.revokedAt.toISOString() } : {}),
            ...(cert.revocationReason !== undefined ? { reason: cert.revocationReason } : {}),
            ...(cert.revokedBy ? { revokedBy: cert.revokedBy } : {}),
            ...(cert.revocationSource ? { source: cert.revocationSource } : {}),
            ...(cert.revocationNote ? { note: cert.revocationNote } : {}),
        };
    }

    /** The Mongo filter for a set of search criteria (all optional, all ANDed). */
    private filterFor(q: { email?: string; serial?: string; account?: string; spki?: string; status?: string; issuer?: string }): Record<string, unknown> {
        const filter: Record<string, unknown> = {};
        if (q.email !== undefined) {
            const mailbox = canonicalMailbox(q.email);
            if (!mailbox) {
                throw AcmeProblem.malformed("email is not a valid address.");
            }
            filter.email = mailbox.key;
        }
        if (q.serial !== undefined) {
            if (!/^[0-9a-fA-F]{1,80}$/.test(q.serial)) {
                throw AcmeProblem.malformed("serial must be hexadecimal.");
            }
            filter.serial = normalizeSerial(q.serial);
        }
        if (q.account !== undefined) {
            if (!/^[A-Za-z0-9_-]{8,128}$/.test(q.account)) {
                throw AcmeProblem.malformed("account is not an account id.");
            }
            filter.accountUid = q.account;
        }
        if (q.spki !== undefined) {
            if (!/^[0-9a-fA-F]{64}$/.test(q.spki)) {
                throw AcmeProblem.malformed("spki must be the SHA-256 (hex) of a SubjectPublicKeyInfo.");
            }
            filter.spkiSha256 = q.spki.toLowerCase();
        }
        if (q.status !== undefined) {
            if (q.status !== "valid" && q.status !== "revoked") {
                throw AcmeProblem.malformed("status must be valid or revoked.");
            }
            filter.status = q.status;
        }
        if (q.issuer !== undefined) {
            if (!/^[a-z0-9][a-z0-9_-]{0,62}$/.test(q.issuer)) {
                throw AcmeProblem.malformed("issuer is not an issuer id.");
            }
            filter.issuerId = q.issuer;
        }
        return filter;
    }

    /** One page of certificates matching the criteria, newest first. */
    public async search(
        q: { email?: string; serial?: string; account?: string; spki?: string; status?: string; issuer?: string },
        limitText: string | undefined,
        cursorText: string | undefined,
    ): Promise<{ certificates: AdminCertificate[]; next?: number }> {
        const limit: number = limitText !== undefined && /^\d{1,4}$/.test(limitText) ? Math.min(Math.max(Number(limitText), 1), MAX_LIST_LIMIT) : 50;
        const cursor: number = cursorText !== undefined && /^\d{1,9}$/.test(cursorText) ? Number(cursorText) : 0;
        const rows: AcmeCertificate[] = await this.ctx.certRepo
            .find(this.filterFor(q), { sort: { dateCreated: -1, serial: 1 }, skip: cursor, limit: limit + 1 })
            .toArray();
        return { certificates: rows.slice(0, limit).map((c) => this.describe(c)), ...(rows.length > limit ? { next: cursor + limit } : {}) };
    }

    /** A certificate by serial. */
    public async get(serial: string): Promise<AcmeCertificate> {
        const filter = this.filterFor({ serial });
        const cert: AcmeCertificate | null = await this.ctx.certRepo.findOne(filter);
        if (!cert) {
            throw AcmeProblem.malformed("No such certificate.", 404);
        }
        return cert;
    }

    /** Revokes one certificate. @throws `alreadyRevoked` (409). */
    public async revoke(serial: string, reason: number, note: string | undefined, by: string | undefined): Promise<AcmeCertificate> {
        const cert: AcmeCertificate = await this.get(serial);
        try {
            return await this.ctx.certificates.markRevoked(cert, reason, { source: "operator", note, by });
        } catch (err) {
            if (err instanceof AcmeProblem && err.errorType === "alreadyRevoked") {
                throw new AcmeProblem("alreadyRevoked", "The certificate is already revoked.", 409);
            }
            throw err;
        }
    }

    /**
     * Revokes every still-valid certificate a selector names: those of an address, of an account, ones certifying one key (the
     * response to a compromised key), or an explicit list of serials. The CRL of each affected issuer is regenerated once, at the end.
     *
     * @param dryRun Only report what would be revoked.
     * @throws `malformed` when the selector is not exactly one member, or would touch more than `MAX_BULK_REVOCATION` certificates.
     */
    public async revokeMany(
        selector: RevocationSelector,
        reason: number,
        note: string | undefined,
        by: string | undefined,
        dryRun: boolean,
    ): Promise<{ matched: number; revoked: number; alreadyRevoked: number; dryRun: boolean; serials: string[] }> {
        const given: string[] = Object.keys(selector ?? {}).filter((k) => (selector as any)[k] !== undefined);
        if (given.length !== 1 || !["email", "account", "spki", "serials"].includes(given[0])) {
            throw AcmeProblem.malformed("selector must have exactly one of email, account, spki or serials.");
        }
        let filter: Record<string, unknown>;
        if (selector.serials !== undefined) {
            if (!Array.isArray(selector.serials) || selector.serials.length === 0 || selector.serials.length > 200) {
                throw AcmeProblem.malformed("serials must be a list of 1 to 200 serial numbers.");
            }
            filter = { serial: { $in: selector.serials.map((s) => this.filterFor({ serial: String(s) }).serial) } };
        } else {
            filter = this.filterFor(selector);
        }
        const candidates: AcmeCertificate[] = await this.ctx.certRepo.find({ ...filter, status: "valid" }, { limit: MAX_BULK_REVOCATION + 1 }).toArray();
        if (candidates.length > MAX_BULK_REVOCATION) {
            throw AcmeProblem.malformed(`The selector matches more than ${MAX_BULK_REVOCATION} valid certificates; narrow it.`);
        }
        const total: number = await this.ctx.certRepo.count(filter);
        const result = { matched: candidates.length, revoked: 0, alreadyRevoked: total - candidates.length, dryRun, serials: candidates.map((c) => c.serial) };
        if (dryRun) {
            return result;
        }
        const issuers: Set<string> = new Set();
        for (const cert of candidates) {
            try {
                await this.ctx.certificates.markRevoked(cert, reason, { source: "operator", note, by, regenerateCrl: false });
                result.revoked += 1;
                issuers.add(cert.issuerId);
            } catch (err) {
                if (!(err instanceof AcmeProblem && err.errorType === "alreadyRevoked")) {
                    throw err;
                }
                result.alreadyRevoked += 1;
            }
        }
        for (const issuerId of issuers) {
            await this.ctx.certificates.regenerateCrlOf(issuerId);
        }
        this.ctx.logger.warn(`Operator${by ? ` ${by}` : ""} revoked ${result.revoked} certificate(s) selected by ${given[0]} (reason ${reason}${note ? `: ${note}` : ""}).`);
        return result;
    }

    /** An account, with what it has done. */
    public async getAccount(id: string): Promise<Record<string, unknown>> {
        const account: AcmeAccount | null = await this.ctx.accountRepo.findOne({ uid: id });
        if (!account) {
            throw AcmeProblem.malformed("No such account.", 404);
        }
        return {
            id: account.uid,
            status: account.status,
            contact: account.contact,
            thumbprint: account.thumbprint,
            created: account.dateCreated.toISOString(),
            orders: await this.ctx.orderRepo.count({ accountUid: id }),
            certificates: await this.ctx.certRepo.count({ accountUid: id }),
            validCertificates: await this.ctx.certRepo.count({ accountUid: id, status: "valid" }),
        };
    }

    /**
     * Suspends an account (status `revoked`): it can no longer do anything, and its pending orders and authorizations are cancelled. Unlike
     * a client's own deactivation an operator can undo this (`reinstate()`).
     *
     * @param revokeCertificates Also revoke every valid certificate of the account.
     */
    public async suspendAccount(
        id: string,
        note: string | undefined,
        by: string | undefined,
        revokeCertificates: { reason: number } | undefined,
    ): Promise<Record<string, unknown>> {
        const account: AcmeAccount | null = await this.ctx.accountRepo.findOne({ uid: id });
        if (!account) {
            throw AcmeProblem.malformed("No such account.", 404);
        }
        if (account.status === "deactivated") {
            throw new AcmeProblem("malformed", "The account was deactivated by its holder and cannot be suspended.", 409);
        }
        await this.ctx.accountRepo.updateOne({ uid: id }, { $set: { status: "revoked" } });
        await this.ctx.authzRepo.updateMany({ accountUid: id, status: "pending" }, { $set: { status: "revoked", "challenge.status": "invalid" } });
        await this.ctx.orderRepo.updateMany(
            { accountUid: id, status: { $in: ["pending", "ready"] } },
            { $set: { status: "invalid", error: { type: "urn:ietf:params:acme:error:unauthorized", detail: "The account was suspended.", status: 403 } } },
        );
        this.ctx.logger.warn(`Operator${by ? ` ${by}` : ""} suspended account ${id}${note ? `: ${note}` : ""}.`);
        const revoked = revokeCertificates ? await this.revokeMany({ account: id }, revokeCertificates.reason, note, by, false) : undefined;
        return { ...(await this.getAccount(id)), ...(revoked ? { revocation: revoked } : {}) };
    }

    /** Lifts an operator suspension. @throws 409 for an account that is not suspended. */
    public async reinstateAccount(id: string, by: string | undefined): Promise<Record<string, unknown>> {
        const done: AcmeAccount | null = await this.ctx.accountRepo.findOneAndUpdate({ uid: id, status: "revoked" }, { $set: { status: "valid" } });
        if (!done) {
            const exists: AcmeAccount | null = await this.ctx.accountRepo.findOne({ uid: id });
            throw exists ? new AcmeProblem("malformed", "The account is not suspended.", 409) : AcmeProblem.malformed("No such account.", 404);
        }
        this.ctx.logger.warn(`Operator${by ? ` ${by}` : ""} reinstated account ${id}.`);
        return await this.getAccount(id);
    }
}
