///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { AcmeProblem } from "../lib/acme/AcmeProblem.js";
import type { LimitName } from "../lib/acme/RateLimits.js";
import { parseEmailIdentifier, sameAddress } from "../lib/acme/Identifiers.js";
import { safeEqual, sha256B64url, sha256Hex } from "../lib/acme/Ids.js";
import { dkimAligned, InboundEnvelope, InboundReply, parseInboundReply } from "../lib/mail/index.js";
import { AcmeAccount } from "../models/AcmeAccount.js";
import type { AcmeAuthorization } from "../models/AcmeAuthorization.js";
import type { AcmeContext } from "./AcmeContext.js";

/** How long a finalize may take before the maintenance job treats it as dead. Issuance is one signature: seconds. */
const FINALIZE_TIMEOUT_MS = 10 * 60_000;

/** The challenge object of RFC 8555 §8 / RFC 8823 §4. */
export interface ChallengeResource {
    type: "email-reply-00";
    url: string;
    status: string;
    token: string;
    from: string;
    validated?: string;
    error?: { type: string; detail: string; status: number };
}

/** The authorization resource of RFC 8555 §7.1.4. */
export interface AuthorizationResource {
    status: string;
    expires: string;
    identifier: { type: string; value: string };
    challenges: ChallengeResource[];
}

/** What handling an inbound e-mail concluded (for logs and the ingest routes' answers). */
export type InboundOutcome =
    | "validated"
    | "recorded"
    | "invalidated"
    | "ignored-unknown"
    | "ignored-sender"
    | "ignored-dkim"
    | "ignored-state"
    | "ignored-malformed";

/**
 * The `email-reply-00` challenge (RFC 8823): sending the verification e-mail, accepting the client's "ready" POST, and
 * checking the applicant's reply.
 *
 * A challenge becomes valid when **both** halves have happened – the reply arrived with the right digest from a DKIM-aligned
 * sender, *and* the client said it was ready – whichever comes second completes it, in one atomic update, so the two paths
 * can race freely.
 *
 * @author Jean-Philippe Steinmetz
 */
export class ChallengeService {
    private readonly ctx: AcmeContext;

    constructor(ctx: AcmeContext) {
        this.ctx = ctx;
    }

    /** The wire form of the challenge of `authz`. */
    public challengeResource(authz: AcmeAuthorization): ChallengeResource {
        const c = authz.challenge;
        return {
            type: "email-reply-00",
            url: this.ctx.urls.challenge(authz.uid, c.id),
            status: c.status,
            token: c.token,
            from: c.from,
            ...(c.status === "valid" && c.completedAt ? { validated: c.completedAt.toISOString() } : {}),
            ...(c.error ? { error: c.error } : {}),
        };
    }

    /** The wire form of `authz`. */
    public resource(authz: AcmeAuthorization): AuthorizationResource {
        return {
            status: authz.status,
            expires: authz.expires.toISOString(),
            identifier: authz.identifier,
            challenges: [this.challengeResource(authz)],
        };
    }

    /** Loads an authorization owned by `accountUid`, moving it to `expired` if its time is up. */
    public async load(authzUid: string, accountUid: string): Promise<AcmeAuthorization> {
        const authz: AcmeAuthorization | null = await this.ctx.authzRepo.findOne({ uid: authzUid });
        if (!authz) {
            throw AcmeProblem.malformed("No such authorization.", 404);
        }
        if (authz.accountUid !== accountUid) {
            throw AcmeProblem.unauthorized("The authorization belongs to a different account.");
        }
        if (authz.status === "pending" && authz.expires <= this.ctx.now()) {
            const expired: AcmeAuthorization | null = await this.ctx.authzRepo.findOneAndUpdate(
                { uid: authz.uid, status: "pending" },
                { $set: { status: "expired", "challenge.status": "invalid" } },
            );
            return expired ?? authz;
        }
        return authz;
    }

    /**
     * Sends the verification e-mail for `authz` if it has not been sent yet (RFC 8823 §3: the CA mails the applicant once the
     * client has fetched the authorization). Idempotent and safe under concurrency: the send is claimed by an atomic update, so
     * however many times and from however many replicas the authorization is fetched, one mail goes out.
     *
     * The recipient-protecting limits are *checked* first – a request over a limit fails with 429 and can be retried later – then
     * the send is claimed and the tokens are spent. If anything after the claim fails (a limit lost to a concurrent request, the
     * relay refusing the mail) the claim is released and the tokens given back, so a later fetch starts over cleanly instead of
     * finding an authorization that is marked as mailed but never was.
     *
     * @param ipSubject The caller's rate-limit subject (see `ipSubject()`).
     */
    public async sendChallengeMail(authz: AcmeAuthorization, account: AcmeAccount, ipSubject: string): Promise<AcmeAuthorization> {
        if (authz.status !== "pending" || authz.challenge.status !== "pending" || authz.challenge.mailClaimedAt) {
            return authz;
        }
        const email = parseEmailIdentifier(authz.identifier.value);
        const budgets: Array<[LimitName, string]> = [
            ["challengeMailsPerAccountEmailHour", `${account.uid}|${email.normalized}`],
            ["challengeMailsPerEmailHour", email.normalized],
            ["challengeMailsPerEmailDay", email.normalized],
            ["challengeMailsPerDomainHour", email.domain],
            ["challengeMailsPerAccountHour", account.uid],
            ["challengeMailsPerIpHour", ipSubject],
        ];
        for (const [name, subject] of budgets) {
            await this.ctx.limits.check(name, subject);
        }

        const claimed: AcmeAuthorization | null = await this.ctx.authzRepo.findOneAndUpdate(
            { uid: authz.uid, status: "pending", "challenge.status": "pending", "challenge.mailClaimedAt": { $exists: false } },
            { $set: { "challenge.mailClaimedAt": this.ctx.now() } },
        );
        if (!claimed) {
            return (await this.ctx.authzRepo.findOne({ uid: authz.uid })) ?? authz;
        }

        const spent: Array<[LimitName, string]> = [];
        try {
            for (const [name, subject] of budgets) {
                await this.ctx.limits.spend(name, subject);
                spent.push([name, subject]);
            }
            const sent = await this.ctx.mailer.send({
                to: email.address,
                tokenPart1: claimed.challenge.tokenPart1,
                from: this.ctx.settings.mailFrom,
                replyTo: this.ctx.settings.mailReplyTo,
            });
            const updated: AcmeAuthorization | null = await this.ctx.authzRepo.findOneAndUpdate(
                { uid: authz.uid },
                { $set: { "challenge.mailSentAt": this.ctx.now(), "challenge.messageId": sent.messageId } },
            );
            this.ctx.logger.info(`Sent the verification e-mail for authorization ${authz.uid} to ${email.domain}.`);
            return updated ?? claimed;
        } catch (err: any) {
            await this.ctx.authzRepo.updateOne({ uid: authz.uid }, { $unset: { "challenge.mailClaimedAt": "" } });
            for (const [name, subject] of spent) {
                await this.ctx.limits.refund(name, subject).catch(() => undefined);
            }
            if (err instanceof AcmeProblem) {
                throw err;
            }
            this.ctx.logger.error(`Could not send the verification e-mail for authorization ${authz.uid}: ${err?.message ?? err}`);
            return (await this.ctx.authzRepo.findOne({ uid: authz.uid })) ?? claimed;
        }
    }

    /**
     * The client's POST to the challenge URL: it has sent (or is about to send) its reply and wants the CA to validate
     * (RFC 8555 §7.5.1). Idempotent.
     */
    public async respond(authzUid: string, challengeId: string, account: AcmeAccount): Promise<AcmeAuthorization> {
        const authz: AcmeAuthorization = await this.load(authzUid, account.uid);
        if (authz.challenge.id !== challengeId) {
            throw AcmeProblem.malformed("No such challenge.", 404);
        }
        if (authz.status === "pending" && authz.challenge.status === "pending") {
            await this.ctx.authzRepo.updateOne(
                { uid: authz.uid, status: "pending", "challenge.status": "pending" },
                { $set: { "challenge.status": "processing", "challenge.clientReadyAt": this.ctx.now() } },
            );
            await this.complete(authz.uid);
        }
        return (await this.ctx.authzRepo.findOne({ uid: authz.uid })) ?? authz;
    }

    /** Deactivates an authorization at the client's request (RFC 8555 §7.5.2). */
    public async deactivate(authzUid: string, account: AcmeAccount): Promise<AcmeAuthorization> {
        const authz: AcmeAuthorization = await this.load(authzUid, account.uid);
        if (authz.status !== "pending" && authz.status !== "valid") {
            throw AcmeProblem.malformed(`The authorization is ${authz.status} and cannot be deactivated.`);
        }
        await this.ctx.authzRepo.updateOne({ uid: authz.uid }, { $set: { status: "deactivated" } });
        return (await this.ctx.authzRepo.findOne({ uid: authz.uid })) ?? authz;
    }

    /**
     * Makes the challenge valid if it is being processed *and* the reply has been verified. One conditional update, so
     * whichever of the two events happens last does the work exactly once.
     */
    private async complete(authzUid: string): Promise<boolean> {
        const done: AcmeAuthorization | null = await this.ctx.authzRepo.findOneAndUpdate(
            { uid: authzUid, status: "pending", "challenge.status": "processing", "challenge.responseVerifiedAt": { $exists: true } },
            { $set: { status: "valid", "challenge.status": "valid", "challenge.completedAt": this.ctx.now() } },
        );
        if (!done) {
            return false;
        }
        // A validation that succeeds gives back the token its earlier failure (if any) spent.
        await this.ctx.limits.refund("failedAuthorizations", `${done.accountUid}|${parseEmailIdentifier(done.identifier.value).normalized}`).catch(() => undefined);
        this.ctx.logger.info(`Authorization ${done.uid} is valid.`);
        return true;
    }

    /** Fails the challenge of `authz` with `problem`, counting it against the failed-authorization limit. */
    private async fail(authz: AcmeAuthorization, problem: AcmeProblem): Promise<void> {
        const failed: AcmeAuthorization | null = await this.ctx.authzRepo.findOneAndUpdate(
            { uid: authz.uid, status: "pending" },
            {
                $set: {
                    status: "invalid",
                    "challenge.status": "invalid",
                    "challenge.completedAt": this.ctx.now(),
                    "challenge.error": { type: problem.type, detail: problem.message, status: problem.status },
                },
            },
        );
        if (failed) {
            await this.ctx.limits.spend("failedAuthorizations", `${failed.accountUid}|${parseEmailIdentifier(failed.identifier.value).normalized}`).catch(() => undefined);
        }
    }

    /**
     * Processes one inbound e-mail (from the SMTP receiver or the HTTP ingest route): if it is a valid reply to a
     * verification e-mail, records the proof and completes the challenge when the client is ready.
     *
     * Everything that is not a genuine reply is ignored, silently and without any answer to the sender: the CA must not become a
     * mail reflector, and the sender of a spoofed message must learn nothing.
     */
    public async handleInbound(raw: Buffer, envelope: Pick<InboundEnvelope, "mailFrom" | "remoteAddress">): Promise<InboundOutcome> {
        // Two passes. The first only reads the message (no DNS): it finds the token. DKIM verification costs a DNS query per signature
        // at names the sender chooses, so it is done only for a message that names a live challenge - never for junk.
        let reply: InboundReply;
        try {
            reply = await parseInboundReply(raw, { skipDkim: true });
        } catch (err: any) {
            this.ctx.logger.debug(`Ignoring an unparsable inbound e-mail: ${err?.message ?? err}`);
            return "ignored-malformed";
        }
        if (!reply.tokenPart1 || !reply.digest || !reply.from) {
            return "ignored-malformed";
        }

        const authz: AcmeAuthorization | null = await this.ctx.authzRepo.findOne({ tokenHash: sha256Hex(reply.tokenPart1) });
        if (!authz) {
            return "ignored-unknown";
        }
        if (authz.status !== "pending" || authz.expires <= this.ctx.now() || !["pending", "processing"].includes(authz.challenge.status)) {
            return "ignored-state";
        }
        if (!sameAddress(reply.from, authz.identifier.value)) {
            this.ctx.logger.debug(`Ignoring a reply for authorization ${authz.uid}: it is not from the address being verified.`);
            return "ignored-sender";
        }
        let verified: InboundReply;
        try {
            verified = await parseInboundReply(raw, { resolver: this.ctx.dkimResolver, sender: envelope.mailFrom, ip: envelope.remoteAddress });
        } catch {
            return "ignored-malformed";
        }
        if (!dkimAligned(verified, this.ctx.settings.dkimAlignment)) {
            this.ctx.logger.info(`Ignoring a reply for authorization ${authz.uid}: no DKIM signature aligned with the sender's domain.`);
            return "ignored-dkim";
        }

        const account: AcmeAccount | null = await this.ctx.accountRepo.findOne({ uid: authz.accountUid });
        if (!account) {
            return "ignored-state";
        }
        // RFC 8823 §3: keyAuthorization = token || "." || base64url(JWK thumbprint); the reply carries base64url(SHA-256(it)).
        const expected: string = sha256B64url(`${authz.challenge.tokenPart1}${authz.challenge.token}.${account.thumbprint}`);
        if (!safeEqual(expected, reply.digest)) {
            await this.fail(authz, new AcmeProblem("incorrectResponse", "The reply e-mail carried the wrong digest."));
            return "invalidated";
        }

        const recorded: AcmeAuthorization | null = await this.ctx.authzRepo.findOneAndUpdate(
            { uid: authz.uid, status: "pending", "challenge.responseVerifiedAt": { $exists: false } },
            { $set: { "challenge.responseVerifiedAt": this.ctx.now() } },
        );
        if (!recorded) {
            return "ignored-state";
        }
        return (await this.complete(authz.uid)) ? "validated" : "recorded";
    }

    /**
     * Marks authorizations and orders whose time is up, and recovers orders whose finalize died (the process was killed between
     * claiming the order and finishing): one whose certificate was already stored becomes valid, any other goes back to ready so
     * the client can finalize again. Called by the maintenance job.
     */
    public async expire(): Promise<{ authorizations: number; orders: number }> {
        const now: Date = this.ctx.now();
        const stuck = await this.ctx.orderRepo.find({ status: "processing", processingSince: { $lte: new Date(now.getTime() - FINALIZE_TIMEOUT_MS) } }).toArray();
        for (const order of stuck) {
            const certificate = await this.ctx.certRepo.findOne({ orderUid: order.uid });
            await this.ctx.orderRepo.updateOne(
                { uid: order.uid, status: "processing" },
                certificate ? { $set: { status: "valid", certificateUid: certificate.uid }, $unset: { processingSince: "" } } : { $set: { status: "ready" }, $unset: { processingSince: "" } },
            );
            this.ctx.logger.warn(`Recovered order ${order.uid} whose finalize did not finish: now ${certificate ? "valid" : "ready"}.`);
        }
        const authz = await this.ctx.authzRepo.updateMany(
            { status: "pending", expires: { $lte: now } },
            { $set: { status: "expired", "challenge.status": "invalid" } },
        );
        const orders = await this.ctx.orderRepo.updateMany(
            { status: { $in: ["pending", "ready"] }, expires: { $lte: now } },
            { $set: { status: "invalid", error: { type: "urn:ietf:params:acme:error:malformed", detail: "The order expired before it was completed.", status: 400 } } },
        );
        return { authorizations: authz.modifiedCount, orders: orders.modifiedCount };
    }
}
