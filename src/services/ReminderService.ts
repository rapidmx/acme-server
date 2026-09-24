///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { AcmeProblem } from "../lib/acme/AcmeProblem.js";
import {
    firstReminder,
    MAX_CERTIFICATES_PER_REMINDER,
    planReminder,
    REMINDER_GRACE_MS,
    REMINDER_MILESTONES,
    REMINDER_RETRY_MS,
    ReminderPlan,
} from "../lib/acme/Reminders.js";
import { composeReminder, isDeliverableMailbox, ReminderItem } from "../lib/mail/index.js";
import { AcmeAccount } from "../models/AcmeAccount.js";
import { AcmeCertificate } from "../models/AcmeCertificate.js";
import type { AcmeContext } from "./AcmeContext.js";

/** A certificate whose reminder this run claimed, with what was claimed. */
interface Claimed {
    cert: AcmeCertificate;
    plan: ReminderPlan;
    item: ReminderItem;
}

/** What one run did. */
export interface ReminderRun {
    /** Certificates a reminder was sent for (at least one contact received it). */
    certificates: number;
    /** E-mails sent. */
    mails: number;
}

/**
 * Expiry reminders: tells the holder of an ACME account (its `mailto:` contacts) that a certificate is about to expire, has, and
 * has not been renewed.
 *
 * The schedule (`lib/acme/Reminders.ts`) is 1 week, 3 days and 1 day before, at the moment of expiry, and 1 day and 1 week after,
 * all relative to `notAfter`. Every certificate carries its next milestone (`reminderStage`) and when it falls
 * (`nextReminderAt`, indexed), so a run only ever touches what is due. A milestone is *claimed* with a conditional update before
 * anything is sent, which makes it safe to run on every replica at once: of two replicas exactly one wins a certificate. If every
 * recipient then fails, the claim is released and retried an hour later (for as long as the reminder is still worth sending).
 *
 * Nothing is sent - and the milestone is used up - when the account is no longer valid, has no usable contact, or a newer valid
 * certificate for the same address and type exists (it was renewed: there is nothing to remind anybody of). One e-mail per contact
 * lists everything of that account that is due, so an account with many certificates is not flooded, and each contact address
 * has a daily budget (`reminderMailsPerContactDay`) because anybody can name any address as a contact.
 *
 * @author Jean-Philippe Steinmetz
 */
export class ReminderService {
    private readonly ctx: AcmeContext;
    private backfilled: boolean = false;

    constructor(ctx: AcmeContext) {
        this.ctx = ctx;
    }

    /** Sends every reminder that has come due. Called by the maintenance job. */
    public async run(): Promise<ReminderRun> {
        const result: ReminderRun = { certificates: 0, mails: 0 };
        if (!this.ctx.settings.remindersEnabled) {
            return result;
        }
        if (!this.backfilled) {
            await this.backfill();
            this.backfilled = true;
        }
        const now: Date = this.ctx.now();
        const due: AcmeCertificate[] = await this.ctx.certRepo
            .find({ status: "valid", nextReminderAt: { $lte: now } }, { limit: this.ctx.settings.reminderBatchSize })
            .toArray();

        const byAccount: Map<string, Claimed[]> = new Map();
        for (const cert of due) {
            const claimed: Claimed | undefined = await this.claim(cert, now);
            if (claimed) {
                byAccount.set(cert.accountUid, [...(byAccount.get(cert.accountUid) ?? []), claimed]);
            }
        }
        for (const [accountUid, claims] of byAccount) {
            try {
                const sent = await this.notify(accountUid, claims, now);
                result.certificates += sent.certificates;
                result.mails += sent.mails;
            } catch (err: any) {
                this.ctx.logger.error(`Sending the reminders of account ${accountUid} failed: ${err?.message ?? err}`);
                await this.release(claims, now);
            }
        }
        return result;
    }

    /**
     * Gives a certificate issued before reminders existed (or while they were switched off) its schedule. Once per process: a
     * certificate issued afterwards is scheduled when it is issued, and the updates are conditional, so replicas may all do it.
     */
    private async backfill(): Promise<void> {
        const since: Date = new Date(this.ctx.now().getTime() - (REMINDER_MILESTONES[REMINDER_MILESTONES.length - 1].offsetMs + REMINDER_GRACE_MS));
        for (let batch = 0; batch < 200; batch++) {
            const rows: AcmeCertificate[] = await this.ctx.certRepo.find({ status: "valid", reminderStage: { $exists: false }, notAfter: { $gt: since } }, { limit: 500 }).toArray();
            for (const cert of rows) {
                const first = firstReminder(cert.notBefore, cert.notAfter);
                await this.ctx.certRepo.updateOne({ uid: cert.uid, reminderStage: { $exists: false } }, { $set: { reminderStage: first.stage, ...(first.dueAt ? { nextReminderAt: first.dueAt } : {}) } });
            }
            if (rows.length < 500) {
                return;
            }
        }
    }

    /**
     * Takes the milestone that has come for `cert`: one conditional update moves the certificate on to its next milestone, so
     * only one replica gets it.
     *
     * @returns What to tell the holder, or `undefined` when there is nothing to send (lost the race, the milestone is stale,
     * or the certificate was renewed).
     */
    private async claim(cert: AcmeCertificate, now: Date): Promise<Claimed | undefined> {
        const stage: number = cert.reminderStage ?? 0;
        const plan: ReminderPlan | undefined = planReminder(cert.notAfter, stage, now);
        if (!plan) {
            return undefined;
        }
        const won: AcmeCertificate | null = await this.ctx.certRepo.findOneAndUpdate(
            { uid: cert.uid, status: "valid", reminderStage: stage },
            plan.nextAt ? { $set: { reminderStage: plan.nextStage, nextReminderAt: plan.nextAt } } : { $set: { reminderStage: plan.nextStage }, $unset: { nextReminderAt: "" } },
        );
        if (!won) {
            return undefined;
        }
        if (!plan.notify) {
            this.ctx.logger.warn(`Skipped a stale expiry reminder for certificate ${cert.serial} (more than a day late).`);
            return undefined;
        }
        if (await this.renewed(cert, now)) {
            return undefined;
        }
        return { cert, plan, item: { email: cert.email, type: cert.certificateType, serial: cert.serial, notAfter: cert.notAfter, milestone: plan.notify.key } };
    }

    /** Whether a newer valid certificate for the same address and type outlives `cert`: it has been renewed. */
    private async renewed(cert: AcmeCertificate, now: Date): Promise<boolean> {
        const later: Date = cert.notAfter.getTime() > now.getTime() ? cert.notAfter : now;
        const successor: AcmeCertificate | null = await this.ctx.certRepo.findOne({ email: cert.email, certificateType: cert.certificateType, status: "valid", notAfter: { $gt: later } });
        return successor !== null;
    }

    /** E-mails everything `claims` (all of one account) lists to each usable contact of the account. */
    private async notify(accountUid: string, claims: Claimed[], now: Date): Promise<ReminderRun> {
        const account: AcmeAccount | null = await this.ctx.accountRepo.findOne({ uid: accountUid });
        if (!account || account.status !== "valid") {
            return { certificates: 0, mails: 0 };
        }
        const contacts: string[] = [...new Set(account.contact.map((c) => c.replace(/^mailto:/i, "")).filter((c) => isDeliverableMailbox(c)).map((c) => c.toLowerCase()))];
        if (contacts.length === 0) {
            this.ctx.logger.info(`Account ${accountUid} has no usable contact address: no expiry reminder was sent for ${claims.length} certificate(s).`);
            return { certificates: 0, mails: 0 };
        }
        const result: ReminderRun = { certificates: 0, mails: 0 };
        for (let i = 0; i < claims.length; i += MAX_CERTIFICATES_PER_REMINDER) {
            const chunk: Claimed[] = claims.slice(i, i + MAX_CERTIFICATES_PER_REMINDER);
            let delivered = 0;
            let failed = 0;
            for (const to of contacts) {
                try {
                    await this.ctx.limits.spend("reminderMailsPerContactDay", to);
                } catch (err) {
                    if (err instanceof AcmeProblem && err.errorType === "rateLimited") {
                        this.ctx.logger.warn(`Not sending an expiry reminder to a contact of account ${accountUid}: its daily budget is used up.`);
                        continue;
                    }
                    throw err;
                }
                try {
                    await this.ctx.mailer.sendNotice(
                        composeReminder({
                            to,
                            from: this.ctx.settings.mailFrom,
                            items: chunk.map((c) => c.item),
                            directoryUrl: this.ctx.urls.directory(),
                            accountUrl: this.ctx.urls.account(accountUid),
                        }),
                    );
                    delivered++;
                } catch (err: any) {
                    failed++;
                    await this.ctx.limits.refund("reminderMailsPerContactDay", to).catch(() => undefined);
                    this.ctx.logger.warn(`Could not send an expiry reminder for account ${accountUid}: ${err?.message ?? err}`);
                }
            }
            if (delivered > 0) {
                result.certificates += chunk.length;
                result.mails += delivered;
            } else if (failed > 0) {
                // Nobody got it because the relay failed (not because of a budget): try again in a while.
                await this.release(chunk, now);
            }
        }
        return result;
    }

    /** Puts claimed certificates back at the milestone they were claimed at, to be tried again after `REMINDER_RETRY_MS`. */
    private async release(claims: Claimed[], now: Date): Promise<void> {
        for (const { cert, plan } of claims) {
            await this.ctx.certRepo
                .updateOne({ uid: cert.uid, reminderStage: plan.nextStage }, { $set: { reminderStage: plan.stage, nextReminderAt: new Date(now.getTime() + REMINDER_RETRY_MS) } })
                .catch((err: any) => this.ctx.logger.error(`Could not release the reminder of certificate ${cert.serial}: ${err?.message ?? err}`));
        }
    }
}
