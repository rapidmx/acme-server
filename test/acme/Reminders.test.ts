///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Certificate expiry reminders: the schedule (1 week, 3 days and 1 day before, the day of, 1 day and 1 week after), who gets them
// (the account's contacts), and when they are not sent (renewed, revoked, no contact, budget used up, relay down).
import { AcmeRateLimiter } from "../../src/lib/acme/RateLimits.js";
import { REMINDER_MILESTONES } from "../../src/lib/acme/Reminders.js";
import { MaintenanceJob } from "../../src/jobs/MaintenanceJob.js";
import { AcmeCertificate } from "../../src/models/AcmeCertificate.js";
import { AcmeSettings } from "../../src/services/AcmeSettings.js";
import { ReminderService } from "../../src/services/ReminderService.js";
import { AcmeTestClient } from "../support/client.js";
import { issueCertificate, uniqueEmail } from "../support/flow.js";
import { CaHarness, startCa } from "../support/harness.js";

const DAY = 86_400_000;

describe("expiry reminders", () => {
    let ca: CaHarness;
    let counter = 0;

    beforeAll(async () => {
        ca = await startCa();
    }, 180_000);

    afterAll(async () => {
        await ca?.stop();
    });

    /** A fresh account whose contacts are `contacts`, and a certificate issued to it. */
    const holder = async (contacts: string[] = [uniqueContact()]): Promise<{ client: AcmeTestClient; contact: string; email: string; cert: AcmeCertificate }> => {
        const client = await AcmeTestClient.create(ca.baseUrl);
        await client.register(contacts);
        const email = uniqueEmail("rem");
        await issueCertificate(ca, client, email);
        const cert = (await ca.ctx.certRepo.findOne({ email: email.toLowerCase() }))!;
        return { client, contact: (contacts[0] ?? "").replace(/^mailto:/, ""), email, cert };
    };
    const uniqueContact = (): string => `mailto:holder${++counter}-${Math.random().toString(36).slice(2, 8)}@example.org`;

    /** Runs the reminders as if it were `when`. */
    const runAt = async (when: Date, service: ReminderService = ca.ctx.reminders) => {
        const real = ca.ctx.now;
        ca.ctx.now = () => when;
        try {
            return await service.run();
        } finally {
            ca.ctx.now = real;
        }
    };
    /** A minute past a milestone of `cert`. */
    const at = (cert: AcmeCertificate, offsetMs: number): Date => new Date(cert.notAfter.getTime() + offsetMs + 60_000);
    const mailsTo = (address: string) => ca.mailer.notices.filter((m) => m.to.toLowerCase() === address.toLowerCase());
    const reload = async (cert: AcmeCertificate) => (await ca.ctx.certRepo.findOne({ uid: cert.uid }))!;

    it("schedules the first reminder when a certificate is issued", async () => {
        const { cert } = await holder();
        expect(cert.reminderStage).toBe(0);
        expect(cert.nextReminderAt?.getTime()).toBe(cert.notAfter.getTime() - 7 * DAY);
    });

    it("sends 1 week, 3 days and 1 day before, the day of, and 1 day and 1 week after - each once, to the account contact", async () => {
        const { cert, contact, email } = await holder();
        await runAt(at(cert, -8 * DAY));
        expect(mailsTo(contact)).toHaveLength(0);

        const expected: Array<[number, string]> = [
            [-7 * DAY, "expires in 7 days"],
            [-3 * DAY, "expires in 3 days"],
            [-1 * DAY, "expires in 1 day"],
            [0, "expires today"],
            [1 * DAY, "expired 1 day ago and has not been renewed"],
            [7 * DAY, "expired 7 days ago and has not been renewed"],
        ];
        expect(expected).toHaveLength(REMINDER_MILESTONES.length);
        let received = 0;
        for (const [offset, phrase] of expected) {
            await runAt(at(cert, offset));
            received++;
            const mails = mailsTo(contact);
            expect(mails).toHaveLength(received);
            const mail = mails[mails.length - 1];
            expect(mail.subject).toBe(`Your signing certificate for ${email.toLowerCase()} ${phrase}`);
            expect(mail.from).toBe("acme-challenge@acme.rapidmx.test");
            expect(mail.text).toContain(cert.serial);
            expect(mail.raw).toContain("Auto-Submitted: auto-generated");
            // Nothing more until the next milestone.
            await runAt(at(cert, offset + 60_000));
            expect(mailsTo(contact)).toHaveLength(received);
        }
        const done = await reload(cert);
        expect(done.reminderStage).toBe(REMINDER_MILESTONES.length);
        expect(done.nextReminderAt).toBeUndefined();
        await runAt(at(cert, 30 * DAY));
        expect(mailsTo(contact)).toHaveLength(6);
    });

    it("sends only the latest reminder that has come after a gap, and none that is a day late", async () => {
        const a = await holder();
        await runAt(at(a.cert, 0));
        expect(mailsTo(a.contact).map((m) => m.subject)).toEqual([`Your signing certificate for ${a.email.toLowerCase()} expires today`]);

        const b = await holder();
        // Three days past expiry: "1 day after" was due two days ago, "1 week after" is not due yet.
        await runAt(at(b.cert, 3 * DAY));
        expect(mailsTo(b.contact)).toHaveLength(0);
        const state = await reload(b.cert);
        expect(state.reminderStage).toBe(5);
        expect(state.nextReminderAt?.getTime()).toBe(b.cert.notAfter.getTime() + 7 * DAY);
        await runAt(at(b.cert, 7 * DAY));
        expect(mailsTo(b.contact)).toHaveLength(1);
    });

    it("does not remind about a certificate that has been renewed - and starts again if the renewal is revoked", async () => {
        const { client, contact, email, cert } = await holder();
        await issueCertificate(ca, client, email);
        const renewal = (await ca.ctx.certRepo.findOne({ email: email.toLowerCase(), uid: { $ne: cert.uid } }))!;
        // The renewal outlives the original by a month, so its own reminders are far off.
        const later = new Date(renewal.notAfter.getTime() + 30 * DAY);
        await ca.ctx.certRepo.updateOne({ uid: renewal.uid }, { $set: { notAfter: later, nextReminderAt: new Date(later.getTime() - 7 * DAY) } });

        await runAt(at(cert, -7 * DAY));
        await runAt(at(cert, 0));
        await runAt(at(cert, 1 * DAY));
        expect(mailsTo(contact)).toHaveLength(0);

        await ca.ctx.certificates.markRevoked(renewal, 0, { source: "operator" });
        await runAt(at(cert, 7 * DAY));
        expect(mailsTo(contact).map((m) => m.subject)).toEqual([`Your signing certificate for ${email.toLowerCase()} expired 7 days ago and has not been renewed`]);
    });

    it("does not remind about a revoked certificate", async () => {
        const { contact, cert } = await holder();
        await ca.ctx.certificates.markRevoked(cert, 0, { source: "operator" });
        await runAt(at(cert, -7 * DAY));
        await runAt(at(cert, 0));
        expect(mailsTo(contact)).toHaveLength(0);
    });

    it("sends nothing, and uses the milestone up, for an account with no contact or one that is no longer valid", async () => {
        const noContact = await holder([]);
        await runAt(at(noContact.cert, -7 * DAY));
        expect(ca.mailer.notices.filter((m) => m.text.includes(noContact.cert.serial))).toHaveLength(0);
        expect((await reload(noContact.cert)).reminderStage).toBe(1);

        const closed = await holder();
        const accountUid = closed.client.kid!.split("/").pop()!;
        await ca.ctx.accountRepo.updateOne({ uid: accountUid }, { $set: { status: "deactivated" } });
        await runAt(at(closed.cert, -7 * DAY));
        expect(mailsTo(closed.contact)).toHaveLength(0);
        expect((await reload(closed.cert)).reminderStage).toBe(1);
    });

    it("skips a contact that cannot be mailed, and sends to each of the others once", async () => {
        const first = `holder-a-${Math.random().toString(36).slice(2, 8)}@example.org`;
        const second = `holder-b-${Math.random().toString(36).slice(2, 8)}@example.org`;
        const { cert } = await holder([`mailto:${first}`, `mailto:${first.toUpperCase()}`, "mailto:nobody@localhost", `mailto:${second}`]);
        await runAt(at(cert, -7 * DAY));
        expect(mailsTo(first)).toHaveLength(1);
        expect(mailsTo(second)).toHaveLength(1);
        expect(mailsTo("nobody@localhost")).toHaveLength(0);
    });

    it("lists everything of an account that is due in one e-mail", async () => {
        const one = await holder();
        const secondEmail = uniqueEmail("rem");
        await issueCertificate(ca, one.client, secondEmail);
        const two = (await ca.ctx.certRepo.findOne({ email: secondEmail.toLowerCase() }))!;
        await runAt(at(two, -7 * DAY));
        const mails = mailsTo(one.contact);
        expect(mails).toHaveLength(1);
        expect(mails[0].subject).toBe("2 of your S/MIME certificates need renewing");
        expect(mails[0].text).toContain(one.email.toLowerCase());
        expect(mails[0].text).toContain(secondEmail.toLowerCase());
    });

    it("tries again an hour later when the relay refuses, and stops caring once the reminder is a day late", async () => {
        const { cert, contact } = await holder();
        ca.mailer.failNoticesTo.add(contact.toLowerCase());
        const when = at(cert, -7 * DAY);
        await runAt(when);
        expect(mailsTo(contact)).toHaveLength(0);
        let state = await reload(cert);
        expect(state.reminderStage).toBe(0);
        expect(state.nextReminderAt?.getTime()).toBe(when.getTime() + 3_600_000);

        ca.mailer.failNoticesTo.delete(contact.toLowerCase());
        await runAt(new Date(when.getTime() + 30 * 60_000));
        expect(mailsTo(contact)).toHaveLength(0);
        await runAt(new Date(when.getTime() + 61 * 60_000));
        expect(mailsTo(contact)).toHaveLength(1);
        state = await reload(cert);
        expect(state.reminderStage).toBe(1);

        // A relay that stays down past the grace period: the reminder is dropped, not retried for ever.
        const late = await holder();
        ca.mailer.failNoticesTo.add(late.contact.toLowerCase());
        const first = at(late.cert, -7 * DAY);
        await runAt(first);
        await runAt(new Date(first.getTime() + 25 * 3_600_000));
        ca.mailer.failNoticesTo.delete(late.contact.toLowerCase());
        expect(mailsTo(late.contact)).toHaveLength(0);
        expect((await reload(late.cert)).reminderStage).toBe(1);
    });

    it("gives every contact address a daily budget, because anybody can name any address as a contact", async () => {
        const { cert, contact } = await holder();
        const real = ca.ctx.limits;
        ca.ctx.limits = new AcmeRateLimiter(ca.ctx.store, {
            enabled: true,
            overrides: [{ limit: "reminderMailsPerContactDay", subject: contact, count: 1, burst: 1 }],
        });
        try {
            await runAt(at(cert, -7 * DAY));
            await runAt(at(cert, -3 * DAY));
            expect(mailsTo(contact)).toHaveLength(1);
            // The milestone that found the budget empty is used up, not retried.
            expect((await reload(cert)).reminderStage).toBe(2);
        } finally {
            ca.ctx.limits = real;
        }
    });

    it("lets only one of several replicas claim a milestone", async () => {
        const { cert, contact } = await holder();
        const replicas = [new ReminderService(ca.ctx), new ReminderService(ca.ctx), new ReminderService(ca.ctx)];
        const real = ca.ctx.now;
        const when = at(cert, -7 * DAY);
        ca.ctx.now = () => when;
        try {
            await Promise.all(replicas.map((r) => r.run()));
        } finally {
            ca.ctx.now = real;
        }
        expect(mailsTo(contact)).toHaveLength(1);
    });

    it("gives a certificate issued before reminders existed its schedule", async () => {
        const { cert, contact } = await holder();
        await ca.ctx.certRepo.updateOne({ uid: cert.uid }, { $unset: { reminderStage: "", nextReminderAt: "" } });
        expect((await reload(cert)).reminderStage).toBeUndefined();
        await runAt(at(cert, -7 * DAY), new ReminderService(ca.ctx));
        expect(mailsTo(contact)).toHaveLength(1);
        expect((await reload(cert)).reminderStage).toBe(1);
    });

    it("can be switched off", () => {
        const source = (values: Record<string, unknown>) => ({ get: (key: string) => values[key] });
        expect(new AcmeSettings(source({})).remindersEnabled).toBe(true);
        expect(new AcmeSettings(source({ "acme:reminders:enabled": false })).remindersEnabled).toBe(false);
        expect(new AcmeSettings(source({ "acme:reminders:enabled": "false" })).remindersEnabled).toBe(false);
        expect(new AcmeSettings(source({})).reminderBatchSize).toBe(500);
    });

    it("is run by the maintenance job", async () => {
        const { cert, contact } = await holder();
        const job = ca.objectFactory.getInstance<MaintenanceJob>(MaintenanceJob) as MaintenanceJob;
        const real = ca.ctx.now;
        ca.ctx.now = () => at(cert, -7 * DAY);
        try {
            await job.run();
        } finally {
            ca.ctx.now = real;
        }
        expect(mailsTo(contact)).toHaveLength(1);
    });
});
