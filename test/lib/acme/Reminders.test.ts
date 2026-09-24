///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { firstReminder, planReminder, REMINDER_GRACE_MS, REMINDER_MILESTONES, reminderDueAt } from "../../../src/lib/acme/Reminders.js";

const DAY = 86_400_000;
const notAfter = new Date("2027-01-31T12:00:00.000Z");
const at = (offsetMs: number): Date => new Date(notAfter.getTime() + offsetMs);

describe("the reminder schedule", () => {
    it("is 1 week, 3 days and 1 day before, on the day, and 1 day and 1 week after expiry", () => {
        expect(REMINDER_MILESTONES.map((m) => m.offsetMs / DAY)).toEqual([-7, -3, -1, 0, 1, 7]);
        expect(REMINDER_MILESTONES.map((m) => m.key)).toEqual(["7d-before", "3d-before", "1d-before", "expiry", "1d-after", "7d-after"]);
        expect(reminderDueAt(notAfter, 0)).toEqual(new Date("2027-01-24T12:00:00.000Z"));
        expect(reminderDueAt(notAfter, 3)).toEqual(notAfter);
        expect(reminderDueAt(notAfter, 5)).toEqual(new Date("2027-02-07T12:00:00.000Z"));
        expect(reminderDueAt(notAfter, 6)).toBeUndefined();
    });

    it("starts at the first milestone a certificate's own lifetime leaves room for", () => {
        // 90 days: all of them.
        expect(firstReminder(at(-90 * DAY), notAfter).stage).toBe(0);
        // 5 days: no "1 week before", the first is "3 days before".
        expect(firstReminder(at(-5 * DAY), notAfter)).toEqual({ stage: 1, dueAt: at(-3 * DAY) });
        // 12 hours: only the expiry itself and what follows.
        expect(firstReminder(at(-12 * 3_600_000), notAfter)).toEqual({ stage: 3, dueAt: notAfter });
        // A milestone exactly at the start does not count (nothing was issued yet to remind of).
        expect(firstReminder(at(-7 * DAY), notAfter).stage).toBe(1);
    });
});

describe("planReminder", () => {
    it("does nothing before the next milestone", () => {
        expect(planReminder(notAfter, 0, at(-7 * DAY - 1))).toBeUndefined();
        expect(planReminder(notAfter, 2, at(-1 * DAY - 1))).toBeUndefined();
        expect(planReminder(notAfter, 6, at(30 * DAY))).toBeUndefined();
    });

    it("notifies at the milestone and moves on to the next", () => {
        const plan = planReminder(notAfter, 0, at(-7 * DAY + 5 * 60_000))!;
        expect(plan.notify).toEqual({ index: 0, key: "7d-before", dueAt: at(-7 * DAY) });
        expect(plan.nextStage).toBe(1);
        expect(plan.nextAt).toEqual(at(-3 * DAY));
    });

    it("finishes the schedule after the last milestone", () => {
        const plan = planReminder(notAfter, 5, at(7 * DAY + 60_000))!;
        expect(plan.notify?.key).toBe("7d-after");
        expect(plan.nextStage).toBe(6);
        expect(plan.nextAt).toBeUndefined();
    });

    it("notifies only about the latest milestone that has come, using up the ones it missed", () => {
        const plan = planReminder(notAfter, 0, at(60_000))!;
        expect(plan.notify?.key).toBe("expiry");
        expect(plan.nextStage).toBe(4);
    });

    it("does not send a milestone that is more than a day late, but still uses it up", () => {
        const plan = planReminder(notAfter, 3, at(3 * DAY))!;
        expect(plan.notify).toBeUndefined();
        expect(plan.nextStage).toBe(5);
        expect(plan.nextAt).toEqual(at(7 * DAY));
        // Right at the limit it is still sent.
        expect(planReminder(notAfter, 3, at(DAY + REMINDER_GRACE_MS))!.notify?.key).toBe("1d-after");
        expect(planReminder(notAfter, 3, at(DAY + REMINDER_GRACE_MS + 1))!.notify).toBeUndefined();
    });
});
