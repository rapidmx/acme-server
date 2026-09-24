///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////

const DAY_MS = 86_400_000;

/** One point in a certificate's life at which its account holder is reminded. */
export interface ReminderMilestone {
    /** A stable name. */
    key: "7d-before" | "3d-before" | "1d-before" | "expiry" | "1d-after" | "7d-after";
    /** When it falls, relative to the certificate's `notAfter`. */
    offsetMs: number;
}

/**
 * The reminder schedule, in order: a week, three days and a day before the certificate expires, at the moment it expires, and a
 * day and a week after (the last two only while no certificate has replaced it). Each is relative to `notAfter`, so a reminder
 * always arrives at the time of day the certificate was issued at.
 */
export const REMINDER_MILESTONES: readonly ReminderMilestone[] = [
    { key: "7d-before", offsetMs: -7 * DAY_MS },
    { key: "3d-before", offsetMs: -3 * DAY_MS },
    { key: "1d-before", offsetMs: -1 * DAY_MS },
    { key: "expiry", offsetMs: 0 },
    { key: "1d-after", offsetMs: 1 * DAY_MS },
    { key: "7d-after", offsetMs: 7 * DAY_MS },
];

/**
 * How late a reminder may still be sent. One that is later than this (the CA was down, or a relay kept refusing) is skipped instead
 * of sent: "expires in 3 days" arriving a day and a half after the fact is worse than nothing.
 */
export const REMINDER_GRACE_MS = DAY_MS;

/** How long to wait before trying again after every recipient of a reminder failed. */
export const REMINDER_RETRY_MS = 3_600_000;

/** The most certificates one reminder e-mail lists (an account with more gets several e-mails). */
export const MAX_CERTIFICATES_PER_REMINDER = 50;

/** When milestone `stage` of a certificate falls, or `undefined` when there is no such milestone (the schedule is finished). */
export function reminderDueAt(notAfter: Date, stage: number): Date | undefined {
    const milestone: ReminderMilestone | undefined = REMINDER_MILESTONES[stage];
    return milestone ? new Date(notAfter.getTime() + milestone.offsetMs) : undefined;
}

/**
 * The first milestone worth scheduling for a certificate: milestones that already lie before the certificate's own start (a
 * 3-day certificate has no "1 week before") are left out.
 *
 * @returns The stage and when it is due; `dueAt` is `undefined` when nothing is left to send.
 */
export function firstReminder(notBefore: Date, notAfter: Date): { stage: number; dueAt?: Date } {
    let stage = 0;
    while (stage < REMINDER_MILESTONES.length && (reminderDueAt(notAfter, stage) as Date).getTime() <= notBefore.getTime()) {
        stage++;
    }
    return { stage, dueAt: reminderDueAt(notAfter, stage) };
}

/** What to do with a certificate whose next milestone has come. */
export interface ReminderPlan {
    /** The stage being processed (the certificate's current `reminderStage`). */
    stage: number;
    /** The milestone to tell the account holder about; `undefined` when every due milestone is too old to be worth sending. */
    notify?: { index: number; key: ReminderMilestone["key"]; dueAt: Date };
    /** The stage to store afterwards: every milestone up to and including the one notified about (or skipped) is used up. */
    nextStage: number;
    /** When `nextStage` falls; `undefined` when the schedule is finished. */
    nextAt?: Date;
}

/**
 * Decides what a certificate at `stage` needs at `now`.
 *
 * Only the latest milestone that has come is notified: if the CA was down for two days, one reminder ("expires today") is right,
 * not a burst of the three it missed.
 *
 * @returns `undefined` when the next milestone has not come yet.
 */
export function planReminder(notAfter: Date, stage: number, now: Date): ReminderPlan | undefined {
    let latest = -1;
    for (let i = stage; i < REMINDER_MILESTONES.length; i++) {
        if ((reminderDueAt(notAfter, i) as Date).getTime() <= now.getTime()) {
            latest = i;
        } else {
            break;
        }
    }
    if (latest < 0) {
        return undefined;
    }
    const dueAt: Date = reminderDueAt(notAfter, latest) as Date;
    return {
        stage,
        ...(now.getTime() - dueAt.getTime() <= REMINDER_GRACE_MS ? { notify: { index: latest, key: REMINDER_MILESTONES[latest].key, dueAt } } : {}),
        nextStage: latest + 1,
        nextAt: reminderDueAt(notAfter, latest + 1),
    };
}
