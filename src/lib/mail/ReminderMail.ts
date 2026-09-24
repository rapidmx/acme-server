///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import type { ReminderMilestone } from "../acme/Reminders.js";
import type { NoticeMail } from "./ChallengeMailer.js";

/** One certificate a reminder is about. */
export interface ReminderItem {
    /** The address in the certificate. */
    email: string;
    /** `signing`, `encryption` or `signing-encryption`. */
    type: string;
    /** The serial number, hex. */
    serial: string;
    notAfter: Date;
    /** Which milestone this reminder is. */
    milestone: ReminderMilestone["key"];
}

/** What the milestone says about the certificate, as it reads inside a sentence. */
const WHEN: Readonly<Record<ReminderMilestone["key"], string>> = {
    "7d-before": "expires in 7 days",
    "3d-before": "expires in 3 days",
    "1d-before": "expires in 1 day",
    expiry: "expires today",
    "1d-after": "expired 1 day ago and has not been renewed",
    "7d-after": "expired 7 days ago and has not been renewed",
};

/** `2026-10-01 12:34 UTC`. */
export function utcMinute(date: Date): string {
    return date.toISOString().replace("T", " ").replace(/:\d\d(?:\.\d+)?Z$/, " UTC");
}

/** A short name for a certificate type, for people. */
function typeName(type: string): string {
    return type === "signing-encryption" ? "signing and encryption" : type;
}

/**
 * Composes the reminder for one account contact: one message for everything of the account that has reached a milestone.
 *
 * The text names only what the account holder's own client ordered (addresses, types, serial numbers, dates) and says why the
 * message arrived and how to stop it. The subject of a single-certificate reminder carries the address and how long is left, so a
 * mail client's list view is enough to see what is wrong.
 *
 * @param o `items` must not be empty. `directoryUrl` is the ACME directory a client renews against, `accountUrl` the account the
 * contact belongs to, `from` the CA's own address (the one challenge e-mails come from).
 */
export function composeReminder(o: { to: string; from: string; items: ReminderItem[]; directoryUrl: string; accountUrl: string }): NoticeMail {
    if (o.items.length === 0) {
        throw new Error("A reminder needs at least one certificate.");
    }
    const first: ReminderItem = o.items[0];
    const subject: string =
        o.items.length === 1
            ? `Your ${typeName(first.type)} certificate for ${first.email} ${WHEN[first.milestone]}`
            : `${o.items.length} of your S/MIME certificates need renewing`;
    const lines: string[] = [
        "This is an automated message from a certificate authority.",
        "",
        o.items.length === 1 ? "An S/MIME certificate issued to your ACME account needs attention:" : "S/MIME certificates issued to your ACME account need attention:",
        "",
        ...o.items.flatMap((item) => [
            `  ${item.email} (${typeName(item.type)})`,
            `    ${item.milestone === "expiry" || item.milestone.endsWith("before") ? "Expires" : "Expired"}: ${utcMinute(item.notAfter)} - ${WHEN[item.milestone].replace(/^expires /, "").replace(/^expired /, "")}`,
            `    Serial: ${item.serial}`,
            "",
        ]),
        "To renew, order a new certificate for the same address with your ACME client. Most clients do this on their own well before",
        "expiry; if this message comes as a surprise, check that yours is running and can reach this service:",
        `  ${o.directoryUrl}`,
        "",
        "Reminders for a certificate stop once a newer one for the same address and type has been issued, or it has been revoked.",
        "If you no longer need it, no action is needed.",
        "",
        `You get this message because your address is listed as a contact of the ACME account ${o.accountUrl}.`,
        "To stop receiving it, remove the address from the account's contacts (an account update, RFC 8555 section 7.3.2).",
        "",
    ];
    return { to: o.to, from: o.from, subject, text: lines.join("\r\n") };
}
