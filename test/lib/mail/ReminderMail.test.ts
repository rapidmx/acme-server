///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { simpleParser } from "mailparser";
import { composeNoticeMessage, composeReminder, isDeliverableMailbox, MemoryChallengeMailer, ReminderItem } from "../../../src/lib/mail/index.js";
import { makeDkimKey } from "./helpers.js";

const notAfter = new Date("2027-01-31T12:34:56.000Z");
const item = (over: Partial<ReminderItem> = {}): ReminderItem => ({ email: "alice@example.com", type: "signing", serial: "0a1b2c", notAfter, milestone: "3d-before", ...over });
const base = { to: "owner@example.org", from: "acme-challenge@acme.rapidmx.io", directoryUrl: "https://acme.rapidmx.io/directory", accountUrl: "https://acme.rapidmx.io/acme/acct/abc" };

describe("composeReminder", () => {
    it("says what is wrong in the subject of a single-certificate reminder", () => {
        const subjects: Record<ReminderItem["milestone"], string> = {
            "7d-before": "Your signing certificate for alice@example.com expires in 7 days",
            "3d-before": "Your signing certificate for alice@example.com expires in 3 days",
            "1d-before": "Your signing certificate for alice@example.com expires in 1 day",
            expiry: "Your signing certificate for alice@example.com expires today",
            "1d-after": "Your signing certificate for alice@example.com expired 1 day ago and has not been renewed",
            "7d-after": "Your signing certificate for alice@example.com expired 7 days ago and has not been renewed",
        };
        for (const [milestone, subject] of Object.entries(subjects)) {
            expect(composeReminder({ ...base, items: [item({ milestone: milestone as ReminderItem["milestone"] })] }).subject).toBe(subject);
        }
    });

    it("lists the certificates, the way to renew and the reason and way out of the reminders", () => {
        const mail = composeReminder({ ...base, items: [item({ type: "signing-encryption" })] });
        expect(mail.to).toBe("owner@example.org");
        expect(mail.from).toBe("acme-challenge@acme.rapidmx.io");
        expect(mail.text).toContain("alice@example.com (signing and encryption)");
        expect(mail.text).toContain("Expires: 2027-01-31 12:34 UTC");
        expect(mail.text).toContain("Serial: 0a1b2c");
        expect(mail.text).toContain("https://acme.rapidmx.io/directory");
        expect(mail.text).toContain("https://acme.rapidmx.io/acme/acct/abc");
        expect(mail.text).toContain("remove the address from the account's contacts");
    });

    it("words an expired certificate in the past tense", () => {
        const mail = composeReminder({ ...base, items: [item({ milestone: "1d-after" })] });
        expect(mail.text).toContain("Expired: 2027-01-31 12:34 UTC - 1 day ago and has not been renewed");
    });

    it("lists several certificates in one message", () => {
        const mail = composeReminder({ ...base, items: [item(), item({ email: "bob@example.com", serial: "ff", milestone: "1d-before" })] });
        expect(mail.subject).toBe("2 of your S/MIME certificates need renewing");
        expect(mail.text).toContain("alice@example.com");
        expect(mail.text).toContain("bob@example.com");
        expect(mail.text).toContain("Serial: ff");
    });

    it("refuses an empty list", () => {
        expect(() => composeReminder({ ...base, items: [] })).toThrow();
    });
});

describe("composeNoticeMessage", () => {
    const notice = { to: "owner@example.org", from: "acme-challenge@acme.rapidmx.io", subject: "Hello", text: "Body line one.\nBody line two." };

    it("builds a text/plain message marked as automatic, with no Reply-To", async () => {
        const { raw, messageId } = await composeNoticeMessage(notice);
        const parsed = await simpleParser(raw);
        expect(parsed.subject).toBe("Hello");
        expect(parsed.from?.value[0].address).toBe("acme-challenge@acme.rapidmx.io");
        expect((parsed.to as any).value[0].address).toBe("owner@example.org");
        expect(parsed.headers.get("auto-submitted")).toBe("auto-generated");
        expect(parsed.replyTo).toBeUndefined();
        expect(parsed.text).toContain("Body line two.");
        expect(parsed.messageId).toBe(messageId);
        expect(messageId.endsWith("@acme.rapidmx.io>")).toBe(true);
    });

    it("DKIM-signs it for the From domain when a key is configured", async () => {
        const key = makeDkimKey("acme.rapidmx.io");
        const { raw } = await composeNoticeMessage(notice, { dkim: { domain: "acme.rapidmx.io", selector: key.selector, privateKey: key.privateKey } });
        expect(raw.toString("utf8")).toMatch(/^DKIM-Signature: [\s\S]*?d=acme\.rapidmx\.io/im);
    });

    it("refuses anything that could inject a header or a command", async () => {
        await expect(composeNoticeMessage({ ...notice, subject: "a\r\nBcc: x@example.com" })).rejects.toThrow(/subject/i);
        await expect(composeNoticeMessage({ ...notice, subject: "" })).rejects.toThrow(/subject/i);
        await expect(composeNoticeMessage({ ...notice, subject: "x".repeat(201) })).rejects.toThrow(/subject/i);
        await expect(composeNoticeMessage({ ...notice, to: "a@example.com\r\nRCPT TO:<b@example.com>" })).rejects.toThrow(/to/i);
        await expect(composeNoticeMessage({ ...notice, to: "a b@example.com" })).rejects.toThrow();
        await expect(composeNoticeMessage({ ...notice, from: "Mallory <m@example.com>" })).rejects.toThrow();
        await expect(composeNoticeMessage({ ...notice, text: "" })).rejects.toThrow(/text/i);
        await expect(composeNoticeMessage({ ...notice, text: "a" + String.fromCharCode(0) + "b" })).rejects.toThrow(/text/i);
    });

    it("refuses a DKIM domain that is not the From domain or a parent of it", async () => {
        const key = makeDkimKey("other.example");
        await expect(composeNoticeMessage(notice, { dkim: { domain: "other.example", selector: key.selector, privateKey: key.privateKey } })).rejects.toThrow(/DKIM/);
    });
});

describe("MemoryChallengeMailer notices", () => {
    it("records what it would have sent, and can simulate a relay that is down", async () => {
        const mailer = new MemoryChallengeMailer();
        await mailer.sendNotice({ to: "a@example.org", from: "acme-challenge@acme.rapidmx.io", subject: "s", text: "t" });
        expect(mailer.notices).toHaveLength(1);
        mailer.failNoticesTo.add("b@example.org");
        await expect(mailer.sendNotice({ to: "B@example.org", from: "acme-challenge@acme.rapidmx.io", subject: "s", text: "t" })).rejects.toThrow(/relay/);
        expect(mailer.notices).toHaveLength(1);
    });
});

describe("isDeliverableMailbox", () => {
    it("accepts a plain (or internationalized) mailbox and nothing else", () => {
        expect(isDeliverableMailbox("owner@example.org")).toBe(true);
        expect(isDeliverableMailbox("用户@example.org")).toBe(true);
        for (const bad of ["", "owner", "owner@localhost", "a@b@example.org", "o wner@example.org", "<o@example.org>", 5, undefined]) {
            expect(isDeliverableMailbox(bad)).toBe(false);
        }
    });
});
