///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { readFileSync } from "fs";
import { ChallengeMail, ChallengeMailTransport, MemoryChallengeMailer, SmtpChallengeMailer } from "../lib/mail/index.js";
import type { SettingsSource } from "./AcmeSettings.js";

/**
 * The `ChallengeMailTransport` a deployment runs with, built from `acme.mail.smtp.*` and `acme.mail.dkim.*` on first use:
 * an SMTP relay (nodemailer) with the challenge mail DKIM-signed for the CA's own domain, as RFC 8823 requires.
 *
 * Without an SMTP relay the CA can only run in development, where the mails are kept in memory (and logged) instead of sent;
 * anywhere else the first send fails loudly, and `assertProductionConfig()` refuses to start at all.
 *
 * @author Jean-Philippe Steinmetz
 */
export class ConfiguredChallengeMailer implements ChallengeMailTransport {
    private readonly config: SettingsSource;
    private delegate?: ChallengeMailTransport;

    constructor(config: SettingsSource) {
        this.config = config;
    }

    public async send(mail: ChallengeMail): Promise<{ messageId: string }> {
        this.delegate ??= this.build();
        return await this.delegate.send(mail);
    }

    private build(): ChallengeMailTransport {
        const get = (key: string): any => this.config.get(`acme:mail:${key}`);
        const url: string | undefined = get("smtp:url") || undefined;
        const host: string | undefined = get("smtp:host") || undefined;

        const keyPath: string | undefined = get("dkim:private_key_path") || undefined;
        const inlineKey: string | undefined = get("dkim:private_key") || undefined;
        const dkim =
            get("dkim:domain") && get("dkim:selector") && (keyPath || inlineKey)
                ? { domain: String(get("dkim:domain")), selector: String(get("dkim:selector")), privateKey: inlineKey ?? readFileSync(keyPath!, "utf8") }
                : undefined;

        if (!url && !host) {
            if (["dev", "development", "test"].includes(process.env.NODE_ENV ?? "")) {
                return new MemoryChallengeMailer(dkim ? { dkim } : {});
            }
            throw new Error("No SMTP relay is configured (acme:mail:smtp:url or acme:mail:smtp:host), so verification e-mails cannot be sent.");
        }
        const user: string | undefined = get("smtp:user") || undefined;
        return new SmtpChallengeMailer({
            smtp: {
                ...(url ? { url } : {}),
                ...(host ? { host, port: Number(get("smtp:port") || 587), secure: get("smtp:secure") === true } : {}),
                ...(user ? { auth: { user, pass: String(get("smtp:pass") ?? "") } } : {}),
                ...(get("smtp:ignore_tls") === true ? { ignoreTLS: true } : {}),
            },
            ...(dkim ? { dkim } : {}),
        });
    }
}
