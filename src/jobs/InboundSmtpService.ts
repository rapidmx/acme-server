///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { readFileSync } from "fs";
import { ObjectDecorators } from "@rapidrest/core";
import { BackgroundService } from "@rapidrest/service-core";
import { InboundEnvelope, SmtpReceiver } from "../lib/mail/index.js";
import { AcmeContext } from "../services/AcmeContext.js";
const { Inject, Logger } = ObjectDecorators;

/**
 * The CA's own SMTP receiver (`acme.mail.inbound.smtp.enabled`): the applicants' reply e-mails arrive here directly, so a
 * standalone deployment needs no mail server in front of it. It accepts mail only for the challenge and response addresses
 * and hands each message to `ChallengeService.handleInbound()`.
 *
 * A background *service* rather than a job only so the framework starts and stops it with the server; its cron tick merely
 * restarts the listener if it ever went away.
 *
 * @author Jean-Philippe Steinmetz
 */
export class InboundSmtpService extends BackgroundService {
    @Inject(AcmeContext)
    private ctx?: AcmeContext;

    @Logger
    private logger: any;

    private receiver?: SmtpReceiver;
    private stopping: boolean = false;

    public get schedule(): string | undefined {
        return "* * * * *";
    }

    public async run(): Promise<void> {
        if (!this.stopping && this.ctx?.ready && this.ctx.settings.inboundSmtpEnabled && !this.receiver) {
            await this.start();
        }
    }

    public async start(): Promise<void> {
        const ctx: AcmeContext | undefined = this.ctx;
        if (!ctx?.ready || !ctx.settings.inboundSmtpEnabled || this.receiver) {
            return;
        }
        const settings = ctx.settings;
        const tls = settings.inboundSmtpTls;
        const receiver: SmtpReceiver = new SmtpReceiver(
            {
                host: settings.inboundSmtpHost,
                port: settings.inboundSmtpPort,
                hostname: new URL(settings.externalUrl).hostname,
                recipients: [settings.mailFrom, settings.mailReplyTo],
                maxSizeBytes: settings.inboundSmtpMaxSizeBytes,
                ...(tls ? { tls: { key: readFileSync(tls.key, "utf8"), cert: readFileSync(tls.cert, "utf8") } } : {}),
            },
            async (raw: Buffer, envelope: InboundEnvelope): Promise<void> => {
                const outcome = await ctx.challenges.handleInbound(raw, envelope);
                this.logger.debug(`Inbound mail via SMTP: ${outcome}.`);
            },
        );
        try {
            await receiver.start();
        } catch (err: any) {
            this.logger.error(`Could not start the inbound SMTP receiver on ${settings.inboundSmtpHost}:${settings.inboundSmtpPort}: ${err?.message ?? err}`);
            return;
        }
        this.receiver = receiver;
        this.logger.info(`Receiving reply e-mails on SMTP port ${receiver.port}.`);
    }

    public async stop(): Promise<void> {
        this.stopping = true;
        const receiver: SmtpReceiver | undefined = this.receiver;
        this.receiver = undefined;
        await receiver?.stop();
    }
}
