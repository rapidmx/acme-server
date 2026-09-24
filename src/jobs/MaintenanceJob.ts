///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { ObjectDecorators } from "@rapidrest/core";
import { BackgroundService } from "@rapidrest/service-core";
import { AcmeContext } from "../services/AcmeContext.js";
const { Inject, Logger } = ObjectDecorators;

/**
 * The CA's housekeeping, every ten minutes: authorizations and orders whose time is up are marked expired, the expiry reminders
 * that have come due are e-mailed to the account contacts, and every issuer's
 * CRL is regenerated when it is older than `acme.ca.crl_refresh_hours` (a CRL that goes stale would make relying parties
 * treat every certificate as unverifiable).
 *
 * Safe to run on every replica at once: each step is a conditional update, and a lost race on a CRL just means another
 * replica's CRL is served.
 *
 * @author Jean-Philippe Steinmetz
 */
export class MaintenanceJob extends BackgroundService {
    @Inject(AcmeContext)
    private ctx?: AcmeContext;

    @Logger
    private logger: any;

    public get schedule(): string | undefined {
        return "*/10 * * * *";
    }

    public async run(): Promise<void> {
        if (!this.ctx?.ready) {
            return;
        }
        try {
            const expired = await this.ctx.challenges.expire();
            if (expired.authorizations > 0 || expired.orders > 0) {
                this.logger.info(`Expired ${expired.authorizations} authorization(s) and ${expired.orders} order(s).`);
            }
        } catch (err) {
            this.logger.error("Expiring old authorizations and orders failed.");
            this.logger.debug(err);
        }
        try {
            const sent = await this.ctx.reminders.run();
            if (sent.certificates > 0) {
                this.logger.info(`Sent ${sent.mails} expiry reminder e-mail(s) about ${sent.certificates} certificate(s).`);
            }
        } catch (err) {
            this.logger.error("Sending the expiry reminders failed.");
            this.logger.debug(err);
        }
        try {
            await this.ctx.crls.refreshAll();
        } catch (err) {
            this.logger.error("Refreshing the CRLs failed.");
            this.logger.debug(err);
        }
    }

    public async start(): Promise<void> {
        // Nothing to prepare: `run()` does its work from the shared context.
    }

    public async stop(): Promise<void> {
        // Nothing to release.
    }
}
