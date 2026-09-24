///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { buildCrl, Issuer, RevokedEntry } from "../lib/pki/index.js";
import { AcmeCrl } from "../models/AcmeCrl.js";
import type { AcmeCertificate } from "../models/AcmeCertificate.js";
import { randomId } from "../lib/acme/Ids.js";
import { isDuplicateKey } from "../lib/acme/Util.js";
import type { AcmeContext } from "./AcmeContext.js";

/** How long a superseded CRL is kept: a client that fetched one just before a refresh must not see a number go backwards. */
const KEEP_OLD_CRLS_DAYS = 30;

/**
 * Certificate revocation lists. A full CRL per issuer is regenerated on a schedule and at once whenever a certificate is
 * revoked, stored in the database (so every replica serves the same one), and lists every revoked certificate until it
 * would have expired anyway.
 *
 * @author Jean-Philippe Steinmetz
 */
export class CrlService {
    private readonly ctx: AcmeContext;

    constructor(ctx: AcmeContext) {
        this.ctx = ctx;
    }

    /** Builds, signs and stores a new CRL for `issuer`. Another replica doing the same at the same moment is harmless. */
    public async regenerate(issuer: Issuer): Promise<AcmeCrl> {
        const now: Date = this.ctx.now();
        const revoked: AcmeCertificate[] = await this.ctx.certRepo.find({ issuerId: issuer.id, status: "revoked", notAfter: { $gt: now } }).toArray();
        const entries: RevokedEntry[] = revoked.map((c) => ({ serialHex: c.serial, revokedAt: c.revokedAt ?? now, reason: c.revocationReason }));

        for (let attempt = 0; attempt < 3; attempt++) {
            const last: AcmeCrl | null = await this.ctx.crlRepo.findOne({ issuerId: issuer.id }, { sort: { sequence: -1 } });
            const sequence: number = (last?.sequence ?? 0) + 1;
            const nextUpdate: Date = new Date(now.getTime() + this.ctx.settings.crlValidityHours * 3_600_000);
            const built = await buildCrl(issuer, { ["number"]: BigInt(sequence), thisUpdate: now, nextUpdate, revoked: entries });
            const record: AcmeCrl = new AcmeCrl({
                uid: randomId(),
                issuerId: issuer.id,
                sequence,
                thisUpdate: now,
                nextUpdate,
                der: Buffer.from(built.der).toString("base64"),
                entries: entries.length,
                purgeAt: new Date(nextUpdate.getTime() + KEEP_OLD_CRLS_DAYS * 86_400_000),
            });
            try {
                await this.ctx.crlRepo.save(record, { insertOnly: true });
                this.ctx.logger.info(`Generated CRL #${sequence} for ${issuer.id} (${entries.length} revoked).`);
                return record;
            } catch (err) {
                if (!isDuplicateKey(err)) {
                    throw err;
                }
            }
        }
        // Another replica won every race: its CRL is as good as ours.
        return (await this.ctx.crlRepo.findOne({ issuerId: issuer.id }, { sort: { sequence: -1 } }))!;
    }

    /** The newest CRL of `issuer`, regenerated first if there is none or it is older than the refresh interval. */
    public async current(issuer: Issuer): Promise<AcmeCrl> {
        const latest: AcmeCrl | null = await this.ctx.crlRepo.findOne({ issuerId: issuer.id }, { sort: { sequence: -1 } });
        const stale: boolean = !latest || latest.thisUpdate.getTime() + this.ctx.settings.crlRefreshHours * 3_600_000 <= this.ctx.now().getTime();
        return stale ? await this.regenerate(issuer) : latest!;
    }

    /** Refreshes the CRL of every issuer whose current one is due (the cron job's work). */
    public async refreshAll(): Promise<number> {
        let refreshed = 0;
        for (const issuer of this.ctx.registry.all()) {
            if (issuer.info().role === "root") {
                continue;
            }
            const before: AcmeCrl | null = await this.ctx.crlRepo.findOne({ issuerId: issuer.id }, { sort: { sequence: -1 } });
            const after: AcmeCrl = await this.current(issuer);
            if (!before || before.sequence !== after.sequence) {
                refreshed++;
            }
        }
        return refreshed;
    }
}
