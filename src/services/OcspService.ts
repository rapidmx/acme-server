///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { CertStatusLookup, OcspResponder } from "../lib/pki/index.js";
import type { AcmeCertificate } from "../models/AcmeCertificate.js";
import type { AcmeContext } from "./AcmeContext.js";

/**
 * The OCSP responder (RFC 6960, lightweight profile RFC 5019): answers `good`, `revoked` (with the time and reason) or
 * `unknown` for a serial this CA never issued – never `good` for an unissued serial, as the Baseline Requirements insist.
 *
 * @author Jean-Philippe Steinmetz
 */
export class OcspService {
    private readonly responder: OcspResponder;

    constructor(ctx: AcmeContext) {
        const lookup: CertStatusLookup = async (issuer, serialHex) => {
            const cert: AcmeCertificate | null = await ctx.certificates.findBySerial(serialHex, issuer.id);
            if (!cert) {
                return { status: "unknown" };
            }
            return cert.status === "revoked"
                ? { status: "revoked", revokedAt: cert.revokedAt, reason: cert.revocationReason }
                : { status: "good" };
        };
        this.responder = new OcspResponder(ctx.registry, lookup, { validityHours: ctx.settings.ocspValidityHours });
    }

    /** Answers a DER OCSP request with a DER OCSP response (always a well-formed response, even for a bad request). */
    public async respond(requestDer: Uint8Array): Promise<Uint8Array> {
        return await this.responder.respond(requestDer);
    }
}
