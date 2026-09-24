///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import "reflect-metadata";
import { createPublicKey } from "crypto";
import * as x509 from "@peculiar/x509";
import { AcmeProblem } from "../lib/acme/AcmeProblem.js";
import type { EmailIdentifier } from "../lib/acme/Identifiers.js";
import { PublicJwk } from "../lib/acme/Jws.js";
import { randomId, sha256Hex } from "../lib/acme/Ids.js";
import { ariCertId, fromB64url, issueLeafCertificate, Issuer, IssuedCertificate, IssuerUrls, parseAriCertId, ValidatedCsr } from "../lib/pki/index.js";
import { AcmeAccount } from "../models/AcmeAccount.js";
import { AcmeCertificate } from "../models/AcmeCertificate.js";
import type { AcmeOrder, CertificateTypeName } from "../models/AcmeOrder.js";
import { isDuplicateKey, normalizeSerial } from "../lib/acme/Util.js";
import type { AcmeContext } from "./AcmeContext.js";

/** The RFC 5280 revocation reasons a client may give (RFC 8555 §7.6; Let's Encrypt's set). */
const REVOCATION_REASONS: readonly number[] = [0, 1, 3, 4, 5];
const DAY_MS = 86_400_000;

/** The RFC 9773 §4.2 renewal information of a certificate. */
export interface RenewalInfo {
    suggestedWindow: { start: string; end: string };
    explanationURL?: string;
}

/**
 * Issued certificates: signing them, handing them out, revoking them, and telling clients when to renew.
 *
 * @author Jean-Philippe Steinmetz
 */
export class CertificateService {
    private readonly ctx: AcmeContext;

    constructor(ctx: AcmeContext) {
        this.ctx = ctx;
    }

    /** The URLs written into a certificate of `issuer`: where its CRL, its own certificate and its OCSP responder are. */
    public urlsFor(issuer: Issuer): IssuerUrls {
        return {
            crl: this.ctx.urls.forPath(`/crl/${issuer.id}.crl`),
            caIssuers: this.ctx.urls.forPath(`/ca/${issuer.id}.crt`),
            ocsp: this.ctx.urls.forPath("/ocsp"),
        };
    }

    /**
     * Signs a certificate for a validated CSR and records it.
     *
     * The validity is `validity_days` for the type, capped at the issuing CA's own expiry (a certificate must never outlive its
     * issuer), and starts a little in the past (`backdate_minutes`) so a client whose clock runs slow still accepts it.
     */
    public async issue(o: { account: AcmeAccount; order: AcmeOrder; email: EmailIdentifier; csr: ValidatedCsr; type: CertificateTypeName }): Promise<AcmeCertificate> {
        const issuer: Issuer = this.ctx.registry.active();
        const now: Date = this.ctx.now();
        const notBefore: Date = new Date(now.getTime() - this.ctx.settings.backdateMinutes * 60_000);
        let notAfter: Date = new Date(now.getTime() + this.ctx.settings.validityDays(o.type) * DAY_MS);
        const issuerEnd: Date = issuer.certificate.notAfter;
        if (issuerEnd.getTime() - now.getTime() < DAY_MS) {
            this.ctx.logger.error(`The active issuer '${issuer.id}' expires ${issuerEnd.toISOString()}: not issuing. Add a new issuer to the manifest.`);
            throw AcmeProblem.internal();
        }
        if (notAfter > issuerEnd) {
            notAfter = issuerEnd;
        }

        for (let attempt = 0; attempt < 3; attempt++) {
            const issued: IssuedCertificate = await issueLeafCertificate(issuer, this.urlsFor(issuer), {
                spki: o.csr.spki,
                email: o.email.address,
                type: o.type,
                notBefore,
                notAfter,
            });
            const record: AcmeCertificate = new AcmeCertificate({
                uid: randomId(),
                serial: normalizeSerial(issued.serialHex),
                issuerId: issuer.id,
                orderUid: o.order.uid,
                accountUid: o.account.uid,
                email: o.email.normalized,
                certificateType: o.type,
                notBefore: issued.notBefore,
                notAfter: issued.notAfter,
                pem: issued.pem,
                sha256Fingerprint: issued.sha256Fingerprint,
                spkiSha256: o.csr.spkiSha256,
                status: "valid",
                dateCreated: now,
            });
            try {
                await this.ctx.certRepo.save(record, { insertOnly: true });
                this.ctx.logger.info(`Issued ${o.type} certificate ${record.serial} for an address at ${o.email.domain} (issuer ${issuer.id}, account ${o.account.uid}).`);
                return record;
            } catch (err) {
                // A serial collision is a 2^-159 event; a repeat of it means something is broken, so give up after a few tries.
                if (!isDuplicateKey(err)) {
                    throw err;
                }
            }
        }
        throw AcmeProblem.internal();
    }

    /** The certificate chain to send a client: the certificate, then the CAs up to (not including) the root. */
    public chainPem(cert: AcmeCertificate): string {
        const issuer: Issuer | undefined = this.ctx.registry.get(cert.issuerId);
        if (!issuer) {
            throw AcmeProblem.internal();
        }
        const intermediates: x509.X509Certificate[] = issuer.chain.slice(0, -1);
        return [cert.pem.trim(), issuer.certificate.toString("pem").trim(), ...intermediates.map((c) => c.toString("pem").trim())].join("\n") + "\n";
    }

    /** Loads a certificate for download by its account, from its URL id. */
    public async loadForAccount(uid: string, account: AcmeAccount): Promise<AcmeCertificate> {
        const cert: AcmeCertificate | null = await this.ctx.certRepo.findOne({ uid });
        if (!cert) {
            throw AcmeProblem.malformed("No such certificate.", 404);
        }
        if (cert.accountUid !== account.uid) {
            throw AcmeProblem.unauthorized("The certificate belongs to a different account.");
        }
        return cert;
    }

    /** The certificate with the given serial (any issuer), for the public look-up endpoint and OCSP. */
    public async findBySerial(serialHex: string, issuerId?: string): Promise<AcmeCertificate | null> {
        return await this.ctx.certRepo.findOne({ serial: normalizeSerial(serialHex), ...(issuerId ? { issuerId } : {}) });
    }

    /** The certificate an ARI certificate id names, or `undefined` if none of ours does. */
    public async findByAri(id: { authorityKeyId: Uint8Array; serialHex: string }): Promise<AcmeCertificate | undefined> {
        const issuer: Issuer | undefined = this.ctx.registry.all().find((i) => Buffer.compare(Buffer.from(i.keyId), Buffer.from(id.authorityKeyId)) === 0);
        if (!issuer) {
            return undefined;
        }
        return (await this.findBySerial(id.serialHex, issuer.id)) ?? undefined;
    }

    /** The ARI certificate id (RFC 9773 §4.1) of `cert`. */
    public ariId(cert: AcmeCertificate): string {
        return ariCertId(new x509.X509Certificate(cert.pem));
    }

    /**
     * ARI (RFC 9773): when a client should renew. The suggested window opens two thirds of the way through the
     * certificate's life (60 days into a 90-day certificate) and lasts a twelfth of it; a revoked certificate's window opens
     * at once so clients replace it immediately.
     *
     * @throws `badCertificateIdentifier` (404) for an id that is not one of ours.
     */
    public async renewalInfo(certId: string): Promise<RenewalInfo> {
        const parsed = parseAriCertId(certId);
        const cert: AcmeCertificate | undefined = parsed ? await this.findByAri(parsed) : undefined;
        if (!cert) {
            throw new AcmeProblem("badCertificateIdentifier", "No such certificate.");
        }
        const now: number = this.ctx.now().getTime();
        if (cert.status === "revoked") {
            return {
                suggestedWindow: { start: new Date(now - 3_600_000).toISOString(), end: new Date(now + 3_600_000).toISOString() },
                explanationURL: `${this.ctx.settings.externalUrl}/certs/${cert.serial}`,
            };
        }
        const life: number = cert.notAfter.getTime() - cert.notBefore.getTime();
        const start: number = cert.notBefore.getTime() + (life * 2) / 3;
        return { suggestedWindow: { start: new Date(start).toISOString(), end: new Date(start + life / 12).toISOString() } };
    }

    /**
     * revoke-cert (RFC 8555 §7.6). Two ways to be authorized: the account that ordered the certificate, or whoever holds the
     * certificate's private key (the JWS is then signed with it and embeds it as `jwk`) – the latter is how a compromised key
     * gets revoked by someone who has no account.
     *
     * @throws `malformed` (404) for a certificate this CA did not issue, `unauthorized`, `badRevocationReason`, `alreadyRevoked`.
     */
    public async revoke(auth: { account?: AcmeAccount; jwk: PublicJwk }, payload: Record<string, any>): Promise<void> {
        if (typeof payload.certificate !== "string" || !/^[A-Za-z0-9_-]+$/.test(payload.certificate)) {
            throw AcmeProblem.malformed("certificate must be the base64url DER of the certificate to revoke.");
        }
        const reason: number = payload.reason === undefined ? 0 : payload.reason;
        if (!Number.isInteger(reason) || !REVOCATION_REASONS.includes(reason)) {
            throw new AcmeProblem("badRevocationReason", `reason must be one of ${REVOCATION_REASONS.join(", ")}.`);
        }
        const der: Uint8Array = fromB64url(payload.certificate);
        const cert: AcmeCertificate | null = await this.ctx.certRepo.findOne({ sha256Fingerprint: sha256Hex(der) });
        if (!cert) {
            throw AcmeProblem.malformed("This CA did not issue that certificate.", 404);
        }
        const byAccount: boolean = auth.account !== undefined && auth.account.uid === cert.accountUid;
        const byKey: boolean = !auth.account && this.jwkSpkiHash(auth.jwk) === cert.spkiSha256;
        if (!byAccount && !byKey) {
            throw AcmeProblem.unauthorized("Only the account that ordered the certificate, or the holder of its private key, can revoke it.");
        }
        if (cert.status === "revoked") {
            throw new AcmeProblem("alreadyRevoked", "The certificate is already revoked.");
        }
        await this.markRevoked(cert, reason, { source: byAccount ? "account" : "key" });
    }

    /**
     * Records a revocation and republishes the CRL. The one place a certificate becomes revoked, whoever asked (its account, the
     * holder of its key, or an operator), so the CRL, OCSP and the compromised-key blocklist can never disagree about it.
     *
     * The transition is one conditional update, so of two concurrent revocations exactly one wins and the other gets
     * `alreadyRevoked`.
     *
     * @param o `source` who asked; `note`/`by` the operator's free-text reason and label (operator revocations only);
     * `regenerateCrl: false` lets a bulk caller regenerate each affected CRL once at the end.
     * @throws `alreadyRevoked`.
     */
    public async markRevoked(
        cert: AcmeCertificate,
        reason: number,
        o: { source: "account" | "key" | "operator"; note?: string; by?: string; regenerateCrl?: boolean },
    ): Promise<AcmeCertificate> {
        const revoked: AcmeCertificate | null = await this.ctx.certRepo.findOneAndUpdate(
            { uid: cert.uid, status: "valid" },
            {
                $set: {
                    status: "revoked",
                    revokedAt: this.ctx.now(),
                    revocationReason: reason,
                    revocationSource: o.source,
                    ...(o.note ? { revocationNote: o.note } : {}),
                    ...(o.by ? { revokedBy: o.by } : {}),
                },
            },
        );
        if (!revoked) {
            throw new AcmeProblem("alreadyRevoked", "The certificate is already revoked.");
        }
        this.ctx.logger.info(`Revoked certificate ${cert.serial} (reason ${reason}, by ${o.source}${o.by ? ` ${o.by}` : ""}${o.note ? `: ${o.note}` : ""}).`);
        if (o.regenerateCrl !== false) {
            await this.regenerateCrlOf(cert.issuerId);
        }
        return revoked;
    }

    /** Regenerates the CRL of `issuerId`, logging (never throwing) a failure: the revocation itself has already been recorded. */
    public async regenerateCrlOf(issuerId: string): Promise<void> {
        const issuer: Issuer | undefined = this.ctx.registry.get(issuerId);
        if (issuer) {
            await this.ctx.crls.regenerate(issuer).catch((err: any) => this.ctx.logger.error(`Could not regenerate the CRL after a revocation: ${err?.message ?? err}`));
        }
    }

    /** SHA-256 (hex) of the SubjectPublicKeyInfo of a JWK: comparable with `AcmeCertificate.spkiSha256`. */
    private jwkSpkiHash(jwk: PublicJwk): string {
        return sha256Hex(createPublicKey({ key: jwk as any, format: "jwk" }).export({ type: "spki", format: "der" }));
    }
}
