///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { DocDecorators, ModelDecorators, PersistenceDecorators, SimpleMongoEntity } from "@rapidrest/service-core";
import type { CertificateTypeName } from "./AcmeOrder.js";
const { Description } = DocDecorators;
const { DataStore } = ModelDecorators;
const { Column, Entity, Index } = PersistenceDecorators;

/**
 * A certificate this CA issued. Kept for good – it is what the CRL, the OCSP responder, `GET /certs/:serial` and the
 * renewal rate limits are built from, and a CA has to be able to account for everything it ever signed.
 *
 * @author Jean-Philippe Steinmetz
 */
@DataStore("mongo")
@Entity()
@Index("acme_certificate_issuer_status", ["issuerId", "status"])
@Description("A certificate issued by this CA.")
export class AcmeCertificate extends SimpleMongoEntity {
    @Column({ unique: true })
    @Description("The serial number: lower-case hex of whole bytes, without leading zero bytes.")
    public serial: string = "";

    @Column()
    @Description("The id of the issuer (`issuers.json`) that signed it.")
    public issuerId: string = "";

    @Column()
    @Index()
    public orderUid: string = "";

    @Column()
    public accountUid: string = "";

    @Column()
    @Index()
    @Description("The e-mail address in the certificate, lower-cased.")
    public email: string = "";

    @Column()
    public certificateType: CertificateTypeName = "signing";

    @Column()
    @Index()
    public notBefore: Date = new Date();

    @Column()
    @Index()
    public notAfter: Date = new Date();

    @Column()
    @Description("The certificate, PEM.")
    public pem: string = "";

    @Column({ unique: true })
    @Description("SHA-256 of the DER certificate, hex.")
    public sha256Fingerprint: string = "";

    @Column()
    @Index()
    @Description("SHA-256 of the subject public key info, hex: finds keys revoked as compromised.")
    public spkiSha256: string = "";

    @Column()
    @Index()
    public status: "valid" | "revoked" = "valid";

    @Column()
    public revokedAt?: Date;

    @Column()
    @Description("The RFC 5280 CRLReason code.")
    public revocationReason?: number;

    @Column()
    @Description("Who asked for the revocation: the account that ordered it, the holder of its key, or an operator.")
    public revocationSource?: "account" | "key" | "operator";

    @Column()
    @Description("An operator's free-text reason for the revocation (operator revocations only).")
    public revocationNote?: string;

    @Column()
    @Description("The label of the operator who revoked it (X-Operator), if given.")
    public revokedBy?: string;

    @Column()
    @Description("The next expiry reminder to consider (an index into the reminder schedule); `REMINDER_MILESTONES.length` when done.")
    public reminderStage?: number;

    @Column()
    @Index()
    @Description("When the next expiry reminder is due; absent once the schedule is finished.")
    public nextReminderAt?: Date;

    @Column()
    public dateCreated: Date = new Date();

    constructor(other?: Partial<AcmeCertificate>) {
        super(other);
        if (other) {
            Object.assign(this, other);
        }
    }
}
