///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { DocDecorators, ModelDecorators, PersistenceDecorators, SimpleMongoEntity } from "@rapidrest/service-core";
import type { AcmeIdentifier } from "../lib/acme/Identifiers.js";
const { Description } = DocDecorators;
const { DataStore } = ModelDecorators;
const { Column, Entity, Index } = PersistenceDecorators;

/** The states of an order (RFC 8555 §7.1.6). This CA issues inside *finalize*, so `processing` is never observable. */
export type AcmeOrderStatus = "pending" | "ready" | "processing" | "valid" | "invalid";

/** The certificate types this CA issues (RFC 8823 §3.3). */
export type CertificateTypeName = "signing" | "encryption" | "signing-encryption";

/**
 * An ACME order (RFC 8555 §7.1.3): one request for one certificate.
 *
 * @author Jean-Philippe Steinmetz
 */
@DataStore("mongo")
@Entity()
@Index("acme_order_account", ["accountUid", "dateCreated"])
@Description("An ACME order: one request for one certificate.")
export class AcmeOrder extends SimpleMongoEntity {
    @Column()
    @Description("The account that placed the order.")
    public accountUid: string = "";

    @Column()
    @Index()
    public status: AcmeOrderStatus = "pending";

    @Column()
    @Index()
    @Description("When the order stops being usable; the cleanup job invalidates orders past it.")
    public expires: Date = new Date();

    @Column()
    public identifiers: AcmeIdentifier[] = [];

    @Column()
    @Description("The certificate profile the client asked for, if any.")
    public profile?: CertificateTypeName;

    @Column()
    @Description("The certificate type that was issued (resolved from the CSR's key usage and the profile).")
    public certificateType?: CertificateTypeName;

    @Column()
    @Description("The ids of the order's authorizations.")
    public authorizationUids: string[] = [];

    @Column()
    @Description("The issued certificate, once the order is valid.")
    public certificateUid?: string;

    @Column()
    @Description("While the order is being finalized: when that started, so a finalize that died can be recovered.")
    public processingSince?: Date;

    @Column()
    @Index()
    @Description("The certificate id (ARI form) this order replaces, if any.")
    public replaces?: string;

    @Column()
    @Description("Why the order became invalid.")
    public error?: { type: string; detail: string; status: number };

    @Column()
    public dateCreated: Date = new Date();

    @Column()
    @Description("A finalized order's CSR public key (SHA-256 of the SPKI), for audit.")
    public spkiSha256?: string;

    @Column()
    @Index({ expireAfterSeconds: 0 })
    @Description("When the record is deleted altogether (long after the order stopped mattering).")
    public purgeAt: Date = new Date();

    constructor(other?: Partial<AcmeOrder>) {
        super(other);
        if (other) {
            Object.assign(this, other);
        }
    }
}
