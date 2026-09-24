///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { DocDecorators, ModelDecorators, PersistenceDecorators, SimpleMongoEntity } from "@rapidrest/service-core";
const { Description } = DocDecorators;
const { DataStore } = ModelDecorators;
const { Column, Entity, Index } = PersistenceDecorators;

/**
 * One generated certificate revocation list. The newest per issuer is served at `/crl/<issuer>.crl`; older ones are kept
 * a while so a client that fetched one just before a refresh is not confused by a number that went backwards.
 *
 * @author Jean-Philippe Steinmetz
 */
@DataStore("mongo")
@Entity()
@Index("acme_crl_issuer_number", ["issuerId", "sequence"], { unique: true })
@Description("A generated certificate revocation list.")
export class AcmeCrl extends SimpleMongoEntity {
    @Column()
    public issuerId: string = "";

    @Column()
    @Description("The CRL number as a plain integer (fits a double for any realistic CRL count); orders CRLs of an issuer.")
    public sequence: number = 0;

    @Column()
    public thisUpdate: Date = new Date();

    @Column()
    public nextUpdate: Date = new Date();

    @Column()
    @Description("The DER CRL, base64.")
    public der: string = "";

    @Column()
    @Description("How many certificates it lists.")
    public entries: number = 0;

    @Column()
    @Index({ expireAfterSeconds: 0 })
    public purgeAt: Date = new Date();

    constructor(other?: Partial<AcmeCrl>) {
        super(other);
        if (other) {
            Object.assign(this, other);
        }
    }
}
