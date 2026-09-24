///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { DocDecorators, ModelDecorators, PersistenceDecorators, SimpleMongoEntity } from "@rapidrest/service-core";
import type { PublicJwk } from "../lib/acme/Jws.js";
const { Description } = DocDecorators;
const { DataStore } = ModelDecorators;
const { Column, Entity } = PersistenceDecorators;

/** The states of an ACME account (RFC 8555 §7.1.2). `revoked` is set by an operator, `deactivated` by the client. */
export type AcmeAccountStatus = "valid" | "deactivated" | "revoked";

/**
 * An ACME account (RFC 8555 §7.1.2): a registered public key that orders certificates. Its id (`uid`) is the last
 * segment of the account URL, which clients use as the `kid` of every later request.
 *
 * @author Jean-Philippe Steinmetz
 */
@DataStore("mongo")
@Entity()
@Description("An ACME account: a registered public key that requests certificates.")
export class AcmeAccount extends SimpleMongoEntity {
    @Column()
    @Description("valid, deactivated (by the client) or revoked (by an operator).")
    public status: AcmeAccountStatus = "valid";

    @Column({ unique: true })
    @Description("The RFC 7638 SHA-256 thumbprint of the account key: one account per key.")
    public thumbprint: string = "";

    @Column()
    @Description("The public account key, reduced to its RFC 7638 required members.")
    public jwk: PublicJwk = { kty: "EC", crv: "P-256", x: "", y: "" };

    @Column()
    @Description("The contact URLs (mailto:) of the account holder.")
    public contact: string[] = [];

    @Column()
    @Description("When the holder agreed to the terms of service.")
    public termsOfServiceAgreedAt: Date = new Date();

    @Column()
    @Description("When the account was created.")
    public dateCreated: Date = new Date();

    constructor(other?: Partial<AcmeAccount>) {
        super(other);
        if (other) {
            Object.assign(this, other);
        }
    }
}
