///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { DocDecorators, ModelDecorators, PersistenceDecorators, SimpleMongoEntity } from "@rapidrest/service-core";
import type { AcmeIdentifier } from "../lib/acme/Identifiers.js";
const { Description } = DocDecorators;
const { DataStore } = ModelDecorators;
const { Column, Entity, Index } = PersistenceDecorators;

/** The states of an authorization (RFC 8555 §7.1.4). */
export type AcmeAuthorizationStatus = "pending" | "valid" | "invalid" | "deactivated" | "expired" | "revoked";

/** The states of a challenge (RFC 8555 §7.1.6). */
export type AcmeChallengeStatus = "pending" | "processing" | "valid" | "invalid";

/**
 * The single `email-reply-00` challenge (RFC 8823) of an authorization, with the server-side state that is never sent
 * to a client (`tokenPart1`, the proof and the mail bookkeeping).
 */
export interface EmailReplyChallenge {
    /** The opaque id in the challenge URL. */
    id: string;
    type: "email-reply-00";
    status: AcmeChallengeStatus;
    /** token-part2: 256 random bits, sent to the client in the challenge object (`token`). */
    token: string;
    /** token-part1: 256 random bits, sent only in the Subject of the verification e-mail. */
    tokenPart1: string;
    /** The address the verification e-mail comes from (`from` in the challenge object). */
    from: string;
    /** Set (atomically) by whoever sends the verification e-mail, so it is sent exactly once. */
    mailClaimedAt?: Date;
    /** When the mail was handed to the relay. */
    mailSentAt?: Date;
    /** The Message-ID of the verification e-mail. */
    messageId?: string;
    /** When the applicant's reply arrived with a correct digest from the right, DKIM-aligned sender. */
    responseVerifiedAt?: Date;
    /** When the client POSTed to the challenge URL to say it is ready. */
    clientReadyAt?: Date;
    /** When the challenge became valid or invalid. */
    completedAt?: Date;
    error?: { type: string; detail: string; status: number };
}

/**
 * An ACME authorization (RFC 8555 §7.1.4): the proof, for one order, that the applicant controls one mailbox. Never
 * reused between orders – every certificate re-proves control of the mailbox.
 *
 * @author Jean-Philippe Steinmetz
 */
@DataStore("mongo")
@Entity()
@Index("acme_authz_order", ["orderUid"])
@Index("acme_authz_account_status", ["accountUid", "status"])
@Description("An ACME authorization: proof of control of one mailbox for one order.")
export class AcmeAuthorization extends SimpleMongoEntity {
    @Column()
    public accountUid: string = "";

    @Column()
    public orderUid: string = "";

    @Column()
    public identifier: AcmeIdentifier = { type: "email", value: "" };

    @Column()
    @Index()
    public status: AcmeAuthorizationStatus = "pending";

    @Column()
    @Index()
    public expires: Date = new Date();

    @Column()
    public challenge: EmailReplyChallenge = {
        id: "",
        type: "email-reply-00",
        status: "pending",
        token: "",
        tokenPart1: "",
        from: "",
    };

    @Column({ unique: true })
    @Description("SHA-256 (hex) of token-part1: how an inbound reply finds its authorization without an id in the mail.")
    public tokenHash: string = "";

    @Column()
    public dateCreated: Date = new Date();

    @Column()
    @Index({ expireAfterSeconds: 0 })
    public purgeAt: Date = new Date();

    constructor(other?: Partial<AcmeAuthorization>) {
        super(other);
        if (other) {
            Object.assign(this, other);
        }
    }
}
