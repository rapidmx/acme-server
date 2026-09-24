///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { createHash } from "crypto";
import { calculateJwkThumbprint, exportJWK, FlattenedSign, generateKeyPair, JWK } from "jose";
import { x509 } from "../../src/lib/pki/runtime.js";
import { AcmeTestKey } from "./keys.js";
import { applicantDkim } from "./harness.js";
import { composeGenuineReply, type TestDkimKey } from "../lib/mail/helpers.js";
import { derOid, derSequence, derTlv } from "../../src/lib/pki/der.js";

/** What a request to the CA answered. */
export interface Reply {
    status: number;
    headers: Headers;
    /** The parsed JSON body (`undefined` when the body is not JSON). */
    json: any;
    text: string;
}

/** SHA-256 of a string, base64url. */
export function sha256B64url(text: string): string {
    return createHash("sha256").update(text).digest("base64url");
}

/**
 * A minimal ACME client written for the tests: hand-rolled JWS so that every edge case (wrong `url`, replayed nonce, a JWK
 * where a kid is required...) can be produced on purpose. The interop test uses the independent `acme-client` package instead.
 */
export class AcmeTestClient {
    public readonly baseUrl: string;
    public key!: AcmeTestKey;
    public kid?: string;
    public nonce?: string;
    public directory!: Record<string, any>;

    constructor(baseUrl: string) {
        this.baseUrl = baseUrl;
    }

    /** A client with a new ES256 account key (not registered yet). */
    public static async create(baseUrl: string, alg: "ES256" | "ES384" | "RS256" = "ES256"): Promise<AcmeTestClient> {
        const client: AcmeTestClient = new AcmeTestClient(baseUrl);
        client.key = await AcmeTestKey.generate(alg);
        const dir: Reply = await client.get("/directory");
        client.directory = dir.json;
        return client;
    }

    public async get(path: string, headers: Record<string, string> = {}): Promise<Reply> {
        return this.wrap(await fetch(path.startsWith("http") ? path : `${this.baseUrl}${path}`, { headers }));
    }

    private async wrap(response: Response): Promise<Reply> {
        const text: string = await response.text();
        let json: any;
        try {
            json = JSON.parse(text);
        } catch {
            json = undefined;
        }
        return { status: response.status, headers: response.headers, json, text };
    }

    /** A fresh nonce from new-nonce. */
    public async freshNonce(): Promise<string> {
        const reply: Reply = await this.get(this.directory.newNonce);
        return reply.headers.get("replay-nonce")!;
    }

    /**
     * Signs and POSTs a request.
     *
     * @param payload The payload; `undefined` makes it a POST-as-GET, a string is sent as is.
     * @param o `jwk`: embed the key instead of a kid; `nonce`/`url`/`key`/`contentType`: override what a correct client would send.
     */
    public async post(
        url: string,
        payload?: unknown,
        o: { jwk?: boolean; nonce?: string | null; url?: string; key?: AcmeTestKey; contentType?: string; kid?: string; alg?: string } = {},
    ): Promise<Reply> {
        const key: AcmeTestKey = o.key ?? this.key;
        const nonce: string | null | undefined = o.nonce === undefined ? (this.nonce ?? (await this.freshNonce())) : o.nonce;
        const header: Record<string, unknown> = {
            alg: o.alg ?? key.alg,
            url: o.url ?? url,
            ...(nonce ? { nonce } : {}),
            ...(o.jwk ? { jwk: key.publicJwk } : { kid: o.kid ?? this.kid }),
        };
        const body: Uint8Array =
            payload === undefined ? new Uint8Array(0) : new TextEncoder().encode(typeof payload === "string" ? payload : JSON.stringify(payload));
        const jws = await new FlattenedSign(body).setProtectedHeader(header).sign(key.privateKey);
        const response: Response = await fetch(url, {
            method: "POST",
            headers: { "content-type": o.contentType ?? "application/jose+json" },
            body: JSON.stringify(jws),
        });
        this.nonce = response.headers.get("replay-nonce") ?? undefined;
        return this.wrap(response);
    }

    /** Registers the account (agreeing to the terms) and remembers its URL as the kid. */
    public async register(contact: string[] = ["mailto:owner@example.com"]): Promise<Reply> {
        const reply: Reply = await this.post(this.directory.newAccount, { termsOfServiceAgreed: true, contact }, { jwk: true });
        if (reply.status === 201 || reply.status === 200) {
            this.kid = reply.headers.get("location")!;
        }
        return reply;
    }

    public async newOrder(email: string, extra: Record<string, unknown> = {}): Promise<Reply> {
        return await this.post(this.directory.newOrder, { identifiers: [{ type: "email", value: email }], ...extra });
    }

    /** The account key's RFC 7638 thumbprint. */
    public async thumbprint(): Promise<string> {
        return await calculateJwkThumbprint(this.key.publicJwk, "sha256");
    }

    /**
     * Builds the applicant's DKIM-signed reply to a verification e-mail the CA sent, the way the RapidMX server does.
     *
     * @param mail A message from `MemoryChallengeMailer.sent`.
     * @param token The challenge's `token` (token-part2).
     * @param o `digest` overrides the computed digest, `from` the sender, `unsigned` drops the DKIM signature.
     */
    public async replyTo(
        mail: { to: string; subject: string; messageId: string; tokenPart1: string },
        token: string,
        o: { digest?: string; from?: string; unsigned?: boolean; dkimKey?: TestDkimKey } = {},
    ): Promise<Buffer> {
        const digest: string = o.digest ?? sha256B64url(`${mail.tokenPart1}${token}.${await this.thumbprint()}`);
        return await composeGenuineReply(
            { identity: o.from ?? mail.to, replyTo: "acme-response@acme.rapidmx.test", challengeSubject: mail.subject, challengeMessageId: mail.messageId, digest },
            o.unsigned ? undefined : { key: o.dkimKey ?? applicantDkim },
        );
    }
}

/** Delivers a raw reply e-mail to the CA over the HTTP ingest route. */
export async function ingest(baseUrl: string, secret: string, raw: Buffer, headers: Record<string, string> = {}): Promise<Response> {
    return await fetch(`${baseUrl}/internal/mail/inbound`, {
        method: "POST",
        headers: { authorization: `Bearer ${secret}`, "content-type": "message/rfc822", ...headers },
        body: new Uint8Array(raw),
    });
}

/**
 * A PKCS#10 request for `email`, like the RapidMX client sends: the address as an rfc822Name SAN and, unless `keyUsage` is
 * `"none"`, a KeyUsage request that selects the certificate type (RFC 8823 §3.3).
 */
export async function makeCsr(
    email: string,
    o: { type?: "signing" | "encryption" | "signing-encryption" | "none"; key?: "ec-p256" | "ec-p384" | "rsa-2048"; keys?: CryptoKeyPair; extraSans?: string[]; smtpUtf8?: string } = {},
): Promise<{ der: Uint8Array; b64url: string; keys: CryptoKeyPair; spkiDer: Uint8Array }> {
    const kind = o.key ?? "ec-p256";
    const algorithm: any =
        kind === "rsa-2048"
            ? { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) }
            : { name: "ECDSA", namedCurve: kind === "ec-p384" ? "P-384" : "P-256" };
    const keys: CryptoKeyPair = o.keys ?? ((await crypto.subtle.generateKey(algorithm, true, ["sign", "verify"])));
    const type = o.type ?? "signing";
    const encryption: number = kind === "rsa-2048" ? x509.KeyUsageFlags.keyEncipherment : x509.KeyUsageFlags.keyAgreement;
    const usage: number | undefined =
        type === "none"
            ? undefined
            : type === "signing"
              ? x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.nonRepudiation
              : type === "encryption"
                ? encryption
                : x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.nonRepudiation | encryption;
    const csr = await x509.Pkcs10CertificateRequestGenerator.create({
        name: `CN=${email}`,
        keys,
        signingAlgorithm: kind === "rsa-2048" ? { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } : { name: "ECDSA", hash: kind === "ec-p384" ? "SHA-384" : "SHA-256" },
        extensions: [
            ...(usage !== undefined ? [new x509.KeyUsagesExtension(usage, true)] : []),
            // An internationalized local part travels as an SmtpUTF8Mailbox otherName (RFC 8398), which x509 has no type for.
            o.smtpUtf8 !== undefined
                ? new x509.Extension("2.5.29.17", false, new Uint8Array(smtpUtf8San(o.smtpUtf8)).buffer)
                : new x509.SubjectAlternativeNameExtension([email, ...(o.extraSans ?? [])].map((value) => ({ type: "email" as const, value }))),
        ],
    });
    const der: Uint8Array = new Uint8Array(csr.rawData);
    const spki: ArrayBuffer = await crypto.subtle.exportKey("spki", keys.publicKey);
    return { der, b64url: Buffer.from(der).toString("base64url"), keys, spkiDer: new Uint8Array(spki) };
}

export { exportJWK, generateKeyPair };

/** The DER of a subjectAltName holding one SmtpUTF8Mailbox otherName: [0] { 1.3.6.1.5.5.7.8.9, [0] UTF8String }. */
export function smtpUtf8San(address: string): Uint8Array {
    const value = Buffer.from(address, "utf8");
    return derSequence(derTlv(0xa0, Buffer.concat([derOid("1.3.6.1.5.5.7.8.9"), derTlv(0xa0, derTlv(0x0c, value))])));
}
