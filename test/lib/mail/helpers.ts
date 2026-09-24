///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { generateKeyPairSync } from "node:crypto";
import nodemailer from "nodemailer";
import { dkimSign } from "mailauth/lib/dkim/sign.js";
import type { DnsTxtResolver } from "../../../src/lib/mail/index.js";

/** A DKIM key pair with the DNS TXT record that publishes its public half. */
export interface TestDkimKey {
    domain: string;
    selector: string;
    privateKey: string;
    /** The TXT record value, `v=DKIM1; k=rsa; p=...`. */
    txt: string;
}

/** Generates an RSA-2048 DKIM key for `<selector>._domainkey.<domain>`. */
export function makeDkimKey(domain: string, selector: string = "s1"): TestDkimKey {
    const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const spki: string = publicKey.export({ type: "spki", format: "der" }).toString("base64");
    return {
        domain,
        selector,
        privateKey: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
        txt: `v=DKIM1; k=rsa; p=${spki}`,
    };
}

/**
 * A resolver that answers TXT queries for the given keys and fails like a missing DNS name for everything else.
 * `queries` records what was asked, so a test can assert that nothing else was looked up.
 */
export function makeResolver(...keys: TestDkimKey[]): DnsTxtResolver & { queries: string[] } {
    const queries: string[] = [];
    const resolver = async (name: string, rr: string): Promise<unknown> => {
        queries.push(`${rr} ${name}`);
        for (const key of keys) {
            if (rr === "TXT" && name.toLowerCase() === `${key.selector}._domainkey.${key.domain}`) {
                return [[key.txt]];
            }
        }
        throw Object.assign(new Error(`queryTxt ENOTFOUND ${name}`), { code: "ENOTFOUND" });
    };
    return Object.assign(resolver, { queries });
}

/** Composes a message with nodemailer's stream transport (CRLF), optionally DKIM-signed, the way a real client would. */
export async function composeMessage(
    message: Record<string, unknown>,
    dkim?: { key: TestDkimKey | TestDkimKey[]; headerFieldNames?: string }
): Promise<Buffer> {
    const keys: TestDkimKey[] = dkim ? ([] as TestDkimKey[]).concat(dkim.key) : [];
    const transport = nodemailer.createTransport({
        streamTransport: true,
        buffer: true,
        newline: "windows",
        ...(dkim
            ? {
                  dkim: {
                      keys: keys.map((k) => ({ domainName: k.domain, keySelector: k.selector, privateKey: k.privateKey })),
                      ...(dkim.headerFieldNames ? { headerFieldNames: dkim.headerFieldNames } : {}),
                  },
              }
            : {}),
    } as any);
    const info: any = await transport.sendMail(message);
    return info.message as Buffer;
}

/** A well-formed 43 character base64url digest for tests. */
export const SAMPLE_DIGEST: string = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG";

/**
 * Builds a reply exactly like `Rfc8823AcmeSigningCertificateEnrollment.sendChallengeReply()` in `@rapidmx/restapi`
 * does: From is the identity, To is the challenge's Reply-To, `Subject: Re: <challenge subject>`, `In-Reply-To` and
 * `References` carry the challenge's Message-ID, and the text body carries the digest between the markers.
 */
export async function composeGenuineReply(
    o: {
        identity: string;
        replyTo: string;
        challengeSubject: string;
        challengeMessageId: string;
        digest?: string;
        text?: string;
    },
    dkim?: { key: TestDkimKey; headerFieldNames?: string }
): Promise<Buffer> {
    return composeMessage(
        {
            from: o.identity,
            to: o.replyTo,
            subject: `Re: ${o.challengeSubject}`,
            inReplyTo: o.challengeMessageId,
            references: o.challengeMessageId,
            text:
                o.text ??
                `-----BEGIN ACME RESPONSE-----\n${o.digest ?? SAMPLE_DIGEST}\n-----END ACME RESPONSE-----\n`,
        },
        dkim
    );
}

/**
 * Signs `raw` with mailauth, which (unlike nodemailer) can produce the unusual signatures a verifier must cope with:
 * `l=` body limits, SHA-1, already expired signatures, custom header lists.
 */
export async function signWithMailauth(
    raw: Buffer | string,
    key: TestDkimKey,
    o: {
        algorithm?: string;
        maxBodyLength?: number;
        expires?: Date;
        signTime?: Date;
        headerList?: string[];
    } = {}
): Promise<Buffer> {
    const { maxBodyLength, ...shared } = o;
    const { signatures, errors } = await dkimSign(raw, {
        canonicalization: "relaxed/relaxed",
        ...shared,
        signatureData: [
            {
                signingDomain: key.domain,
                selector: key.selector,
                privateKey: key.privateKey,
                ...(maxBodyLength !== undefined ? { maxBodyLength } : {}),
            },
        ],
    } as any);
    if (errors.length > 0) {
        throw (errors[0] as any).err ?? errors[0];
    }
    return Buffer.concat([Buffer.from(signatures), Buffer.isBuffer(raw) ? raw : Buffer.from(raw)]);
}
