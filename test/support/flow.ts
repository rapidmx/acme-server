///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { AcmeTestClient, ingest, makeCsr, Reply } from "./client.js";
import { CaHarness } from "./harness.js";

/** A finished issuance. */
export interface Issued {
    order: Reply;
    orderUrl: string;
    certificateUrl: string;
    pem: string;
    csr: Awaited<ReturnType<typeof makeCsr>>;
}

/** The newest verification e-mail the CA sent to `email`. */
export function lastMail(ca: CaHarness, email: string) {
    const sent = ca.mailer.sent.filter((m) => m.to.toLowerCase() === email.toLowerCase());
    return sent[sent.length - 1];
}

/**
 * Drives a new order through `email-reply-00`: fetches the authorization (which makes the CA send its e-mail), answers with the
 * applicant's DKIM-signed reply over the HTTP ingest route, and tells the CA the client is ready.
 *
 * @returns The order (refetched) once every authorization is valid.
 */
export async function validateOrder(ca: CaHarness, client: AcmeTestClient, order: Reply, email: string): Promise<Reply> {
    const authzUrl: string = order.json.authorizations[0];
    const authz: Reply = await client.post(authzUrl);
    if (authz.status !== 200) {
        throw new Error(`fetching the authorization answered ${authz.status}: ${authz.text}`);
    }
    const mail = lastMail(ca, email);
    const challenge = authz.json.challenges[0];
    const reply: Buffer = await client.replyTo(mail, challenge.token);
    const ingested = await ingest(ca.baseUrl, ca.inboundSecret, reply);
    if (ingested.status !== 202) {
        throw new Error(`ingesting the reply answered ${ingested.status}`);
    }
    const ready: Reply = await client.post(challenge.url, {});
    if (ready.status !== 200) {
        throw new Error(`answering the challenge answered ${ready.status}: ${ready.text}`);
    }
    return await client.post(order.headers.get("location")!);
}

/** A whole issuance: order, validate, finalize with a fresh CSR, download. */
export async function issueCertificate(
    ca: CaHarness,
    client: AcmeTestClient,
    email: string,
    o: { csr?: Parameters<typeof makeCsr>[1]; orderExtra?: Record<string, unknown> } = {},
): Promise<Issued> {
    const created: Reply = await client.newOrder(email, o.orderExtra ?? {});
    if (created.status !== 201) {
        throw new Error(`new-order answered ${created.status}: ${created.text}`);
    }
    const orderUrl: string = created.headers.get("location")!;
    const ready: Reply = await validateOrder(ca, client, created, email);
    if (ready.json.status !== "ready") {
        throw new Error(`the order is ${ready.json.status}, not ready`);
    }
    const csr = await makeCsr(email, o.csr);
    const finalized: Reply = await client.post(ready.json.finalize, { csr: csr.b64url });
    if (finalized.status !== 200 || finalized.json.status !== "valid") {
        throw new Error(`finalize answered ${finalized.status}: ${finalized.text}`);
    }
    const certificateUrl: string = finalized.json.certificate;
    const cert: Reply = await client.post(certificateUrl);
    return { order: finalized, orderUrl, certificateUrl, pem: cert.text, csr };
}

let counter = 0;

/** A unique mailbox at the applicants' domain, so tests never share rate-limit buckets or authorizations. */
export function uniqueEmail(prefix: string = "user"): string {
    counter += 1;
    return `${prefix}${counter}-${Math.random().toString(36).slice(2, 8)}@example.com`;
}
