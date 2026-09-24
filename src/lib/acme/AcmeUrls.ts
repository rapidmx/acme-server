///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////

/**
 * Builds every absolute URL this CA hands out, and parses the resource ids back out of the ones a client sends (the
 * `kid` of a JWS, a certificate URL, ...).
 *
 * All URLs come from the configured `acme.external_url`, never from the `Host` header of a request: behind a reverse
 * proxy the two differ, and a client-controlled `Host` must not be able to put an attacker's origin into a directory,
 * an order or an issued certificate.
 *
 * @author Jean-Philippe Steinmetz
 */
export class AcmeUrls {
    /** The base URL, without a trailing slash. */
    public readonly base: string;

    constructor(externalUrl: string) {
        this.base = externalUrl.replace(/\/+$/, "");
    }

    /** The URL a request arrived at, for comparison with a JWS `url` header. */
    public forPath(path: string): string {
        return `${this.base}${path}`;
    }

    public directory(): string {
        return `${this.base}/directory`;
    }

    public newNonce(): string {
        return `${this.base}/acme/new-nonce`;
    }

    public newAccount(): string {
        return `${this.base}/acme/new-acct`;
    }

    public newOrder(): string {
        return `${this.base}/acme/new-order`;
    }

    public revokeCert(): string {
        return `${this.base}/acme/revoke-cert`;
    }

    public keyChange(): string {
        return `${this.base}/acme/key-change`;
    }

    public renewalInfoBase(): string {
        return `${this.base}/acme/renewal-info`;
    }

    public renewalInfo(certId: string): string {
        return `${this.renewalInfoBase()}/${certId}`;
    }

    public account(id: string): string {
        return `${this.base}/acme/acct/${id}`;
    }

    public accountOrders(id: string): string {
        return `${this.account(id)}/orders`;
    }

    public order(id: string): string {
        return `${this.base}/acme/order/${id}`;
    }

    public finalize(id: string): string {
        return `${this.order(id)}/finalize`;
    }

    public authorization(id: string): string {
        return `${this.base}/acme/authz/${id}`;
    }

    public challenge(authorizationId: string, challengeId: string): string {
        return `${this.base}/acme/chall/${authorizationId}/${challengeId}`;
    }

    public certificate(id: string): string {
        return `${this.base}/acme/cert/${id}`;
    }

    public terms(): string {
        return `${this.base}/terms`;
    }

    /** The account id in an account URL (a JWS `kid`), or `undefined` if `url` is not one of this CA's account URLs. */
    public accountIdFrom(url: string): string | undefined {
        return this.idFrom(url, `${this.base}/acme/acct/`);
    }

    /** The certificate id in a certificate URL, or `undefined` if `url` is not one of this CA's. */
    public certificateIdFrom(url: string): string | undefined {
        return this.idFrom(url, `${this.base}/acme/cert/`);
    }

    private idFrom(url: string, prefix: string): string | undefined {
        if (typeof url !== "string" || !url.startsWith(prefix)) {
            return undefined;
        }
        const id: string = url.slice(prefix.length);
        return /^[A-Za-z0-9_-]{8,128}$/.test(id) ? id : undefined;
    }
}
