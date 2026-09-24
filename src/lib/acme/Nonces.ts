///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { randomBytes } from "crypto";
import { AcmeStore } from "./AcmeStore.js";

const NONCE_SHAPE = /^[A-Za-z0-9_-]{16,64}$/;

/**
 * Issues and consumes the anti-replay nonces of RFC 8555 §6.5.
 *
 * A nonce is 144 random bits, remembered in the shared `AcmeStore` until it is used or expires. Consuming is one atomic
 * delete, so a nonce works exactly once even when the replay races itself against two replicas.
 *
 * @author Jean-Philippe Steinmetz
 */
export class NonceService {
    private readonly store: AcmeStore;
    private readonly ttlSeconds: number;

    constructor(store: AcmeStore, ttlSeconds: number = 3600) {
        this.store = store;
        this.ttlSeconds = ttlSeconds;
    }

    /** Creates and remembers a fresh nonce. */
    public async issue(): Promise<string> {
        const nonce: string = randomBytes(18).toString("base64url");
        await this.store.putIfAbsent(`nonce:${nonce}`, this.ttlSeconds);
        return nonce;
    }

    /** Uses up `nonce`. Resolves `true` exactly once per issued, unexpired nonce. */
    public async consume(nonce: string): Promise<boolean> {
        if (typeof nonce !== "string" || !NONCE_SHAPE.test(nonce)) {
            return false;
        }
        return await this.store.take(`nonce:${nonce}`);
    }
}
