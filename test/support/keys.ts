///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { exportJWK, generateKeyPair, JWK } from "jose";

/** A JWS signing key for the test client, with its public JWK. */
export class AcmeTestKey {
    public readonly alg: string;
    public readonly privateKey: CryptoKey;
    public readonly publicJwk: JWK;

    private constructor(alg: string, privateKey: CryptoKey, publicJwk: JWK) {
        this.alg = alg;
        this.privateKey = privateKey;
        this.publicJwk = publicJwk;
    }

    public static async generate(alg: "ES256" | "ES384" | "RS256" = "ES256"): Promise<AcmeTestKey> {
        const pair = await generateKeyPair(alg, { extractable: true, ...(alg === "RS256" ? { modulusLength: 2048 } : {}) });
        const jwk: JWK = await exportJWK(pair.publicKey);
        return new AcmeTestKey(alg, pair.privateKey, jwk);
    }
}
