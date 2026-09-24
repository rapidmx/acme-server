///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { calculateJwkThumbprint, flattenedVerify, importJWK } from "jose";
import { AcmeProblem } from "./AcmeProblem.js";

/** The `Content-Type` every ACME POST carries (RFC 8555 §6.2). */
export const JOSE_CONTENT_TYPE = "application/jose+json";

/** The signature algorithms accepted for account and certificate keys (RFC 8555 §6.2; no MAC, no `none`). */
export const ALLOWED_JWS_ALGORITHMS: readonly string[] = ["ES256", "ES384", "ES512", "RS256", "RS384", "RS512"];

/** The most a JWS body may be. ACME messages are tiny; the biggest is a finalize request with a CSR. */
export const MAX_JWS_BYTES = 64 * 1024;

/** The smallest and largest RSA modulus accepted in a JWK. */
const MIN_RSA_BITS = 2048;
const MAX_RSA_BITS = 8192;

const CURVES: readonly string[] = ["P-256", "P-384", "P-521"];
const BASE64URL = /^[A-Za-z0-9_-]+$/;

/** A JWK reduced to its public, canonical members (RFC 7638 required members). */
export type PublicJwk = { kty: "EC"; crv: string; x: string; y: string } | { kty: "RSA"; n: string; e: string };

/** The protected header of an ACME JWS after structural validation. */
export interface AcmeJwsHeader {
    alg: string;
    nonce?: string;
    url: string;
    jwk?: PublicJwk;
    kid?: string;
}

/** A JWS that passed structural validation but whose signature is not verified yet (see `verifyJwsSignature()`). */
export interface ParsedJws {
    /** The flattened JWS exactly as received, for signature verification. */
    jws: { protected: string; payload: string; signature: string };
    header: AcmeJwsHeader;
    /** The decoded payload. Empty for a POST-as-GET (RFC 8555 §6.3). */
    payloadText: string;
}

/** Decodes base64url to bytes, refusing anything that is not canonical base64url. */
function b64urlDecode(value: string, what: string): Buffer {
    if (typeof value !== "string" || (value.length > 0 && !BASE64URL.test(value))) {
        throw AcmeProblem.malformed(`The JWS ${what} is not valid base64url.`);
    }
    return Buffer.from(value, "base64url");
}

/** The bit length of an unsigned big-endian integer given as base64url. */
function bitLength(base64url: string): number {
    const bytes: Buffer = Buffer.from(base64url, "base64url");
    let i = 0;
    while (i < bytes.length && bytes[i] === 0) {
        i++;
    }
    if (i === bytes.length) {
        return 0;
    }
    return (bytes.length - i - 1) * 8 + (32 - Math.clz32(bytes[i]));
}

/**
 * Validates a JWK from a request (an account key, or the key of a certificate being revoked) and reduces it to its
 * public members.
 *
 * Refuses private key material outright (a client that sends `d` has leaked its key to everyone on the path),
 * unsupported key types and curves, and RSA keys that are too small or too large to be sensible.
 *
 * @throws `malformed` for something that is not a JWK, `badPublicKey` for a key this CA will not accept.
 */
export function normalizeJwk(jwk: unknown): PublicJwk {
    if (typeof jwk !== "object" || jwk === null || Array.isArray(jwk)) {
        throw AcmeProblem.malformed("The JWK is not a JSON object.");
    }
    const key: Record<string, unknown> = jwk as Record<string, unknown>;
    for (const secret of ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]) {
        if (secret in key) {
            throw new AcmeProblem("badPublicKey", "The JWK contains private key material.");
        }
    }
    const str = (name: string): string => {
        const value: unknown = key[name];
        if (typeof value !== "string" || value.length === 0 || value.length > 4096 || !BASE64URL.test(value)) {
            throw AcmeProblem.malformed(`The JWK member '${name}' is missing or not base64url.`);
        }
        return value;
    };
    if (key.kty === "EC") {
        const crv: unknown = key.crv;
        if (typeof crv !== "string" || !CURVES.includes(crv)) {
            throw new AcmeProblem("badPublicKey", "Only the P-256, P-384 and P-521 curves are supported.");
        }
        return { kty: "EC", crv, x: str("x"), y: str("y") };
    }
    if (key.kty === "RSA") {
        const n: string = str("n");
        const e: string = str("e");
        const bits: number = bitLength(n);
        if (bits < MIN_RSA_BITS || bits > MAX_RSA_BITS) {
            throw new AcmeProblem("badPublicKey", `RSA keys must be between ${MIN_RSA_BITS} and ${MAX_RSA_BITS} bits.`);
        }
        const exponent: Buffer = Buffer.from(e, "base64url");
        if (exponent.length === 0 || (exponent[exponent.length - 1] & 1) === 0 || bitLength(e) < 17) {
            throw new AcmeProblem("badPublicKey", "The RSA public exponent must be odd and at least 65537.");
        }
        return { kty: "RSA", n, e };
    }
    throw new AcmeProblem("badPublicKey", "Only EC and RSA keys are supported.");
}

/** The RFC 7638 SHA-256 thumbprint of a JWK, base64url – the account key thumbprint of RFC 8555 §8.1. */
export async function jwkThumbprint(jwk: PublicJwk): Promise<string> {
    return await calculateJwkThumbprint(jwk, "sha256");
}

/**
 * Structurally validates a request body as an ACME JWS (RFC 8555 §6.2): a flattened JWS with exactly the members
 * `protected`, `payload` and `signature`; a protected header with an allowed `alg`, a `url`, and exactly one of `jwk` or
 * `kid`; no unprotected header, no `crit`, no unencoded payload.
 *
 * Does **not** verify the signature, the nonce or the `url` against the request – the caller does that in an order that
 * never burns a nonce for a request that could not have been authentic.
 *
 * @param body The raw request body.
 * @param options `nonceRequired`: `false` for the inner JWS of a key change, which has none (RFC 8555 §7.3.5).
 */
export function parseJws(body: Buffer | undefined, options: { nonceRequired?: boolean } = {}): ParsedJws {
    if (!body || body.length === 0) {
        throw AcmeProblem.malformed("The request body is empty; a JWS is required.");
    }
    if (body.length > MAX_JWS_BYTES) {
        throw AcmeProblem.malformed("The request body is too large.", 413);
    }
    let outer: any;
    try {
        outer = JSON.parse(body.toString("utf8"));
    } catch {
        throw AcmeProblem.malformed("The request body is not valid JSON.");
    }
    if (typeof outer !== "object" || outer === null || Array.isArray(outer)) {
        throw AcmeProblem.malformed("The request body is not a flattened JWS object.");
    }
    const keys: string[] = Object.keys(outer);
    if (keys.some((k) => k !== "protected" && k !== "payload" && k !== "signature")) {
        throw AcmeProblem.malformed("The JWS must contain only the protected, payload and signature members.");
    }
    if (typeof outer.protected !== "string" || typeof outer.payload !== "string" || typeof outer.signature !== "string") {
        throw AcmeProblem.malformed("The JWS must have string protected, payload and signature members.");
    }

    let header: any;
    try {
        header = JSON.parse(b64urlDecode(outer.protected, "protected header").toString("utf8"));
    } catch (err) {
        if (err instanceof AcmeProblem) {
            throw err;
        }
        throw AcmeProblem.malformed("The JWS protected header is not valid JSON.");
    }
    if (typeof header !== "object" || header === null || Array.isArray(header)) {
        throw AcmeProblem.malformed("The JWS protected header is not a JSON object.");
    }
    if ("crit" in header || "b64" in header) {
        throw AcmeProblem.malformed("The JWS protected header must not use crit or b64.");
    }
    if (typeof header.alg !== "string" || !ALLOWED_JWS_ALGORITHMS.includes(header.alg)) {
        const problem: AcmeProblem = new AcmeProblem(
            "badSignatureAlgorithm",
            `The signature algorithm '${String(header.alg)}' is not supported.`,
        );
        problem.algorithms = [...ALLOWED_JWS_ALGORITHMS];
        throw problem;
    }
    if (typeof header.url !== "string" || header.url.length === 0) {
        throw AcmeProblem.malformed("The JWS protected header has no url.");
    }
    if (options.nonceRequired !== false && (typeof header.nonce !== "string" || header.nonce.length === 0)) {
        throw AcmeProblem.malformed("The JWS protected header has no nonce.", 400);
    }
    if (options.nonceRequired === false && header.nonce !== undefined) {
        throw AcmeProblem.malformed("This JWS must not carry a nonce.");
    }
    const hasJwk: boolean = header.jwk !== undefined;
    const hasKid: boolean = header.kid !== undefined;
    if (hasJwk === hasKid) {
        throw AcmeProblem.malformed("The JWS protected header must contain exactly one of jwk and kid.");
    }
    if (hasKid && (typeof header.kid !== "string" || header.kid.length === 0)) {
        throw AcmeProblem.malformed("The JWS kid is not a string.");
    }

    const payload: Buffer = b64urlDecode(outer.payload, "payload");
    b64urlDecode(outer.signature, "signature");
    return {
        jws: { protected: outer.protected, payload: outer.payload, signature: outer.signature },
        header: {
            alg: header.alg,
            ...(header.nonce !== undefined ? { nonce: String(header.nonce) } : {}),
            url: header.url,
            ...(hasJwk ? { jwk: normalizeJwk(header.jwk) } : {}),
            ...(hasKid ? { kid: header.kid } : {}),
        },
        payloadText: payload.toString("utf8"),
    };
}

/**
 * Verifies the signature of a parsed JWS against `jwk`.
 *
 * @throws `malformed` when the signature does not verify (or the key cannot be used with the algorithm in the header).
 */
export async function verifyJwsSignature(parsed: ParsedJws, jwk: PublicJwk): Promise<void> {
    try {
        const key = await importJWK(jwk as any, parsed.header.alg);
        await flattenedVerify(parsed.jws, key, { algorithms: [parsed.header.alg] });
    } catch {
        // Every failure in here is the client's doing – a bad signature, an algorithm that does not fit the key (an ES256 header
        // over a P-384 key), a key the library refuses – and none of it may surface as a server error.
        throw AcmeProblem.malformed("The JWS signature could not be verified.", 400);
    }
}

/**
 * Parses a JWS payload: `undefined` for a POST-as-GET (empty payload), otherwise the JSON object.
 *
 * @throws `malformed` for a payload that is not a JSON object.
 */
export function parsePayload(payloadText: string): Record<string, any> | undefined {
    if (payloadText === "") {
        return undefined;
    }
    let value: unknown;
    try {
        value = JSON.parse(payloadText);
    } catch {
        throw AcmeProblem.malformed("The JWS payload is not valid JSON.");
    }
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw AcmeProblem.malformed("The JWS payload is not a JSON object.");
    }
    return value as Record<string, any>;
}
