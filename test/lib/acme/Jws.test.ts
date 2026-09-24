///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { FlattenedSign } from "jose";
import { AcmeProblem } from "../../../src/lib/acme/AcmeProblem.js";
import { jwkThumbprint, MAX_JWS_BYTES, normalizeJwk, parseJws, parsePayload, verifyJwsSignature } from "../../../src/lib/acme/Jws.js";
import { AcmeTestKey } from "../../support/keys.js";

const problemType = (fn: () => unknown): string | undefined => {
    try {
        fn();
        return undefined;
    } catch (err) {
        return err instanceof AcmeProblem ? err.errorType : "not-a-problem";
    }
};

const b64 = (value: unknown): string => Buffer.from(typeof value === "string" ? value : JSON.stringify(value)).toString("base64url");

describe("normalizeJwk", () => {
    it("reduces a key to its RFC 7638 members", async () => {
        const key = await AcmeTestKey.generate("ES256");
        const noisy = { ...key.publicJwk, kid: "abc", use: "sig", alg: "ES256", key_ops: ["verify"] };
        expect(normalizeJwk(noisy)).toEqual({ kty: "EC", crv: "P-256", x: key.publicJwk.x, y: key.publicJwk.y });
        const rsa = await AcmeTestKey.generate("RS256");
        expect(normalizeJwk(rsa.publicJwk)).toEqual({ kty: "RSA", n: rsa.publicJwk.n, e: rsa.publicJwk.e });
    });

    it("computes the RFC 7638 thumbprint (the example key of the RFC)", async () => {
        const rfcKey = {
            kty: "RSA" as const,
            n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            e: "AQAB",
        };
        expect(await jwkThumbprint(rfcKey)).toBe("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
    });

    it("refuses anything with private key material", async () => {
        const key = await AcmeTestKey.generate("ES256");
        for (const member of ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]) {
            expect(problemType(() => normalizeJwk({ ...key.publicJwk, [member]: "AAAA" })), member).toBe("badPublicKey");
        }
    });

    it("refuses non-objects and members that are missing or not base64url", () => {
        for (const value of [null, undefined, "x", 5, [], true]) {
            expect(problemType(() => normalizeJwk(value))).toBe("malformed");
        }
        expect(problemType(() => normalizeJwk({ kty: "EC", crv: "P-256", x: "AAAA" }))).toBe("malformed");
        expect(problemType(() => normalizeJwk({ kty: "EC", crv: "P-256", x: "not base64!", y: "AAAA" }))).toBe("malformed");
        expect(problemType(() => normalizeJwk({ kty: "EC", crv: "P-256", x: "", y: "AAAA" }))).toBe("malformed");
        expect(problemType(() => normalizeJwk({ kty: "RSA", n: "AAAA" }))).toBe("malformed");
    });

    it("supports only P-256, P-384, P-521 and RSA of 2048 to 8192 bits with a sensible exponent", async () => {
        expect(problemType(() => normalizeJwk({ kty: "EC", crv: "secp256k1", x: "AAAA", y: "AAAA" }))).toBe("badPublicKey");
        expect(problemType(() => normalizeJwk({ kty: "OKP", crv: "Ed25519", x: "AAAA" }))).toBe("badPublicKey");
        expect(problemType(() => normalizeJwk({ kty: "oct", k: "AAAA" }))).toBe("badPublicKey");
        const modulus = (bits: number): string => Buffer.concat([Buffer.from([0x80]), Buffer.alloc(bits / 8 - 1, 0x11)]).toString("base64url");
        expect(problemType(() => normalizeJwk({ kty: "RSA", n: modulus(1024), e: "AQAB" }))).toBe("badPublicKey");
        expect(problemType(() => normalizeJwk({ kty: "RSA", n: modulus(2040), e: "AQAB" }))).toBe("badPublicKey");
        expect(problemType(() => normalizeJwk({ kty: "RSA", n: modulus(2048), e: "AQAB" }))).toBeUndefined();
        expect(problemType(() => normalizeJwk({ kty: "RSA", n: modulus(8192), e: "AQAB" }))).toBeUndefined();
        expect(problemType(() => normalizeJwk({ kty: "RSA", n: modulus(8200), e: "AQAB" }))).toBe("badPublicKey");
        expect(problemType(() => normalizeJwk({ kty: "RSA", n: modulus(2048), e: "Aw" }))).toBe("badPublicKey");
        expect(problemType(() => normalizeJwk({ kty: "RSA", n: modulus(2048), e: "AQAC" }))).toBe("badPublicKey");
        expect(problemType(() => normalizeJwk({ kty: "RSA", n: modulus(2048), e: "AA" }))).toBe("badPublicKey");
    });
});

describe("parseJws", () => {
    const header = { alg: "ES256", nonce: "abcdefghijklmnop", url: "https://acme.test/x", kid: "https://acme.test/acme/acct/x" };
    const body = (overrides: Record<string, unknown> = {}): Buffer => Buffer.from(JSON.stringify({ protected: b64(header), payload: b64("{}"), signature: b64("sig"), ...overrides }));

    it("parses a well-formed flattened JWS", () => {
        const parsed = parseJws(body());
        expect(parsed.header).toEqual(header);
        expect(parsed.payloadText).toBe("{}");
    });

    it("treats an empty payload as POST-as-GET", () => {
        expect(parseJws(body({ payload: "" })).payloadText).toBe("");
        expect(parsePayload("")).toBeUndefined();
        expect(parsePayload("{}")).toEqual({});
        expect(problemType(() => parsePayload("[]"))).toBe("malformed");
        expect(problemType(() => parsePayload("null"))).toBe("malformed");
        expect(problemType(() => parsePayload("{oops"))).toBe("malformed");
    });

    it("rejects what is not a JWS", () => {
        expect(problemType(() => parseJws(undefined))).toBe("malformed");
        expect(problemType(() => parseJws(Buffer.alloc(0)))).toBe("malformed");
        expect(problemType(() => parseJws(Buffer.from("nope")))).toBe("malformed");
        expect(problemType(() => parseJws(Buffer.from("[]")))).toBe("malformed");
        expect(problemType(() => parseJws(body({ header: {} })))).toBe("malformed");
        expect(problemType(() => parseJws(body({ protected: 5 })))).toBe("malformed");
        expect(problemType(() => parseJws(body({ payload: null })))).toBe("malformed");
        expect(problemType(() => parseJws(body({ signature: {} })))).toBe("malformed");
        expect(problemType(() => parseJws(body({ protected: "$$$" })))).toBe("malformed");
        expect(problemType(() => parseJws(body({ protected: b64("not json") })))).toBe("malformed");
        expect(problemType(() => parseJws(body({ protected: b64("[]") })))).toBe("malformed");
        expect(problemType(() => parseJws(body({ signature: "$$$" })))).toBe("malformed");
    });

    it("caps the size of a request", () => {
        expect(problemType(() => parseJws(Buffer.alloc(MAX_JWS_BYTES + 1, 32)))).toBe("malformed");
    });

    it("requires alg, url and nonce, and exactly one of jwk and kid", () => {
        const make = (h: Record<string, unknown>) => body({ protected: b64(h) });
        expect(problemType(() => parseJws(make({ ...header, alg: undefined })))).toBe("badSignatureAlgorithm");
        expect(problemType(() => parseJws(make({ ...header, alg: "HS256" })))).toBe("badSignatureAlgorithm");
        expect(problemType(() => parseJws(make({ ...header, alg: "none" })))).toBe("badSignatureAlgorithm");
        expect(problemType(() => parseJws(make({ ...header, alg: "PS256" })))).toBe("badSignatureAlgorithm");
        expect(problemType(() => parseJws(make({ ...header, url: undefined })))).toBe("malformed");
        expect(problemType(() => parseJws(make({ ...header, url: "" })))).toBe("malformed");
        expect(problemType(() => parseJws(make({ ...header, nonce: undefined })))).toBe("malformed");
        expect(problemType(() => parseJws(make({ ...header, nonce: "" })))).toBe("malformed");
        expect(problemType(() => parseJws(make({ ...header, kid: undefined })))).toBe("malformed");
        expect(problemType(() => parseJws(make({ ...header, jwk: { kty: "EC" } })))).toBe("malformed");
        expect(problemType(() => parseJws(make({ ...header, kid: 5 })))).toBe("malformed");
        expect(problemType(() => parseJws(make({ ...header, kid: "" })))).toBe("malformed");
        expect(problemType(() => parseJws(make({ ...header, crit: [] })))).toBe("malformed");
        expect(problemType(() => parseJws(make({ ...header, b64: false })))).toBe("malformed");
    });

    it("can require the nonce to be absent, as in the inner JWS of a key change", () => {
        const { nonce: _nonce, kid: _kid, ...rest } = header;
        const inner = (h: Record<string, unknown>) => body({ protected: b64(h) });
        const jwk = { kty: "EC", crv: "P-256", x: "AAAA", y: "AAAA" };
        expect(parseJws(inner({ ...rest, jwk }), { nonceRequired: false }).header.nonce).toBeUndefined();
        expect(problemType(() => parseJws(inner({ ...rest, jwk, nonce: "x" }), { nonceRequired: false }))).toBe("malformed");
    });

    it("lists the acceptable algorithms in a badSignatureAlgorithm problem", () => {
        try {
            parseJws(body({ protected: b64({ ...header, alg: "HS512" }) }));
            expect.unreachable();
        } catch (err) {
            expect((err as AcmeProblem).toDocument().algorithms).toEqual(["ES256", "ES384", "ES512", "RS256", "RS384", "RS512"]);
        }
    });
});

describe("verifyJwsSignature", () => {
    const signed = async (key: AcmeTestKey, alg: string = key.alg) => {
        const jws = await new FlattenedSign(new TextEncoder().encode("{}")).setProtectedHeader({ alg, nonce: "abcdefghijklmnop", url: "https://acme.test/x", jwk: key.publicJwk }).sign(key.privateKey);
        return parseJws(Buffer.from(JSON.stringify(jws)));
    };

    it("verifies a correct signature for each supported key type", async () => {
        for (const alg of ["ES256", "ES384", "RS256"] as const) {
            const key = await AcmeTestKey.generate(alg);
            await expect(verifyJwsSignature(await signed(key), normalizeJwk(key.publicJwk))).resolves.toBeUndefined();
        }
    });

    it("rejects a signature by another key, a tampered payload, and an algorithm that does not fit the key", async () => {
        const key = await AcmeTestKey.generate("ES256");
        const other = await AcmeTestKey.generate("ES256");
        const parsed = await signed(key);
        await expect(verifyJwsSignature(parsed, normalizeJwk(other.publicJwk))).rejects.toMatchObject({ errorType: "malformed" });
        await expect(verifyJwsSignature({ ...parsed, jws: { ...parsed.jws, payload: b64('{"a":1}') } }, normalizeJwk(key.publicJwk))).rejects.toMatchObject({ errorType: "malformed" });
        const p384 = await AcmeTestKey.generate("ES384");
        await expect(verifyJwsSignature(parsed, normalizeJwk(p384.publicJwk))).rejects.toMatchObject({ errorType: "malformed" });
    });
});
