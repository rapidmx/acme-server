///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { createHash, createPublicKey, KeyObject, verify } from "node:crypto";
import { DnsName, nameToWire } from "./name.js";
import { DsRecord } from "./types.js";

/** DNSSEC signature algorithm numbers (IANA "DNS Security Algorithm Numbers"). */
export const ALGORITHM = {
    RSASHA1: 5,
    RSASHA1_NSEC3_SHA1: 7,
    RSASHA256: 8,
    RSASHA512: 10,
    ECDSAP256SHA256: 13,
    ECDSAP384SHA384: 14,
    ED25519: 15,
    ED448: 16,
} as const;

/** DNSKEY flag bit: Zone Key (RFC 4034 section 2.1.1). */
export const FLAG_ZONE = 0x0100;
/** DNSKEY flag bit: Revoked (RFC 5011). A revoked key must not be used to validate anything. */
export const FLAG_REVOKE = 0x0080;

/** Signature algorithms this library validates. SHA-1 based ones (5, 7) are deliberately absent (RFC 8624). */
const SUPPORTED_ALGORITHMS: ReadonlySet<number> = new Set<number>([8, 10, 13, 14, 15, 16]);

/** DS digest types this library accepts as proof (SHA-256 and SHA-384; SHA-1 is out per RFC 8624). */
const SUPPORTED_DIGESTS: ReadonlySet<number> = new Set<number>([2, 4]);

/** Whether the DNSSEC signature algorithm is one this library validates. */
export function isSupportedAlgorithm(algorithm: number): boolean {
    return SUPPORTED_ALGORITHMS.has(algorithm);
}

/** Whether the DS digest type is one this library accepts. */
export function isSupportedDigest(digestType: number): boolean {
    return SUPPORTED_DIGESTS.has(digestType);
}

/** A DNSKEY as parsed from RDATA. */
export interface DnskeyRecord {
    flags: number;
    protocol: number;
    algorithm: number;
    /** The public key field, still in DNSSEC wire form. */
    key: Buffer;
    /** The whole RDATA (what the key tag and DS digests are computed over). */
    rdata: Buffer;
    tag: number;
}

/** Parses DNSKEY RDATA, or returns `undefined` when it is too short to be one. */
export function parseDnskey(rdata: Buffer): DnskeyRecord | undefined {
    if (rdata.length < 5) {
        return undefined;
    }
    return {
        flags: rdata.readUInt16BE(0),
        protocol: rdata[2],
        algorithm: rdata[3],
        key: rdata.subarray(4),
        rdata,
        tag: keyTag(rdata),
    };
}

/** Computes the key tag of DNSKEY RDATA (RFC 4034 Appendix B). */
export function keyTag(rdata: Uint8Array): number {
    let sum = 0;
    for (let i = 0; i < rdata.length; i++) {
        sum += i & 1 ? rdata[i] : rdata[i] << 8;
    }
    sum += (sum >>> 16) & 0xffff;
    return sum & 0xffff;
}

/**
 * Computes a DS digest: the hash of the canonical owner name followed by the DNSKEY RDATA (RFC 4034 section 5.1.4).
 * SHA-1 (1) is computable here so RFC vectors can be checked, but validation never accepts it.
 */
export function dsDigest(owner: DnsName, dnskeyRdata: Uint8Array, digestType: number): Buffer | undefined {
    const algorithm: string | undefined = digestType === 1 ? "sha1" : digestType === 2 ? "sha256" : digestType === 4 ? "sha384" : undefined;
    if (!algorithm) {
        return undefined;
    }
    return createHash(algorithm).update(nameToWire(owner)).update(dnskeyRdata).digest();
}

/** The bytes of a DS's digest, whichever form the caller gave it in. */
export function dsDigestBytes(ds: DsRecord): Buffer {
    return typeof ds.digest === "string" ? Buffer.from(ds.digest, "hex") : Buffer.from(ds.digest);
}

/** Parses DS RDATA, or returns `undefined` when it is too short. */
export function parseDs(rdata: Buffer): DsRecord | undefined {
    if (rdata.length < 5) {
        return undefined;
    }
    return {
        keyTag: rdata.readUInt16BE(0),
        algorithm: rdata[2],
        digestType: rdata[3],
        digest: Buffer.from(rdata.subarray(4)),
    };
}

/** Whether a DS record can be used as proof by this library (a supported algorithm and digest type). */
export function isSupportedDs(ds: DsRecord): boolean {
    return isSupportedAlgorithm(ds.algorithm) && isSupportedDigest(ds.digestType);
}

/** Whether `ds` is the digest of `key` at `owner`. */
export function dsMatches(owner: DnsName, key: DnskeyRecord, ds: DsRecord): boolean {
    if (ds.keyTag !== key.tag || ds.algorithm !== key.algorithm) {
        return false;
    }
    const digest: Buffer | undefined = dsDigest(owner, key.rdata, ds.digestType);
    return digest !== undefined && digest.equals(dsDigestBytes(ds));
}

function bitLength(value: Buffer): number {
    let i = 0;
    while (i < value.length && value[i] === 0) {
        i++;
    }
    if (i === value.length) {
        return 0;
    }
    return (value.length - i) * 8 - Math.clz32(value[i]) + 24;
}

/**
 * Converts a DNSKEY public key field to a Node key object, or returns `undefined` when the key is malformed or outside this
 * library's safety limits. RSA keys (RFC 3110: exponent length prefix, exponent, modulus) must have a modulus of 1024 to 4096
 * bits and an odd exponent of at most 32 bits; ECDSA keys are the raw x||y point and EdDSA keys the raw public key.
 */
export function importPublicKey(algorithm: number, key: Buffer): KeyObject | undefined {
    try {
        if (algorithm === ALGORITHM.RSASHA256 || algorithm === ALGORITHM.RSASHA512) {
            if (key.length < 3) {
                return undefined;
            }
            let exponentLength: number = key[0];
            let offset = 1;
            if (exponentLength === 0) {
                exponentLength = key.readUInt16BE(1);
                offset = 3;
            }
            if (exponentLength === 0 || offset + exponentLength >= key.length) {
                return undefined;
            }
            const exponent: Buffer = key.subarray(offset, offset + exponentLength);
            const modulus: Buffer = key.subarray(offset + exponentLength);
            const exponentBits: number = bitLength(exponent);
            const modulusBits: number = bitLength(modulus);
            if (exponentBits < 2 || exponentBits > 32 || (exponent[exponent.length - 1] & 1) === 0) {
                return undefined;
            }
            if (modulusBits < 1024 || modulusBits > 4096 || (modulus[modulus.length - 1] & 1) === 0) {
                return undefined;
            }
            return createPublicKey({
                key: { kty: "RSA", n: modulus.toString("base64url"), e: exponent.toString("base64url") },
                format: "jwk",
            });
        }
        if (algorithm === ALGORITHM.ECDSAP256SHA256 && key.length === 64) {
            return createPublicKey({
                key: { kty: "EC", crv: "P-256", x: key.subarray(0, 32).toString("base64url"), y: key.subarray(32).toString("base64url") },
                format: "jwk",
            });
        }
        if (algorithm === ALGORITHM.ECDSAP384SHA384 && key.length === 96) {
            return createPublicKey({
                key: { kty: "EC", crv: "P-384", x: key.subarray(0, 48).toString("base64url"), y: key.subarray(48).toString("base64url") },
                format: "jwk",
            });
        }
        if (algorithm === ALGORITHM.ED25519 && key.length === 32) {
            return createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: key.toString("base64url") }, format: "jwk" });
        }
        if (algorithm === ALGORITHM.ED448 && key.length === 57) {
            return createPublicKey({ key: { kty: "OKP", crv: "Ed448", x: key.toString("base64url") }, format: "jwk" });
        }
    } catch {
        return undefined;
    }
    return undefined;
}

/**
 * Verifies a DNSSEC signature over `data`. ECDSA signatures are the raw r||s concatenation (RFC 6605), which Node calls
 * IEEE P1363 encoding; RSA uses PKCS#1 v1.5 (RFC 5702); EdDSA is pure (RFC 8080). Any failure, including a malformed
 * signature, is simply `false`.
 */
export function verifySignature(algorithm: number, key: KeyObject, data: Uint8Array, signature: Uint8Array): boolean {
    try {
        switch (algorithm) {
            case ALGORITHM.RSASHA256:
                return verify("sha256", data, key, signature);
            case ALGORITHM.RSASHA512:
                return verify("sha512", data, key, signature);
            case ALGORITHM.ECDSAP256SHA256:
                return signature.length === 64 && verify("sha256", data, { key, dsaEncoding: "ieee-p1363" }, signature);
            case ALGORITHM.ECDSAP384SHA384:
                return signature.length === 96 && verify("sha384", data, { key, dsaEncoding: "ieee-p1363" }, signature);
            case ALGORITHM.ED25519:
                return signature.length === 64 && verify(null, data, key, signature);
            case ALGORITHM.ED448:
                return signature.length === 114 && verify(null, data, key, signature);
            default:
                return false;
        }
    } catch {
        return false;
    }
}
