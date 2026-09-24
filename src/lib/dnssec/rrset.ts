///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { KeyObject } from "node:crypto";
import { DnskeyRecord, importPublicKey, isSupportedAlgorithm, verifySignature } from "./keys.js";
import { DnsName, isSubdomain, labelCount, labelsToName, nameToLabels, nameToWire } from "./name.js";
import { bogus, CLASS_IN, indeterminate, RRTYPE } from "./types.js";
import { DnsRecord, readPlainName } from "./wire.js";

/** How many signature verifications one RRset may cost, so a hostile zone cannot burn CPU with colliding key tags (KeyTrap). */
const MAX_VERIFICATIONS = 16;

/** A validated DNSKEY of a zone. The Node key object is built lazily, only if a signature names the key. */
export interface TrustedKey extends DnskeyRecord {
    object?: KeyObject | null;
}

/** A parsed RRSIG (RFC 4034 section 3). */
export interface RrsigRecord {
    typeCovered: number;
    algorithm: number;
    labels: number;
    originalTtl: number;
    expiration: number;
    inception: number;
    keyTag: number;
    signer: DnsName;
    /** RDATA up to the signature with the signer name in canonical (lower-case) form: the start of the signed data. */
    header: Buffer;
    signature: Buffer;
}

/** Parses RRSIG RDATA, or returns `undefined` when it is malformed. */
export function parseRrsig(rdata: Buffer): RrsigRecord | undefined {
    if (rdata.length < 19) {
        return undefined;
    }
    try {
        const { name, end } = readPlainName(rdata, 18);
        if (end >= rdata.length) {
            return undefined;
        }
        return {
            typeCovered: rdata.readUInt16BE(0),
            algorithm: rdata[2],
            labels: rdata[3],
            originalTtl: rdata.readUInt32BE(4),
            expiration: rdata.readUInt32BE(8),
            inception: rdata.readUInt32BE(12),
            keyTag: rdata.readUInt16BE(16),
            signer: name,
            header: Buffer.concat([rdata.subarray(0, 18), nameToWire(name)]),
            signature: Buffer.from(rdata.subarray(end)),
        };
    } catch {
        return undefined;
    }
}

/**
 * The canonical RDATA of a record (RFC 4034 section 6.2): names embedded in the RDATA of the classic types are lower-cased.
 * NSEC's next name is left alone (RFC 6840 section 5.1). Only the types this library validates are supported.
 *
 * @throws `indeterminate` for a type without canonicalisation rules here or for malformed RDATA.
 */
export function canonicalRdata(type: number, rdata: Buffer): Buffer {
    switch (type) {
        case RRTYPE.A:
        case RRTYPE.AAAA:
        case RRTYPE.TXT:
        case RRTYPE.DS:
        case RRTYPE.DNSKEY:
        case RRTYPE.NSEC:
        case RRTYPE.NSEC3:
        case RRTYPE.NSEC3PARAM:
        case RRTYPE.CAA:
            return rdata;
        case RRTYPE.NS:
        case RRTYPE.CNAME:
        case RRTYPE.PTR:
        case RRTYPE.DNAME: {
            const { name, end } = readPlainName(rdata, 0);
            if (end !== rdata.length) {
                throw indeterminate("malformed RDATA: trailing bytes after a name");
            }
            return nameToWire(name);
        }
        case RRTYPE.MX: {
            if (rdata.length < 3) {
                throw indeterminate("malformed MX RDATA");
            }
            const { name, end } = readPlainName(rdata, 2);
            if (end !== rdata.length) {
                throw indeterminate("malformed MX RDATA");
            }
            return Buffer.concat([rdata.subarray(0, 2), nameToWire(name)]);
        }
        case RRTYPE.SRV: {
            if (rdata.length < 7) {
                throw indeterminate("malformed SRV RDATA");
            }
            const { name, end } = readPlainName(rdata, 6);
            if (end !== rdata.length) {
                throw indeterminate("malformed SRV RDATA");
            }
            return Buffer.concat([rdata.subarray(0, 6), nameToWire(name)]);
        }
        case RRTYPE.SOA: {
            const a = readPlainName(rdata, 0);
            const b = readPlainName(rdata, a.end);
            if (b.end + 20 !== rdata.length) {
                throw indeterminate("malformed SOA RDATA");
            }
            return Buffer.concat([nameToWire(a.name), nameToWire(b.name), rdata.subarray(b.end)]);
        }
        default:
            throw indeterminate(`no canonical form implemented for RR type ${type}`);
    }
}

/** RFC 1982 serial number arithmetic on 32-bit values: `a <= b`. */
function serialLte(a: number, b: number): boolean {
    return (b - a) >>> 0 < 0x80000000;
}

/**
 * Builds the data an RRSIG signs (RFC 4034 section 3.1.8.1): the RRSIG RDATA without the signature, then every record of the
 * RRset in canonical form, ordered by canonical RDATA with duplicates removed. `owner` is the name to sign as, which for a
 * wildcard expansion is the wildcard itself, not the queried name.
 */
export function signedData(rrsig: RrsigRecord, owner: DnsName, type: number, rdatas: Buffer[]): Buffer {
    const canon: Buffer[] = rdatas.map((r) => canonicalRdata(type, r)).sort((a, b) => Buffer.compare(a, b));
    const ownerWire: Buffer = nameToWire(owner);
    const parts: Buffer[] = [rrsig.header];
    let previous: Buffer | undefined;
    for (const rdata of canon) {
        if (previous && previous.equals(rdata)) {
            continue;
        }
        previous = rdata;
        const fixed: Buffer = Buffer.alloc(10);
        fixed.writeUInt16BE(type, 0);
        fixed.writeUInt16BE(CLASS_IN, 2);
        fixed.writeUInt32BE(rrsig.originalTtl, 4);
        fixed.writeUInt16BE(rdata.length, 8);
        parts.push(ownerWire, fixed, rdata);
    }
    return Buffer.concat(parts);
}

/** What a successful RRset validation established. */
export interface RrsetValidation {
    /** When the RRSIG that validated the RRset was a wildcard expansion: the number of labels of the wildcard's parent. */
    wildcardLabels?: number;
    /** The moment (ms since the epoch) the validating signature expires. */
    expiresAt: number;
    /** The RRset's TTL in seconds, capped by the signature's original TTL. */
    ttl: number;
}

/**
 * Validates an RRset against the keys of the zone that must have signed it (RFC 4035 section 5.3): some RRSIG covering the
 * type, whose signer is exactly the zone, made by a zone key with matching algorithm and key tag, valid at `now` in serial
 * arithmetic, and cryptographically correct over the canonical RRset. The RRSIG `labels` field is checked, and a wildcard
 * expansion is reported so the caller can demand the proof that the exact name does not exist.
 *
 * @param input.records The RRset (one owner, one type, class IN).
 * @param input.sigs Candidate RRSIG records; ones for other owners or types are ignored.
 * @param input.zone The zone whose keys must have signed the RRset.
 * @param input.keys The validated zone keys.
 * @param input.now The current time.
 * @throws `bogus` when no RRSIG validates the RRset.
 */
export function validateRrset(input: {
    name: DnsName;
    type: number;
    records: DnsRecord[];
    sigs: DnsRecord[];
    zone: DnsName;
    keys: TrustedKey[];
    now: Date;
}): RrsetValidation {
    const { name, type, records, sigs, zone, keys, now } = input;
    if (records.length === 0) {
        throw bogus(`empty RRset for ${name || "."} type ${type}`);
    }
    if (!isSubdomain(name, zone)) {
        throw bogus(`${name || "."} is not inside the zone ${zone || "."} that is supposed to sign it`);
    }
    const covering: DnsRecord[] = sigs.filter((s) => s.name === name && s.cls === CLASS_IN);
    let candidates = 0;
    let reason = `no RRSIG covers ${name || "."} type ${type}`;
    let verifications = 0;
    const now32: number = Math.floor(now.getTime() / 1000) >>> 0;
    const rdatas: Buffer[] = records.map((r) => r.rdata);
    const ownerLabels: number = labelCount(name);
    const wildcardOwner: boolean = ownerLabels > 0 && nameToLabels(name)[0] === "*";
    for (const record of covering) {
        const sig: RrsigRecord | undefined = parseRrsig(record.rdata);
        if (!sig || sig.typeCovered !== type) {
            continue;
        }
        candidates++;
        if (sig.signer !== zone) {
            reason = `RRSIG signer ${sig.signer || "."} is not the zone ${zone || "."}`;
            continue;
        }
        if (!isSupportedAlgorithm(sig.algorithm)) {
            reason = `RRSIG algorithm ${sig.algorithm} is not supported`;
            continue;
        }
        if (!serialLte(sig.inception, now32)) {
            reason = "RRSIG is not yet valid";
            continue;
        }
        if (!serialLte(now32, sig.expiration)) {
            reason = "RRSIG has expired";
            continue;
        }
        const effectiveLabels: number = ownerLabels - (wildcardOwner ? 1 : 0);
        if (sig.labels > effectiveLabels) {
            reason = "RRSIG labels field exceeds the owner name's labels";
            continue;
        }
        const wildcard: boolean = sig.labels < effectiveLabels;
        const labels: string[] = nameToLabels(name);
        const signedOwner: DnsName = wildcard ? labelsToName(["*", ...labels.slice(labels.length - sig.labels)]) : name;
        const matching: TrustedKey[] = keys.filter((k) => k.tag === sig.keyTag && k.algorithm === sig.algorithm);
        if (matching.length === 0) {
            reason = `no validated zone key ${sig.keyTag}/${sig.algorithm} made the RRSIG`;
            continue;
        }
        const data: Buffer = signedData(sig, signedOwner, type, rdatas);
        for (const key of matching) {
            if (++verifications > MAX_VERIFICATIONS) {
                throw bogus("too many candidate signatures to check");
            }
            if (key.object === undefined) {
                key.object = importPublicKey(key.algorithm, key.key) ?? null;
            }
            if (!key.object) {
                reason = `zone key ${key.tag} is unusable`;
                continue;
            }
            if (verifySignature(sig.algorithm, key.object, data, sig.signature)) {
                const remaining: number = (sig.expiration - now32) >>> 0;
                const minTtl: number = Math.min(...records.map((r) => r.ttl), sig.originalTtl);
                return {
                    wildcardLabels: wildcard ? sig.labels : undefined,
                    expiresAt: now.getTime() + remaining * 1000,
                    ttl: minTtl,
                };
            }
            reason = "RRSIG signature does not verify";
        }
    }
    throw bogus(candidates === 0 ? reason : `${name || "."} type ${type}: ${reason}`);
}
