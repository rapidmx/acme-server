///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { createHash } from "node:crypto";
import {
    commonAncestor,
    compareNames,
    DnsName,
    isProperSubdomain,
    isSubdomain,
    labelCount,
    labelsToName,
    nameToLabels,
    nameToWire,
} from "./name.js";
import { RRTYPE } from "./types.js";
import { readPlainName } from "./wire.js";

/** The most NSEC3 hash iterations this library will compute. RFC 9276 says more than 150 may be treated as insecure. */
export const MAX_NSEC3_ITERATIONS = 500;

const BASE32HEX = "0123456789abcdefghijklmnopqrstuv";

/** Base32hex without padding, lower-case (RFC 4648 section 7), the form of NSEC3 owner labels. */
export function base32hexEncode(data: Uint8Array): string {
    let bits = 0;
    let value = 0;
    let out = "";
    for (const byte of data) {
        value = (value << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            out += BASE32HEX[(value >>> (bits - 5)) & 31];
            bits -= 5;
        }
        value &= (1 << bits) - 1;
    }
    if (bits > 0) {
        out += BASE32HEX[(value << (5 - bits)) & 31];
    }
    return out;
}

/** Decodes base32hex (either case, no padding); returns `undefined` for a character outside the alphabet. */
export function base32hexDecode(text: string): Buffer | undefined {
    let bits = 0;
    let value = 0;
    const out: number[] = [];
    for (const ch of text.toLowerCase()) {
        const digit: number = BASE32HEX.indexOf(ch);
        if (digit < 0) {
            return undefined;
        }
        value = (value << 5) | digit;
        bits += 5;
        if (bits >= 8) {
            out.push((value >>> (bits - 8)) & 0xff);
            bits -= 8;
            value &= (1 << bits) - 1;
        }
    }
    return Buffer.from(out);
}

/**
 * The NSEC3 hash of a name (RFC 5155 section 5): SHA-1 over the canonical wire name and the salt, then `iterations` more
 * rounds over the previous digest and the salt. Only hash algorithm 1 exists.
 */
export function nsec3Hash(name: DnsName, salt: Uint8Array, iterations: number): Buffer {
    let digest: Buffer = createHash("sha1").update(nameToWire(name)).update(salt).digest();
    for (let i = 0; i < iterations; i++) {
        digest = createHash("sha1").update(digest).update(salt).digest();
    }
    return digest;
}

/** Parses an NSEC/NSEC3 type bitmap (RFC 4034 section 4.1.2); `undefined` when it is malformed. */
export function parseTypeBitmap(data: Uint8Array): Set<number> | undefined {
    const types = new Set<number>();
    let offset = 0;
    let previousWindow = -1;
    while (offset < data.length) {
        if (offset + 2 > data.length) {
            return undefined;
        }
        const window: number = data[offset];
        const length: number = data[offset + 1];
        if (window <= previousWindow || length < 1 || length > 32 || offset + 2 + length > data.length) {
            return undefined;
        }
        previousWindow = window;
        for (let i = 0; i < length; i++) {
            const byte: number = data[offset + 2 + i];
            for (let bit = 0; bit < 8; bit++) {
                if (byte & (0x80 >> bit)) {
                    types.add(window * 256 + i * 8 + bit);
                }
            }
        }
        offset += 2 + length;
    }
    return types;
}

/** A validated NSEC record. */
export interface NsecRecord {
    owner: DnsName;
    next: DnsName;
    types: Set<number>;
}

/** Parses NSEC RDATA for the record at `owner`; `undefined` when malformed. */
export function parseNsec(owner: DnsName, rdata: Buffer): NsecRecord | undefined {
    try {
        const { name, end } = readPlainName(rdata, 0);
        const types: Set<number> | undefined = parseTypeBitmap(rdata.subarray(end));
        return types ? { owner, next: name, types } : undefined;
    } catch {
        return undefined;
    }
}

/** A validated NSEC3 record. */
export interface Nsec3Record {
    /** The owner hash (decoded from the owner's first label). */
    hash: Buffer;
    next: Buffer;
    algorithm: number;
    iterations: number;
    salt: Buffer;
    flags: number;
    types: Set<number>;
}

/** Parses NSEC3 RDATA for the record at `owner` within `zone`; `undefined` when malformed. */
export function parseNsec3(owner: DnsName, zone: DnsName, rdata: Buffer): Nsec3Record | undefined {
    const labels: string[] = nameToLabels(owner);
    if (labels.length !== labelCount(zone) + 1 || !isSubdomain(owner, zone)) {
        return undefined;
    }
    const hash: Buffer | undefined = base32hexDecode(labels[0]);
    if (!hash || hash.length !== 20 || rdata.length < 6) {
        return undefined;
    }
    const saltLength: number = rdata[4];
    if (5 + saltLength + 1 > rdata.length) {
        return undefined;
    }
    const hashLength: number = rdata[5 + saltLength];
    const nextStart: number = 6 + saltLength;
    if (hashLength !== 20 || nextStart + hashLength > rdata.length) {
        return undefined;
    }
    const types: Set<number> | undefined = parseTypeBitmap(rdata.subarray(nextStart + hashLength));
    if (!types) {
        return undefined;
    }
    return {
        hash,
        next: Buffer.from(rdata.subarray(nextStart, nextStart + hashLength)),
        algorithm: rdata[0],
        flags: rdata[1],
        iterations: rdata.readUInt16BE(2),
        salt: Buffer.from(rdata.subarray(5, 5 + saltLength)),
        types,
    };
}

/**
 * A set of validated denial-of-existence records (NSEC or NSEC3) for one zone, offering the questions the resolver needs
 * answered: which names provably exist, which provably do not, and what a matching record says about a name's types.
 */
export interface DenialProof {
    /**
     * The type bitmap of the record proving `name` exists, or `undefined` if no record does. For NSEC an empty non-terminal
     * (a covering record whose next name lies below `name`) matches with an empty bitmap.
     */
    matching(name: DnsName): Set<number> | undefined;
    /**
     * Proof that `name` does not exist: its closest encloser and whether the record covering the next closer name has the
     * opt-out flag (RFC 5155 section 6), or `undefined` when there is no such proof.
     */
    nonexistence(name: DnsName): { closestEncloser: DnsName; optOut: boolean } | undefined;
    /** Whether a record covers `name`, proving it (a wildcard, in practice) does not exist. */
    covers(name: DnsName): boolean;
}

function isDelegation(types: Set<number>): boolean {
    return types.has(RRTYPE.NS) && !types.has(RRTYPE.SOA);
}

/** NSEC-based denial (RFC 4035 section 5.4) over records already validated as signed by `zone`. */
export class NsecDenial implements DenialProof {
    private readonly zone: DnsName;
    private readonly records: NsecRecord[];

    constructor(zone: DnsName, records: NsecRecord[]) {
        this.zone = zone;
        this.records = records.filter((r) => isSubdomain(r.owner, zone) && isSubdomain(r.next, zone));
    }

    private static spans(record: NsecRecord, name: DnsName): boolean {
        const { owner, next } = record;
        if (owner === next) {
            return name !== owner;
        }
        if (compareNames(owner, next) < 0) {
            return compareNames(owner, name) < 0 && compareNames(name, next) < 0;
        }
        return compareNames(owner, name) < 0 || compareNames(name, next) < 0;
    }

    /** The covering record, provided it is not a delegation or DNAME that would put `name` outside this zone's data. */
    private cover(name: DnsName): NsecRecord | undefined {
        if (!isSubdomain(name, this.zone)) {
            return undefined;
        }
        const found: NsecRecord | undefined = this.records.find((r) => NsecDenial.spans(r, name));
        if (!found) {
            return undefined;
        }
        if ((isDelegation(found.types) || found.types.has(RRTYPE.DNAME)) && isProperSubdomain(name, found.owner)) {
            return undefined;
        }
        return found;
    }

    public matching(name: DnsName): Set<number> | undefined {
        const exact: NsecRecord | undefined = this.records.find((r) => r.owner === name);
        if (exact) {
            return exact.types;
        }
        const cover: NsecRecord | undefined = this.cover(name);
        if (cover && isProperSubdomain(cover.next, name)) {
            return new Set<number>();
        }
        return undefined;
    }

    public nonexistence(name: DnsName): { closestEncloser: DnsName; optOut: boolean } | undefined {
        if (this.matching(name)) {
            return undefined;
        }
        const cover: NsecRecord | undefined = this.cover(name);
        if (!cover) {
            return undefined;
        }
        const a: DnsName = commonAncestor(name, cover.owner);
        const b: DnsName = commonAncestor(name, cover.next);
        const closestEncloser: DnsName = labelCount(a) >= labelCount(b) ? a : b;
        if (!isSubdomain(closestEncloser, this.zone) || closestEncloser === name) {
            return undefined;
        }
        return { closestEncloser, optOut: false };
    }

    public covers(name: DnsName): boolean {
        return this.cover(name) !== undefined && this.matching(name) === undefined;
    }
}

/** NSEC3-based denial (RFC 5155 section 8) over validated records that all share one parameter set. */
export class Nsec3Denial implements DenialProof {
    private readonly zone: DnsName;
    private readonly records: Nsec3Record[];
    private readonly salt: Buffer;
    private readonly iterations: number;
    private readonly hashes = new Map<DnsName, Buffer>();

    constructor(zone: DnsName, records: Nsec3Record[]) {
        this.zone = zone;
        this.records = records;
        this.salt = records[0].salt;
        this.iterations = records[0].iterations;
    }

    private hashOf(name: DnsName): Buffer {
        let hash: Buffer | undefined = this.hashes.get(name);
        if (!hash) {
            hash = nsec3Hash(name, this.salt, this.iterations);
            this.hashes.set(name, hash);
        }
        return hash;
    }

    private find(name: DnsName): Nsec3Record | undefined {
        const hash: Buffer = this.hashOf(name);
        return this.records.find((r) => r.hash.equals(hash));
    }

    private static spans(record: Nsec3Record, hash: Buffer): boolean {
        const toOwner: number = Buffer.compare(record.hash, hash);
        const toNext: number = Buffer.compare(hash, record.next);
        const order: number = Buffer.compare(record.hash, record.next);
        if (order < 0) {
            return toOwner < 0 && toNext < 0;
        }
        if (order === 0) {
            return toOwner !== 0;
        }
        return toOwner < 0 || toNext < 0;
    }

    private cover(name: DnsName): Nsec3Record | undefined {
        const hash: Buffer = this.hashOf(name);
        return this.records.find((r) => Nsec3Denial.spans(r, hash));
    }

    public matching(name: DnsName): Set<number> | undefined {
        return isSubdomain(name, this.zone) ? this.find(name)?.types : undefined;
    }

    public nonexistence(name: DnsName): { closestEncloser: DnsName; optOut: boolean } | undefined {
        if (!isSubdomain(name, this.zone)) {
            return undefined;
        }
        const labels: string[] = nameToLabels(name);
        const zoneLabels: number = labelCount(this.zone);
        let nextCloser: DnsName | undefined;
        for (let skip = 0; labels.length - skip >= zoneLabels; skip++) {
            const candidate: DnsName = labelsToName(labels.slice(skip));
            const record: Nsec3Record | undefined = this.find(candidate);
            if (record) {
                if (nextCloser === undefined) {
                    return undefined;
                }
                if (isDelegation(record.types) || record.types.has(RRTYPE.DNAME)) {
                    return undefined;
                }
                const cover: Nsec3Record | undefined = this.cover(nextCloser);
                if (!cover) {
                    return undefined;
                }
                return { closestEncloser: candidate, optOut: (cover.flags & 1) !== 0 };
            }
            nextCloser = candidate;
        }
        return undefined;
    }

    public covers(name: DnsName): boolean {
        return isSubdomain(name, this.zone) && this.find(name) === undefined && this.cover(name) !== undefined;
    }
}

/**
 * Tries several denial proofs (an NSEC set and one NSEC3 set per distinct parameter set) and answers with the first that
 * proves the point. Unvalidated or foreign records never get here, so mixing is harmless.
 */
export class CompositeDenial implements DenialProof {
    private readonly proofs: DenialProof[];
    /** Set when NSEC3 records were dropped for parameters this library will not process (unknown hash, too many iterations). */
    public readonly unsupported: string | undefined;

    constructor(proofs: DenialProof[], unsupported?: string) {
        this.proofs = proofs;
        this.unsupported = unsupported;
    }

    public get empty(): boolean {
        return this.proofs.length === 0;
    }

    public matching(name: DnsName): Set<number> | undefined {
        for (const proof of this.proofs) {
            const found: Set<number> | undefined = proof.matching(name);
            if (found) {
                return found;
            }
        }
        return undefined;
    }

    public nonexistence(name: DnsName): { closestEncloser: DnsName; optOut: boolean } | undefined {
        for (const proof of this.proofs) {
            const found = proof.nonexistence(name);
            if (found) {
                return found;
            }
        }
        return undefined;
    }

    public covers(name: DnsName): boolean {
        return this.proofs.some((p) => p.covers(name));
    }
}
