///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { createHash, generateKeyPairSync, KeyObject, sign } from "node:crypto";
import { keyTag } from "../../../src/lib/dnssec/keys.js";
import {
    compareNames,
    isProperSubdomain,
    isSubdomain,
    nameToLabels,
    nameToWire,
    normalizeName,
    parentName,
    prependLabel,
} from "../../../src/lib/dnssec/name.js";
import { base32hexEncode } from "../../../src/lib/dnssec/nsec.js";
import { DnssecTransport, DsRecord } from "../../../src/lib/dnssec/types.js";
import { DnssecResolver, DnssecResolverOptions } from "../../../src/lib/dnssec/validator.js";

/**
 * A synthetic, fully signed DNS hierarchy for tests. It owns real keys, signs real RRsets and answers queries as a
 * `DnssecTransport` with real wire-format messages, so the resolver's codec, canonicalisation and denial logic are all
 * exercised. It knows nothing about the library's validator: signing and NSEC/NSEC3 construction are written independently.
 */

/** The resolver's clock in tests; every signature is valid around this moment. */
export const T0 = new Date("2026-06-01T00:00:00Z");
const INCEPTION = Math.floor(T0.getTime() / 1000) - 3600;
const EXPIRATION = Math.floor(T0.getTime() / 1000) + 30 * 86400;

export const T = {
    A: 1,
    NS: 2,
    CNAME: 5,
    SOA: 6,
    TXT: 16,
    MX: 15,
    DNAME: 39,
    DS: 43,
    RRSIG: 46,
    NSEC: 47,
    DNSKEY: 48,
    NSEC3: 50,
    NSEC3PARAM: 51,
    CAA: 257,
} as const;

export type KeyKind = "rsa256" | "rsa512" | "p256" | "p384" | "ed25519" | "ed448";

const ALGORITHM_OF: Record<KeyKind, number> = { rsa256: 8, rsa512: 10, p256: 13, p384: 14, ed25519: 15, ed448: 16 };

/** A signing key with its DNSKEY form. */
export interface TestKey {
    kind: KeyKind;
    algorithm: number;
    flags: number;
    /** DNSKEY RDATA. */
    rdata: Buffer;
    tag: number;
    sign(data: Buffer): Buffer;
}

/** Generates a key of the given kind; `flags` 257 makes a KSK, 256 a ZSK. */
export function makeKey(kind: KeyKind, flags: number): TestKey {
    let publicKey: KeyObject;
    let privateKey: KeyObject;
    let material: Buffer;
    switch (kind) {
        case "rsa256":
        case "rsa512": {
            ({ publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048, publicExponent: 65537 }));
            const jwk = publicKey.export({ format: "jwk" });
            const e: Buffer = Buffer.from(jwk.e as string, "base64url");
            material = Buffer.concat([Buffer.from([e.length]), e, Buffer.from(jwk.n as string, "base64url")]);
            break;
        }
        case "p256":
        case "p384": {
            ({ publicKey, privateKey } = generateKeyPairSync("ec", {
                namedCurve: kind === "p256" ? "P-256" : "P-384",
            }));
            const jwk = publicKey.export({ format: "jwk" });
            material = Buffer.concat([
                Buffer.from(jwk.x as string, "base64url"),
                Buffer.from(jwk.y as string, "base64url"),
            ]);
            break;
        }
        default: {
            ({ publicKey, privateKey } =
                kind === "ed25519" ? generateKeyPairSync("ed25519") : generateKeyPairSync("ed448"));
            material = Buffer.from(publicKey.export({ format: "jwk" }).x as string, "base64url");
        }
    }
    const algorithm: number = ALGORITHM_OF[kind];
    const header: Buffer = Buffer.alloc(4);
    header.writeUInt16BE(flags, 0);
    header[2] = 3;
    header[3] = algorithm;
    const rdata: Buffer = Buffer.concat([header, material]);
    return {
        kind,
        algorithm,
        flags,
        rdata,
        tag: keyTag(rdata),
        sign: (data: Buffer): Buffer => {
            switch (kind) {
                case "rsa256":
                    return sign("sha256", data, privateKey);
                case "rsa512":
                    return sign("sha512", data, privateKey);
                case "p256":
                    return sign("sha256", data, { key: privateKey, dsaEncoding: "ieee-p1363" });
                case "p384":
                    return sign("sha384", data, { key: privateKey, dsaEncoding: "ieee-p1363" });
                default:
                    return sign(null, data, privateKey);
            }
        },
    };
}

/** A resource record. Names are normalised (lower-case, no trailing dot, root is ""). */
export interface RR {
    name: string;
    type: number;
    ttl: number;
    rdata: Buffer;
}

/** What a zone answers, before wire encoding. Hooks may edit it freely. */
export interface TestResponse {
    rcode: number;
    answer: RR[];
    authority: RR[];
    additional?: RR[];
    /** Set the truncation bit (only useful together with a raw transport). */
    tc?: boolean;
}

/** Wire form of a name for RDATA (uncompressed, case preserved as given). */
export function wireName(name: string, keepCase = false): Buffer {
    if (!keepCase) {
        return nameToWire(name);
    }
    const parts: Buffer[] = [];
    for (const label of name === "" ? [] : name.split(".")) {
        parts.push(Buffer.from([label.length]), Buffer.from(label, "latin1"));
    }
    parts.push(Buffer.from([0]));
    return Buffer.concat(parts);
}

export function u16(value: number): Buffer {
    const b: Buffer = Buffer.alloc(2);
    b.writeUInt16BE(value, 0);
    return b;
}

export function caaRdata(flags: number, tag: string, value: string): Buffer {
    return Buffer.concat([Buffer.from([flags, tag.length]), Buffer.from(tag), Buffer.from(value)]);
}

export function aRdata(ip: string): Buffer {
    return Buffer.from(ip.split(".").map((n) => parseInt(n, 10)));
}

export function txtRdata(text: string): Buffer {
    return Buffer.concat([Buffer.from([text.length]), Buffer.from(text)]);
}

function soaRdata(zone: string): Buffer {
    const numbers: Buffer = Buffer.alloc(20);
    numbers.writeUInt32BE(1, 0);
    numbers.writeUInt32BE(7200, 4);
    numbers.writeUInt32BE(900, 8);
    numbers.writeUInt32BE(1209600, 12);
    numbers.writeUInt32BE(300, 16);
    return Buffer.concat([wireName(prependLabel("ns1", zone)), wireName(prependLabel("hostmaster", zone)), numbers]);
}

/** An NSEC/NSEC3 type bitmap. */
export function encodeBitmap(types: Iterable<number>): Buffer {
    const windows = new Map<number, Set<number>>();
    for (const type of types) {
        const window: number = type >> 8;
        windows.set(window, (windows.get(window) ?? new Set<number>()).add(type & 0xff));
    }
    const out: Buffer[] = [];
    for (const window of [...windows.keys()].sort((a, b) => a - b)) {
        const bits: number[] = [...(windows.get(window) as Set<number>)];
        const length: number = Math.max(...bits.map((b) => b >> 3)) + 1;
        const map: Buffer = Buffer.alloc(length);
        for (const bit of bits) {
            map[bit >> 3] |= 0x80 >> (bit & 7);
        }
        out.push(Buffer.from([window, length]), map);
    }
    return Buffer.concat(out);
}

/** The DS RDATA of a key. */
export function makeDs(zone: string, key: TestKey, digestType: 1 | 2 | 4 = 2): Buffer {
    const algorithm: string = digestType === 1 ? "sha1" : digestType === 2 ? "sha256" : "sha384";
    const digest: Buffer = createHash(algorithm).update(nameToWire(zone)).update(key.rdata).digest();
    const head: Buffer = Buffer.alloc(4);
    head.writeUInt16BE(key.tag, 0);
    head[2] = key.algorithm;
    head[3] = digestType;
    return Buffer.concat([head, digest]);
}

function nsec3Hash(name: string, salt: Buffer, iterations: number): Buffer {
    let digest: Buffer = createHash("sha1").update(nameToWire(name)).update(salt).digest();
    for (let i = 0; i < iterations; i++) {
        digest = createHash("sha1").update(digest).update(salt).digest();
    }
    return digest;
}

/** The canonical form of RDATA for signing: names of NS and CNAME lower-cased. */
function canonicalRdata(type: number, rdata: Buffer): Buffer {
    if (type === T.NS || type === T.CNAME) {
        return Buffer.from(rdata.map((b) => (b >= 0x41 && b <= 0x5a ? b + 0x20 : b)));
    }
    return rdata;
}

export interface SignOptions {
    inception?: number;
    expiration?: number;
    signer?: string;
    key?: TestKey;
    /** Overrides the LABELS field. */
    labels?: number;
    originalTtl?: number;
    /** Overrides the type covered stated in the RRSIG (the data signed is still the given RRset's). */
    typeCovered?: number;
}

/** Signs an RRset, returning the RRSIG record. `records` are the RRset's records (same owner and type). */
export function signRrset(zone: string, key: TestKey, records: RR[], options: SignOptions = {}): RR {
    const owner: string = records[0].name;
    const type: number = records[0].type;
    const ownerLabels: string[] = nameToLabels(owner);
    const labels: number = options.labels ?? ownerLabels.length - (ownerLabels[0] === "*" ? 1 : 0);
    const originalTtl: number = options.originalTtl ?? records[0].ttl;
    const signerKey: TestKey = options.key ?? key;
    const head: Buffer = Buffer.alloc(18);
    head.writeUInt16BE(options.typeCovered ?? type, 0);
    head[2] = signerKey.algorithm;
    head[3] = labels;
    head.writeUInt32BE(originalTtl, 4);
    head.writeUInt32BE(options.expiration ?? EXPIRATION, 8);
    head.writeUInt32BE(options.inception ?? INCEPTION, 12);
    head.writeUInt16BE(signerKey.tag, 16);
    const signerWire: Buffer = nameToWire(options.signer ?? zone);
    const canon: Buffer[] = records.map((r) => canonicalRdata(type, r.rdata)).sort((a, b) => Buffer.compare(a, b));
    const parts: Buffer[] = [head, signerWire];
    for (const rdata of canon) {
        const fixed: Buffer = Buffer.alloc(10);
        fixed.writeUInt16BE(type, 0);
        fixed.writeUInt16BE(1, 2);
        fixed.writeUInt32BE(originalTtl, 4);
        fixed.writeUInt16BE(rdata.length, 8);
        parts.push(nameToWire(owner), fixed, rdata);
    }
    const signature: Buffer = signerKey.sign(Buffer.concat(parts));
    return { name: owner, type: T.RRSIG, ttl: records[0].ttl, rdata: Buffer.concat([head, signerWire, signature]) };
}

/** How a zone proves non-existence. */
export type DenialKind = "nsec" | "nsec3" | "nsec3-optout" | "compact" | "unsigned";

export interface ZoneSpec {
    name: string;
    kind?: KeyKind;
    denial?: DenialKind;
    iterations?: number;
    salt?: Buffer;
    /** TTL of every record the zone makes itself (default 300). */
    ttl?: number;
    /** Signature expiration, seconds since the epoch (default: 30 days after T0). */
    expiration?: number;
}

interface NsecEntry {
    owner: string;
    next: string;
    rr: RR;
    sigs: RR[];
}

interface Nsec3Entry {
    hash: Buffer;
    rr: RR;
    sigs: RR[];
}

/** One zone of the hierarchy. */
export class TestZone {
    public readonly name: string;
    public readonly denial: DenialKind;
    public readonly ksk: TestKey;
    public readonly zsk: TestKey;
    /** Every key published in the DNSKEY RRset. */
    public keys: TestKey[];
    /** The keys that sign the DNSKEY RRset (a rollover may use several). */
    public dnskeySigners: TestKey[];
    public readonly iterations: number;
    public readonly salt: Buffer;
    public readonly ttl: number;
    public readonly expiration: number;
    public readonly rrsets = new Map<string, Map<number, RR[]>>();
    /** RRSIGs by `owner|type`. */
    public readonly sigs = new Map<string, RR[]>();
    private nsecs: NsecEntry[] = [];
    private nsec3s: Nsec3Entry[] = [];
    private built = false;

    constructor(spec: ZoneSpec) {
        this.name = spec.name;
        this.denial = spec.denial ?? "nsec";
        this.iterations = spec.iterations ?? 0;
        this.salt = spec.salt ?? Buffer.alloc(0);
        this.ttl = spec.ttl ?? 300;
        this.expiration = spec.expiration ?? EXPIRATION;
        const kind: KeyKind = spec.kind ?? "p256";
        this.ksk = makeKey(kind, 257);
        this.zsk = makeKey(kind, 256);
        this.keys = [this.ksk, this.zsk];
        this.dnskeySigners = [this.ksk];
    }

    public get signed(): boolean {
        return this.denial !== "unsigned";
    }

    /** Adds one record (or several RDATAs) to the zone. */
    public add(name: string, type: number, rdata: Buffer | Buffer[], ttl: number = this.ttl): void {
        const owner: string = name === "@" ? this.name : name;
        const set: Map<number, RR[]> = this.rrsets.get(owner) ?? new Map<number, RR[]>();
        this.rrsets.set(owner, set);
        const list: RR[] = set.get(type) ?? [];
        set.set(type, list);
        for (const r of Array.isArray(rdata) ? rdata : [rdata]) {
            list.push({ name: owner, type, ttl, rdata: r });
        }
    }

    /** A name relative to the zone. */
    public n(label: string): string {
        return label === "" ? this.name : prependLabel(label, this.name);
    }

    private isCut(name: string): boolean {
        return name !== this.name && (this.rrsets.get(name)?.has(T.NS) ?? false);
    }

    private existing(): Set<string> {
        const out = new Set<string>();
        for (const owner of this.rrsets.keys()) {
            let cursor: string = owner;
            while (isSubdomain(cursor, this.name)) {
                out.add(cursor);
                if (cursor === this.name) {
                    break;
                }
                cursor = parentName(cursor);
            }
        }
        return out;
    }

    private typesAt(name: string): number[] {
        return [...(this.rrsets.get(name)?.keys() ?? [])];
    }

    private sigsFor(name: string, type: number): RR[] {
        return this.sigs.get(`${name}|${type}`) ?? [];
    }

    /** Fills in the apex, builds the NSEC/NSEC3 chain and signs everything. Idempotent. */
    public build(): void {
        if (this.built) {
            return;
        }
        this.built = true;
        this.add(this.name, T.SOA, soaRdata(this.name));
        if (!this.rrsets.get(this.name)?.has(T.NS)) {
            this.add(this.name, T.NS, wireName(prependLabel("ns1", this.name)));
        }
        if (!this.signed) {
            return;
        }
        this.add(
            this.name,
            T.DNSKEY,
            this.keys.map((k) => k.rdata)
        );
        if (this.denial === "nsec3" || this.denial === "nsec3-optout") {
            const param: Buffer = Buffer.concat([
                Buffer.from([1, 0]),
                u16(this.iterations),
                Buffer.from([this.salt.length]),
                this.salt,
            ]);
            this.add(this.name, T.NSEC3PARAM, param);
        }
        this.buildChain();
        // Sign every authoritative RRset (not the delegation NS RRsets, which belong to the child).
        for (const [owner, set] of this.rrsets) {
            for (const [type, records] of set) {
                if (type === T.NS && this.isCut(owner)) {
                    continue;
                }
                const signers: TestKey[] = type === T.DNSKEY ? this.dnskeySigners : [this.zsk];
                this.sigs.set(
                    `${owner}|${type}`,
                    signers.map((k) => signRrset(this.name, k, records, { expiration: this.expiration }))
                );
            }
        }
    }

    private chainTypes(name: string): number[] {
        const types = new Set<number>(this.typesAt(name));
        if (this.isCut(name) && !types.has(T.DS)) {
            types.delete(T.RRSIG);
        } else if (types.size > 0) {
            types.add(T.RRSIG);
        }
        return [...types];
    }

    private buildChain(): void {
        if (this.denial === "compact") {
            return;
        }
        if (this.denial === "nsec") {
            const owners: string[] = [...this.rrsets.keys()].sort(compareNames);
            this.nsecs = owners.map((owner, i) => {
                const next: string = owners[(i + 1) % owners.length];
                const rdata: Buffer = Buffer.concat([
                    wireName(next),
                    encodeBitmap([...this.typesAt(owner), T.RRSIG, T.NSEC]),
                ]);
                const rr: RR = { name: owner, type: T.NSEC, ttl: this.ttl, rdata };
                return {
                    owner,
                    next,
                    rr,
                    sigs: [signRrset(this.name, this.zsk, [rr], { expiration: this.expiration })],
                };
            });
            for (const e of this.nsecs) {
                this.sigs.set(`${e.owner}|${T.NSEC}`, e.sigs);
            }
            return;
        }
        const optOut: boolean = this.denial === "nsec3-optout";
        const names: Set<string> = this.existing();
        const excluded = (name: string): boolean => optOut && this.isCut(name) && !this.rrsets.get(name)?.has(T.DS);
        const included: string[] = [...names].filter((name) => {
            if (excluded(name)) {
                return false;
            }
            // An empty non-terminal whose descendants are all opted out is not in the chain either.
            if (optOut && !this.rrsets.has(name) && name !== this.name) {
                return [...this.rrsets.keys()].some((o) => isProperSubdomain(o, name) && !excluded(o));
            }
            return true;
        });
        const hashed = included.map((name) => ({ name, hash: nsec3Hash(name, this.salt, this.iterations) }));
        hashed.sort((a, b) => Buffer.compare(a.hash, b.hash));
        this.nsec3s = hashed.map((entry, i) => {
            const next: Buffer = hashed[(i + 1) % hashed.length].hash;
            const types: number[] = this.chainTypes(entry.name);
            const rdata: Buffer = Buffer.concat([
                Buffer.from([1, optOut ? 1 : 0]),
                u16(this.iterations),
                Buffer.from([this.salt.length]),
                this.salt,
                Buffer.from([next.length]),
                next,
                encodeBitmap(types),
            ]);
            const owner: string = prependLabel(base32hexEncode(entry.hash), this.name);
            const rr: RR = { name: owner, type: T.NSEC3, ttl: this.ttl, rdata };
            return {
                hash: entry.hash,
                rr,
                sigs: [signRrset(this.name, this.zsk, [rr], { expiration: this.expiration })],
            };
        });
        for (const e of this.nsec3s) {
            this.sigs.set(`${e.rr.name}|${T.NSEC3}`, e.sigs);
        }
    }

    ///////////////////////////////////////////////////////////////////////////
    // Answering
    ///////////////////////////////////////////////////////////////////////////

    private withSigs(name: string, type: number): RR[] {
        const records: RR[] = (this.rrsets.get(name)?.get(type) ?? []).map((r) => ({
            ...r,
            rdata: Buffer.from(r.rdata),
        }));
        return [...records, ...this.sigsFor(name, type).map((s) => ({ ...s, rdata: Buffer.from(s.rdata) }))];
    }

    private soa(): RR[] {
        return this.withSigs(this.name, T.SOA);
    }

    private nsecMatch(name: string): RR[] {
        const entry: NsecEntry | undefined = this.nsecs.find((e) => e.owner === name);
        return entry ? [entry.rr, ...entry.sigs] : [];
    }

    private nsecCover(name: string): RR[] {
        const entry: NsecEntry | undefined = this.nsecs.find((e) => {
            if (e.owner === e.next) {
                return name !== e.owner;
            }
            if (compareNames(e.owner, e.next) < 0) {
                return compareNames(e.owner, name) < 0 && compareNames(name, e.next) < 0;
            }
            return compareNames(e.owner, name) < 0 || compareNames(name, e.next) < 0;
        });
        return entry ? [entry.rr, ...entry.sigs] : [];
    }

    private nsec3Match(name: string): RR[] {
        const hash: Buffer = nsec3Hash(name, this.salt, this.iterations);
        const entry: Nsec3Entry | undefined = this.nsec3s.find((e) => e.hash.equals(hash));
        return entry ? [entry.rr, ...entry.sigs] : [];
    }

    private nsec3Cover(name: string): RR[] {
        const hash: Buffer = nsec3Hash(name, this.salt, this.iterations);
        const index: number = this.nsec3s.findIndex((e, i) => {
            const next: Buffer = this.nsec3s[(i + 1) % this.nsec3s.length].hash;
            const order: number = Buffer.compare(e.hash, next);
            if (order < 0) {
                return Buffer.compare(e.hash, hash) < 0 && Buffer.compare(hash, next) < 0;
            }
            return Buffer.compare(e.hash, hash) < 0 || Buffer.compare(hash, next) < 0;
        });
        return index < 0 ? [] : [this.nsec3s[index].rr, ...this.nsec3s[index].sigs];
    }

    /** The NSEC3 closest-encloser proof for a name: the matching record of the closest encloser and the cover of the next closer. */
    private nsec3Proof(name: string): { records: RR[]; closestEncloser: string; nextCloser: string } {
        let nextCloser = "";
        let cursor: string = name;
        for (;;) {
            const match: RR[] = this.nsec3Match(cursor);
            if (match.length > 0 && cursor !== name) {
                return { records: [...match, ...this.nsec3Cover(nextCloser)], closestEncloser: cursor, nextCloser };
            }
            if (cursor === this.name) {
                throw new Error(`no closest encloser for ${name}`);
            }
            nextCloser = cursor;
            cursor = parentName(cursor);
        }
    }

    private uniq(records: RR[]): RR[] {
        const seen = new Set<string>();
        return records.filter((r) => {
            const key = `${r.name}|${r.type}|${r.rdata.toString("hex")}`;
            if (seen.has(key)) {
                return false;
            }
            seen.add(key);
            return true;
        });
    }

    /** Proof records for "name exists (has records or is an empty non-terminal) but has no data of the type". */
    private proveExists(name: string): RR[] {
        if (this.denial === "nsec") {
            const match: RR[] = this.nsecMatch(name);
            return match.length > 0 ? match : this.nsecCover(name);
        }
        const match: RR[] = this.nsec3Match(name);
        return match.length > 0 ? match : this.nsec3Proof(name).records;
    }

    private closestEncloser(name: string): string {
        const existing: Set<string> = this.existing();
        let cursor: string = parentName(name);
        while (!existing.has(cursor)) {
            cursor = parentName(cursor);
        }
        return cursor;
    }

    /** What this zone answers for a query it is authoritative for (delegated names never reach here except DS). */
    public respond(qname: string, qtype: number): TestResponse {
        const existing: Set<string> = this.existing();
        const authenticated = (records: RR[]): RR[] =>
            this.signed ? records : records.filter((r) => r.type !== T.RRSIG);
        const negative = (rcode: number, proof: RR[]): TestResponse => ({
            rcode,
            answer: [],
            authority: this.uniq(authenticated([...this.soa(), ...(this.signed ? proof : [])])),
        });
        if (this.denial === "compact") {
            return this.respondCompact(qname, qtype, existing);
        }
        if (existing.has(qname)) {
            const set: Map<number, RR[]> | undefined = this.rrsets.get(qname);
            if (set?.has(qtype)) {
                return { rcode: 0, answer: this.withSigs(qname, qtype), authority: [] };
            }
            if (set?.has(T.CNAME) && qtype !== T.CNAME) {
                return { rcode: 0, answer: this.withSigs(qname, T.CNAME), authority: [] };
            }
            return negative(0, this.signed ? this.proveExists(qname) : []);
        }
        const ce: string = this.closestEncloser(qname);
        const wildcard: string = prependLabel("*", ce);
        const wildcardSet: Map<number, RR[]> | undefined = this.rrsets.get(wildcard);
        if (wildcardSet) {
            const type: number | undefined = wildcardSet.has(qtype)
                ? qtype
                : wildcardSet.has(T.CNAME) && qtype !== T.CNAME
                  ? T.CNAME
                  : undefined;
            const proof: RR[] =
                this.denial === "nsec" ? this.nsecCover(qname) : this.signed ? this.nsec3Proof(qname).records : [];
            if (type !== undefined) {
                const answer: RR[] = this.withSigs(wildcard, type).map((r) => ({ ...r, name: qname }));
                return { rcode: 0, answer, authority: this.signed ? proof : [] };
            }
            const wildcardProof: RR[] = this.denial === "nsec" ? this.nsecMatch(wildcard) : this.nsec3Match(wildcard);
            return negative(0, [...proof, ...wildcardProof]);
        }
        if (!this.signed) {
            return negative(3, []);
        }
        if (this.denial === "nsec") {
            return negative(3, [...this.nsecCover(qname), ...this.nsecCover(wildcard)]);
        }
        const proof3 = this.nsec3Proof(qname);
        return negative(3, [...proof3.records, ...this.nsec3Cover(prependLabel("*", proof3.closestEncloser))]);
    }

    /**
     * Compact denial of existence (RFC 9824): online signing, every negative answer is NOERROR with an NSEC at the query name whose
     * next name is the name with a zero label prepended; a name that does not exist has the pseudo type NXNAME in its bitmap.
     */
    private respondCompact(qname: string, qtype: number, existing: Set<string>): TestResponse {
        const set: Map<number, RR[]> | undefined = this.rrsets.get(qname);
        if (existing.has(qname) && set?.has(qtype)) {
            return { rcode: 0, answer: this.withSigs(qname, qtype), authority: [] };
        }
        if (existing.has(qname) && set?.has(T.CNAME) && qtype !== T.CNAME) {
            return { rcode: 0, answer: this.withSigs(qname, T.CNAME), authority: [] };
        }
        const types: number[] = existing.has(qname)
            ? [...(set?.keys() ?? []), T.RRSIG, T.NSEC]
            : [T.RRSIG, T.NSEC, 128];
        const rr: RR = {
            name: qname,
            type: T.NSEC,
            ttl: this.ttl,
            rdata: Buffer.concat([Buffer.from([1, 0]), wireName(qname), encodeBitmap(types)]),
        };
        return {
            rcode: 0,
            answer: [],
            authority: [...this.soa(), rr, signRrset(this.name, this.zsk, [rr], { expiration: this.expiration })],
        };
    }

    /** The RRset (with its signatures) at a name, for tests that need to tamper with exact records. */
    public rrsetWithSigs(name: string, type: number): RR[] {
        return this.withSigs(name, type);
    }

    /** The NSEC record (with signatures) at a name, or the NSEC3 record matching it. */
    public proofAt(name: string): RR[] {
        return this.denial === "nsec" ? this.nsecMatch(name) : this.nsec3Match(name);
    }

    /** The NSEC/NSEC3 record covering a name. */
    public proofCovering(name: string): RR[] {
        return this.denial === "nsec" ? this.nsecCover(name) : this.nsec3Cover(name);
    }

    /** The record whose next name (hash) is the given name: what the real chain has just before it. */
    public proofPreceding(name: string): RR[] {
        if (this.denial === "nsec") {
            const entry = this.nsecs.find((e) => e.next === name);
            return entry ? [entry.rr, ...entry.sigs] : [];
        }
        const hash: Buffer = nsec3Hash(name, this.salt, this.iterations);
        const index: number = this.nsec3s.findIndex((_e, i) =>
            this.nsec3s[(i + 1) % this.nsec3s.length].hash.equals(hash)
        );
        return index < 0 ? [] : [this.nsec3s[index].rr, ...this.nsec3s[index].sigs];
    }

    /** The zone-private NSEC3 hash of a name. */
    public hash(name: string): Buffer {
        return nsec3Hash(name, this.salt, this.iterations);
    }
}

/** How a delegation's DS RRset is made. */
export interface DelegationOptions {
    /** `none` makes an unsigned delegation. Default: a SHA-256 DS of the child's KSK. */
    ds?: "sha256" | "sha384" | "sha1" | "none";
    /** Which of the child's keys get a DS (default: the KSK). */
    dsKeys?: TestKey[];
    /** Replaces the DS RDATA entirely. */
    dsRdata?: Buffer[];
}

/** The whole hierarchy: zones plus a `DnssecTransport` answering from them. */
export class TestWorld implements DnssecTransport {
    public readonly zones = new Map<string, TestZone>();
    /** Every question the resolver asked, in order. */
    public readonly queries: Array<{ name: string; type: number }> = [];
    /** Edits or replaces a response before it is encoded; returning bytes sends those bytes verbatim; throwing fails the query. */
    public hook?: (
        q: { name: string; type: number },
        response: TestResponse,
        zone: TestZone | undefined
    ) => Promise<Uint8Array | void> | Uint8Array | void;
    /** Whether the encoder compresses names. */
    public compress = true;

    public add(spec: ZoneSpec): TestZone {
        const zone = new TestZone(spec);
        this.zones.set(zone.name, zone);
        return zone;
    }

    /** Delegates `child` from `parent`: NS and (unless unsigned) DS records in the parent. */
    public delegate(parent: TestZone, child: TestZone, options: DelegationOptions = {}): void {
        parent.add(child.name, T.NS, wireName(prependLabel("ns1", child.name)));
        if (options.dsRdata) {
            parent.add(child.name, T.DS, options.dsRdata);
            return;
        }
        const kind: string = options.ds ?? "sha256";
        if (kind === "none" || !child.signed) {
            return;
        }
        const type: 1 | 2 | 4 = kind === "sha1" ? 1 : kind === "sha384" ? 4 : 2;
        parent.add(
            child.name,
            T.DS,
            (options.dsKeys ?? [child.ksk]).map((k) => makeDs(child.name, k, type))
        );
    }

    public build(): void {
        for (const zone of this.zones.values()) {
            zone.build();
        }
    }

    /** The trust anchors matching the root zone's KSK. */
    public anchors(): DsRecord[] {
        const root: TestZone = this.zones.get("") as TestZone;
        const ds: Buffer = makeDs("", root.ksk, 2);
        return [{ keyTag: root.ksk.tag, algorithm: root.ksk.algorithm, digestType: 2, digest: ds.subarray(4) }];
    }

    /** The zone answering a query: the deepest one containing the name (for DS, one strictly above it). */
    public zoneFor(name: string, type: number): TestZone | undefined {
        let best: TestZone | undefined;
        for (const zone of this.zones.values()) {
            if (!isSubdomain(name, zone.name) || (type === T.DS && zone.name === name)) {
                continue;
            }
            if (!best || nameToLabels(zone.name).length > nameToLabels(best.name).length) {
                best = zone;
            }
        }
        return best;
    }

    public async query(question: { name: string; type: number }): Promise<Uint8Array> {
        const name: string = normalizeName(question.name);
        const q = { name, type: question.type };
        this.queries.push(q);
        const zone: TestZone | undefined = this.zoneFor(name, question.type);
        const response: TestResponse = zone
            ? zone.respond(name, question.type)
            : { rcode: 2, answer: [], authority: [] };
        const replaced: Uint8Array | void = await this.hook?.(q, response, zone);
        if (replaced) {
            return replaced;
        }
        return encodeMessage(name, question.type, response, this.compress);
    }
}

/** Finds the RRSIG(s) covering `type` at `name` in a record list. */
export function sigsOf(records: RR[], name: string, type: number): RR[] {
    return records.filter((r) => r.type === T.RRSIG && r.name === name && r.rdata.readUInt16BE(0) === type);
}

/** Finds the records of a type at a name. */
export function recordsOf(records: RR[], name: string, type: number): RR[] {
    return records.filter((r) => r.type === type && r.name === name);
}

/** Flips one bit in the signature part of an RRSIG record. */
export function corrupt(sig: RR): void {
    sig.rdata[sig.rdata.length - 3] ^= 0x01;
}

///////////////////////////////////////////////////////////////////////////////
// Wire encoding (independent of the library's codec)
///////////////////////////////////////////////////////////////////////////////

function readWireName(rdata: Buffer, offset: number): { name: string; end: number } {
    const labels: string[] = [];
    let at: number = offset;
    while (rdata[at] !== 0) {
        labels.push(rdata.subarray(at + 1, at + 1 + rdata[at]).toString("latin1"));
        at += 1 + rdata[at];
    }
    return { name: labels.join("."), end: at + 1 };
}

class Writer {
    public readonly bytes: number[] = [];
    private readonly offsets = new Map<string, number>();

    constructor(private readonly compress: boolean) {}

    public u8(value: number): void {
        this.bytes.push(value & 0xff);
    }

    public u16(value: number): void {
        this.bytes.push((value >> 8) & 0xff, value & 0xff);
    }

    public u32(value: number): void {
        this.u16(Math.floor(value / 65536));
        this.u16(value % 65536);
    }

    public raw(data: Uint8Array): void {
        for (const b of data) {
            this.bytes.push(b);
        }
    }

    /** Writes a name (raw labels split on dots), compressing against earlier ones. */
    public name(name: string): void {
        const labels: string[] = name === "" ? [] : name.split(".");
        for (let i = 0; i < labels.length; i++) {
            const suffix: string = labels.slice(i).join(".").toLowerCase();
            const known: number | undefined = this.compress ? this.offsets.get(suffix) : undefined;
            if (known !== undefined) {
                this.u16(0xc000 | known);
                return;
            }
            if (this.bytes.length < 0x3fff) {
                this.offsets.set(suffix, this.bytes.length);
            }
            this.u8(labels[i].length);
            this.raw(Buffer.from(labels[i], "latin1"));
        }
        this.u8(0);
    }
}

function writeRecord(w: Writer, rr: RR): void {
    w.name(rr.name);
    w.u16(rr.type);
    w.u16(1);
    w.u32(rr.ttl);
    const lengthAt: number = w.bytes.length;
    w.u16(0);
    if (rr.type === T.NS || rr.type === T.CNAME) {
        w.name(readWireName(rr.rdata, 0).name);
    } else if (rr.type === T.SOA) {
        const a = readWireName(rr.rdata, 0);
        const b = readWireName(rr.rdata, a.end);
        w.name(a.name);
        w.name(b.name);
        w.raw(rr.rdata.subarray(b.end));
    } else {
        w.raw(rr.rdata);
    }
    const length: number = w.bytes.length - lengthAt - 2;
    w.bytes[lengthAt] = (length >> 8) & 0xff;
    w.bytes[lengthAt + 1] = length & 0xff;
}

/** Encodes a response to `qname`/`qtype` as a real DNS message with an EDNS0 OPT record. */
export function encodeMessage(
    qname: string,
    qtype: number,
    response: TestResponse,
    compress = true,
    id = 0x1234
): Buffer {
    const w = new Writer(compress);
    const additional: RR[] = response.additional ?? [];
    w.u16(id);
    w.u16(0x8000 | 0x0400 | 0x0080 | (response.tc ? 0x0200 : 0) | (response.rcode & 0xf));
    w.u16(1);
    w.u16(response.answer.length);
    w.u16(response.authority.length);
    w.u16(additional.length + 1);
    w.name(qname);
    w.u16(qtype);
    w.u16(1);
    for (const rr of [...response.answer, ...response.authority, ...additional]) {
        writeRecord(w, rr);
    }
    w.u8(0);
    w.u16(41);
    w.u16(1232);
    w.u32(0x8000);
    w.u16(0);
    return Buffer.from(w.bytes);
}

///////////////////////////////////////////////////////////////////////////////
// The standard hierarchy
///////////////////////////////////////////////////////////////////////////////

/** The named zones of {@link buildStandardWorld}. */
export interface StandardWorld {
    world: TestWorld;
    root: TestZone;
    com: TestZone;
    net: TestZone;
    org: TestZone;
    /** A TLD with no DS at the root: everything below is unsigned. */
    insecureTld: TestZone;
    example: TestZone;
    p384: TestZone;
    ed25519: TestZone;
    ed448: TestZone;
    rsa: TestZone;
    rsa512: TestZone;
    unsignedCom: TestZone;
    unsignedNet: TestZone;
    unsignedOrg: TestZone;
    secureNet: TestZone;
    secureOrg: TestZone;
    roll: TestZone;
    sha384: TestZone;
    unsupported: TestZone;
    below: TestZone;
    /** Has a wildcard at its apex level and an empty non-terminal beneath it that the wildcard must not cover. */
    wc: TestZone;
    /** NSEC3 with more iterations than the library will compute. */
    iter: TestZone;
    /** Online signing with compact denial of existence (NXNAME). */
    compact: TestZone;
}

/**
 * Builds the hierarchy the tests share: a root (NSEC), `com` (NSEC3 with opt-out), `net` (NSEC), `org` (NSEC3, iterations and salt
 * as in RFC 5155's example), an unsigned TLD, and below them signed second-level zones of every algorithm plus unsigned
 * delegations of each kind of proof.
 */
export function buildStandardWorld(): StandardWorld {
    const world = new TestWorld();
    const root: TestZone = world.add({ name: "", denial: "nsec" });
    const com: TestZone = world.add({
        name: "com",
        denial: "nsec3-optout",
        iterations: 3,
        salt: Buffer.from("aabbccdd", "hex"),
    });
    const net: TestZone = world.add({ name: "net", denial: "nsec" });
    const org: TestZone = world.add({
        name: "org",
        denial: "nsec3",
        iterations: 12,
        salt: Buffer.from("aabbccdd", "hex"),
    });
    const insecureTld: TestZone = world.add({ name: "insecure", denial: "unsigned" });
    world.delegate(root, com);
    world.delegate(root, net);
    world.delegate(root, org);
    world.delegate(root, insecureTld, { ds: "none" });

    const example: TestZone = world.add({ name: "example.com", denial: "nsec" });
    const p384: TestZone = world.add({
        name: "p384.com",
        kind: "p384",
        denial: "nsec3",
        iterations: 1,
        salt: Buffer.from("00ff", "hex"),
    });
    const ed25519: TestZone = world.add({ name: "ed25519.com", kind: "ed25519", denial: "nsec3-optout" });
    const ed448: TestZone = world.add({ name: "ed448.com", kind: "ed448", denial: "nsec" });
    const rsa: TestZone = world.add({ name: "rsa.com", kind: "rsa256", denial: "nsec" });
    const rsa512: TestZone = world.add({ name: "rsa512.com", kind: "rsa512", denial: "nsec3" });
    const unsignedCom: TestZone = world.add({ name: "unsigned.com", denial: "unsigned" });
    const roll: TestZone = world.add({ name: "roll.com", denial: "nsec" });
    const sha384: TestZone = world.add({ name: "sha384.com", denial: "nsec" });
    const unsupported: TestZone = world.add({ name: "unsupported.com", denial: "unsigned" });
    const secureNet: TestZone = world.add({ name: "secure.net", denial: "nsec" });
    const unsignedNet: TestZone = world.add({ name: "unsigned.net", denial: "unsigned" });
    const secureOrg: TestZone = world.add({ name: "secure.org", denial: "nsec3", iterations: 2 });
    const unsignedOrg: TestZone = world.add({ name: "unsigned.org", denial: "unsigned" });
    const below: TestZone = world.add({ name: "below.example.insecure", denial: "unsigned" });
    const wc: TestZone = world.add({ name: "wc.com", denial: "nsec" });
    const iter: TestZone = world.add({ name: "iter.com", denial: "nsec3", iterations: 501 });
    const compact: TestZone = world.add({ name: "compact.com", denial: "compact" });
    for (const child of [example, p384, ed25519, ed448, rsa, rsa512, wc, iter, compact]) {
        world.delegate(com, child);
    }
    world.delegate(com, sha384, { ds: "sha384" });
    world.delegate(com, unsignedCom, { ds: "none" });
    // A DS RRset of which nothing is usable: algorithm 5 with SHA-1, and algorithm 8 with the unsupported GOST digest (3).
    world.delegate(com, unsupported, {
        dsRdata: [
            Buffer.concat([u16(1234), Buffer.from([5, 1]), Buffer.alloc(20, 7)]),
            Buffer.concat([u16(4321), Buffer.from([8, 3]), Buffer.alloc(32, 9)]),
        ],
    });
    world.delegate(net, secureNet);
    world.delegate(net, unsignedNet, { ds: "none" });
    world.delegate(org, secureOrg);
    world.delegate(org, unsignedOrg, { ds: "none" });

    // Rollover: two KSKs and two ZSKs are published, both KSKs sign the DNSKEY RRset, the parent's DS names only the new KSK.
    const newKsk: TestKey = makeKey("p256", 257);
    const newZsk: TestKey = makeKey("p256", 256);
    roll.keys = [roll.ksk, newKsk, roll.zsk, newZsk];
    roll.dnskeySigners = [roll.ksk, newKsk];
    world.delegate(com, roll, { dsKeys: [newKsk] });

    for (const zone of [
        example,
        p384,
        ed25519,
        ed448,
        rsa,
        rsa512,
        wc,
        iter,
        compact,
        unsignedCom,
        roll,
        sha384,
        unsupported,
        secureNet,
        unsignedNet,
        secureOrg,
        unsignedOrg,
        below,
    ]) {
        zone.add("@", T.CAA, caaRdata(0, "issue", `ca.${zone.name}`));
        zone.add(zone.n("host"), T.A, aRdata("192.0.2.1"));
    }
    world.delegate(insecureTld, below, { ds: "none" });
    insecureTld.add("@", T.CAA, caaRdata(0, "issue", "ca.insecure"));

    // example.com: a wildcard, an empty non-terminal, CNAMEs (chained, cross-zone, to an unsigned zone, looping) and a name with a TXT.
    example.add("*.wild.example.com", T.CAA, caaRdata(0, "issue", "wild.test"));
    example.add("*.wild.example.com", T.TXT, txtRdata("wildcard"));
    example.add("*.cwild.example.com", T.CNAME, wireName("host.example.com"));
    example.add("x.ent.example.com", T.A, aRdata("192.0.2.2"));
    example.add("www.example.com", T.CNAME, wireName("host.example.com"));
    example.add("c1.example.com", T.CNAME, wireName("c2.example.com"));
    example.add("c2.example.com", T.CNAME, wireName("c3.example.com"));
    example.add("c3.example.com", T.CAA, caaRdata(0, "issue", "chained.test"));
    example.add("xz.example.com", T.CNAME, wireName("host.p384.com"));
    example.add("toinsecure.example.com", T.CNAME, wireName("host.unsigned.com"));
    example.add("loop1.example.com", T.CNAME, wireName("loop2.example.com"));
    example.add("loop2.example.com", T.CNAME, wireName("loop1.example.com"));
    example.add("mixed.example.com", T.CNAME, wireName("Host.Example.COM", true));
    example.add("txt.example.com", T.TXT, txtRdata("hello"));
    example.add("hinfo.example.com", 13, Buffer.from([1, 65, 1, 66]));
    wc.add("*.wc.com", T.TXT, txtRdata("top"));
    wc.add("sub.mid.wc.com", T.A, aRdata("192.0.2.4"));
    example.add("mx.example.com", T.MX, Buffer.concat([u16(10), wireName("host.example.com")]));
    // A signed CNAME at the apex of the delegation-free part, and a name that has both a wildcard sibling and data.
    example.add("a.wild.example.com", T.A, aRdata("192.0.2.3"));
    for (const zone of [p384, ed25519, rsa, rsa512, secureOrg, secureNet]) {
        zone.add("*.wild." + zone.name, T.CAA, caaRdata(0, "issue", "wild.test"));
        zone.add("x.ent." + zone.name, T.A, aRdata("192.0.2.2"));
    }
    // A delegation-less deep name for opt-out tests.
    world.build();
    return {
        world,
        root,
        com,
        net,
        org,
        insecureTld,
        example,
        p384,
        ed25519,
        ed448,
        rsa,
        rsa512,
        unsignedCom,
        unsignedNet,
        unsignedOrg,
        secureNet,
        secureOrg,
        roll,
        sha384,
        unsupported,
        below,
        wc,
        iter,
        compact,
    };
}

/** A resolver wired to a test world: its transport, anchors and clock, without caching unless asked. */
export function makeResolver(world: TestWorld, overrides: Partial<DnssecResolverOptions> = {}): DnssecResolver {
    return new DnssecResolver({
        transport: world,
        trustAnchors: world.anchors(),
        now: () => T0,
        servers: ["192.0.2.53"],
        cacheSeconds: 0,
        ...overrides,
    });
}
