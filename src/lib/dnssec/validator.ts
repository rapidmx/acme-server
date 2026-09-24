///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { createHash } from "node:crypto";
import { getServers } from "node:dns";
import { dsDigestBytes, dsMatches, FLAG_REVOKE, FLAG_ZONE, isSupportedDs, parseDnskey, parseDs } from "./keys.js";
import { DnsName, labelCount, labelsToName, nameToLabels, normalizeName, prependLabel, toFqdn } from "./name.js";
import {
    CompositeDenial,
    DenialProof,
    MAX_NSEC3_ITERATIONS,
    Nsec3Denial,
    Nsec3Record,
    NsecDenial,
    NsecRecord,
    parseNsec,
    parseNsec3,
} from "./nsec.js";
import { RrsetValidation, TrustedKey, validateRrset } from "./rrset.js";
import { DnssecUdpTcpTransport } from "./transport.js";
import {
    bogus,
    CaaRdata,
    CLASS_IN,
    DnssecError,
    DnssecStatus,
    DnssecTransport,
    DsRecord,
    indeterminate,
    RRTYPE,
} from "./types.js";
import { DnsMessage, DnsRecord, parseMessage, readPlainName } from "./wire.js";

/**
 * The IANA root zone's key signing keys as DS records (https://data.iana.org/root-anchors/root-anchors.xml): KSK-2017 (key
 * tag 20326) and KSK-2024 (key tag 38696). Both were checked against the live root DNSKEY RRset and against IANA's published
 * digests when this library was written.
 */
export const IANA_ROOT_TRUST_ANCHORS: readonly DsRecord[] = [
    {
        keyTag: 20326,
        algorithm: 8,
        digestType: 2,
        digest: "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
    },
    {
        keyTag: 38696,
        algorithm: 8,
        digestType: 2,
        digest: "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
    },
];

/** Options of the {@link DnssecResolver}. */
export interface DnssecResolverOptions {
    /** Recursive resolvers to ask; they are only a transport. Defaults to the system's (`dns.getServers()`). */
    servers?: string[];
    /** Per-query timeout in milliseconds (default 4000). */
    timeoutMs?: number;
    /** The clock used for signature validity (default `new Date()`). */
    now?: () => Date;
    /** The trust anchors (default: the IANA root KSKs). */
    trustAnchors?: DsRecord[];
    /** How DNS messages travel (default: UDP with a TCP fallback). */
    transport?: DnssecTransport;
    /** The most queries one `resolve()` call may send (default 40); more is `indeterminate`. */
    maxQueries?: number;
    /** The longest CNAME chain followed (default 8). */
    maxCnameDepth?: number;
    /** How long validated zone keys and DS verdicts are reused, bounded by signature expiry and TTLs (default 300; 0 disables). */
    cacheSeconds?: number;
}

/** The outcome of a validated lookup. */
export interface DnssecResult {
    status: DnssecStatus;
    /** The raw RDATA of every record of the RRset (empty for NODATA and NXDOMAIN). */
    rdata: Uint8Array[];
    nxdomain: boolean;
}

/** A zone whose DNSKEY RRset has been validated to the trust anchor. */
interface ZoneInfo {
    name: DnsName;
    keys: TrustedKey[];
    expiresAt: number;
}

/** What asking the parent zone for the DS of a child name established. */
type DsVerdict = { kind: "zone"; zone: ZoneInfo } | { kind: "insecure" } | { kind: "same" } | { kind: "nonexistent" };

interface CacheEntry {
    value: unknown;
    expiresAt: number;
}

/** A small bounded map whose entries die at a stated moment, the latest a signature stays valid. */
class VerdictCache {
    private static readonly MAX_ENTRIES = 4096;
    private readonly entries = new Map<string, CacheEntry>();

    public get<T>(key: string, nowMs: number): T | undefined {
        const entry: CacheEntry | undefined = this.entries.get(key);
        if (!entry) {
            return undefined;
        }
        if (nowMs >= entry.expiresAt) {
            this.entries.delete(key);
            return undefined;
        }
        return entry.value as T;
    }

    public set(key: string, value: unknown, expiresAt: number): void {
        if (this.entries.size >= VerdictCache.MAX_ENTRIES) {
            const oldest: string | undefined = this.entries.keys().next().value;
            if (oldest !== undefined) {
                this.entries.delete(oldest);
            }
        }
        this.entries.set(key, { value, expiresAt });
    }
}

interface Context {
    queries: number;
    cache: VerdictCache;
}

/** The most NSEC/NSEC3 RRsets examined per response (a legitimate proof has at most five). */
const MAX_PROOF_RRSETS = 16;
/** The most DNSKEY records accepted in a zone's key set. */
const MAX_DNSKEYS = 32;

function isDelegation(types: Set<number>): boolean {
    return types.has(RRTYPE.NS) && !types.has(RRTYPE.SOA);
}

function weakest(a: DnssecStatus, b: DnssecStatus): DnssecStatus {
    return a === "insecure" || b === "insecure" ? "insecure" : "secure";
}

function toDnssecError(err: unknown): DnssecError {
    if (err instanceof DnssecError) {
        return err;
    }
    return indeterminate(`unexpected failure: ${err instanceof Error ? err.message : String(err)}`);
}

/**
 * A DNSSEC-validating stub resolver.
 *
 * It fetches records from ordinary recursive resolvers but trusts nothing they say: every answer is validated here, from the
 * trust anchor down (RFC 4033, 4034, 4035, 5155). The recursive resolvers' AD bit is never consulted, and queries set CD so
 * they do not withhold data they consider bogus. A lookup either yields a `secure` result (an unbroken chain of signatures
 * and authenticated denials), an `insecure` one (a validated proof that a delegation on the path is unsigned, so the unsigned
 * answer is taken as it is) or throws a {@link DnssecError}. Anything not provably fine fails closed.
 *
 * @author Jean-Philippe Steinmetz
 */
export class DnssecResolver {
    private readonly servers: string[];
    private readonly timeoutMs: number;
    private readonly clock: () => Date;
    private readonly anchors: DsRecord[];
    private readonly transport: DnssecTransport;
    private readonly maxQueries: number;
    private readonly maxCnameDepth: number;
    private readonly cacheSeconds: number;
    private readonly anchorId: string;
    /** Shared by every `resolve()` call of this instance. It lives and dies with its trust anchors, and is keyed on them. */
    private readonly cache = new VerdictCache();

    constructor(o: DnssecResolverOptions = {}) {
        const system: string[] = o.servers ?? getServers();
        this.servers = system.length > 0 ? system : ["8.8.8.8", "1.1.1.1"];
        this.timeoutMs = o.timeoutMs ?? 4000;
        this.clock = o.now ?? ((): Date => new Date());
        this.anchors = o.trustAnchors ? [...o.trustAnchors] : [...IANA_ROOT_TRUST_ANCHORS];
        this.transport = o.transport ?? new DnssecUdpTcpTransport();
        this.maxQueries = o.maxQueries ?? 40;
        this.maxCnameDepth = o.maxCnameDepth ?? 8;
        this.cacheSeconds = o.cacheSeconds ?? 300;
        const hash = createHash("sha256");
        for (const anchor of this.anchors) {
            hash.update(`${anchor.keyTag}/${anchor.algorithm}/${anchor.digestType}/`).update(dsDigestBytes(anchor));
        }
        this.anchorId = hash.digest("hex").slice(0, 16);
    }

    /**
     * Validated CAA lookup for exactly `name` (no tree climbing: the caller climbs). NXDOMAIN and NODATA are both an empty
     * `records`, but validated.
     *
     * @throws {@link DnssecError} `bogus` when validation fails, `indeterminate` when no usable answer could be had.
     */
    public async resolveCaa(name: string): Promise<{ status: DnssecStatus; records: CaaRdata[] }> {
        const result: DnssecResult = await this.resolve(name, RRTYPE.CAA);
        const records: CaaRdata[] = result.rdata.map((raw) => {
            const rdata: Buffer = Buffer.from(raw);
            if (rdata.length < 2 || rdata[1] === 0 || 2 + rdata[1] > rdata.length) {
                throw indeterminate("a CAA record in the answer is malformed");
            }
            return {
                critical: rdata[0],
                tag: rdata.subarray(2, 2 + rdata[1]).toString("latin1"),
                value: rdata.subarray(2 + rdata[1]).toString("utf8"),
            };
        });
        return { status: result.status, records };
    }

    /**
     * Validates the RRset of `type` at `name` and returns the raw RDATA of each record. CNAMEs are followed (each hop is
     * validated with a fresh chain of trust and the status is the weakest of the chain); DNAME is not supported.
     *
     * @throws {@link DnssecError} `bogus` when validation fails, `indeterminate` when no usable answer could be had.
     */
    public async resolve(name: string, type: number): Promise<DnssecResult> {
        try {
            const qname: DnsName = normalizeName(name);
            const ctx: Context = { queries: 0, cache: this.cacheSeconds > 0 ? this.cache : new VerdictCache() };
            return await this.lookup(ctx, qname, type, 0);
        } catch (err: unknown) {
            throw toDnssecError(err);
        }
    }

    ///////////////////////////////////////////////////////////////////////////
    // Transport
    ///////////////////////////////////////////////////////////////////////////

    /** Asks the transport one question and checks the response is a well-formed, usable answer to it. */
    private async fetch(ctx: Context, name: DnsName, type: number): Promise<DnsMessage> {
        if (++ctx.queries > this.maxQueries) {
            throw indeterminate(`query budget of ${this.maxQueries} exhausted`);
        }
        let raw: Uint8Array;
        try {
            raw = await this.transport.query(
                { name: toFqdn(name), type },
                { servers: this.servers, timeoutMs: this.timeoutMs }
            );
        } catch (err: unknown) {
            throw indeterminate(
                `query for ${name || "."} type ${type} failed: ${err instanceof Error ? err.message : String(err)}`
            );
        }
        const message: DnsMessage = parseMessage(raw);
        if (!message.qr || message.opcode !== 0) {
            throw indeterminate("the response is not a query response");
        }
        const q = message.question[0];
        if (message.question.length !== 1 || q.name !== name || q.type !== type || q.cls !== CLASS_IN) {
            throw indeterminate("the response does not answer the question asked");
        }
        if (message.tc) {
            throw indeterminate("the response is truncated");
        }
        if (message.rcode !== 0 && message.rcode !== 3) {
            throw indeterminate(`the resolver answered with RCODE ${message.rcode}`);
        }
        return message;
    }

    ///////////////////////////////////////////////////////////////////////////
    // Chain of trust
    ///////////////////////////////////////////////////////////////////////////

    private nowMs(): number {
        return this.clock().getTime();
    }

    /** The moment a verdict may be reused until: bounded by signatures, TTLs and the configured cache time. */
    private bound(validations: RrsetValidation[], parent?: ZoneInfo): number {
        const seconds: number = this.cacheSeconds > 0 ? this.cacheSeconds : 60;
        const ttl: number = Math.min(seconds, ...validations.map((v) => v.ttl));
        return Math.min(
            this.nowMs() + ttl * 1000,
            ...validations.map((v) => v.expiresAt),
            parent ? parent.expiresAt : Number.POSITIVE_INFINITY
        );
    }

    private async rootZone(ctx: Context): Promise<ZoneInfo> {
        const key = `${this.anchorId}|root`;
        const cached: ZoneInfo | undefined = ctx.cache.get<ZoneInfo>(key, this.nowMs());
        if (cached) {
            return cached;
        }
        if (!this.anchors.some(isSupportedDs)) {
            throw indeterminate("no usable trust anchor");
        }
        const zone: ZoneInfo = await this.establishZone(ctx, "", this.anchors);
        ctx.cache.set(key, zone, zone.expiresAt);
        return zone;
    }

    /**
     * Fetches and validates a zone's DNSKEY RRset against the DS records (or trust anchors) that vouch for it (RFC 4035
     * section 5.2): a zone key must hash to a usable DS and the whole RRset must be signed by that very key.
     */
    private async establishZone(
        ctx: Context,
        zoneName: DnsName,
        dsList: DsRecord[],
        parent?: ZoneInfo
    ): Promise<ZoneInfo> {
        const label: string = zoneName || ".";
        const message: DnsMessage = await this.fetch(ctx, zoneName, RRTYPE.DNSKEY);
        const records: DnsRecord[] = rrsetOf(message.answer, zoneName, RRTYPE.DNSKEY);
        if (records.length === 0) {
            if (zoneName === "") {
                throw indeterminate("the root DNSKEY RRset was not returned");
            }
            throw bogus(`zone ${label} has a DS record but publishes no DNSKEY`);
        }
        if (records.length > MAX_DNSKEYS) {
            throw bogus(`zone ${label} publishes too many DNSKEY records`);
        }
        const keys: TrustedKey[] = [];
        for (const record of records) {
            const key: TrustedKey | undefined = parseDnskey(record.rdata);
            if (key && key.protocol === 3 && (key.flags & FLAG_ZONE) !== 0 && (key.flags & FLAG_REVOKE) === 0) {
                keys.push(key);
            }
        }
        const entries: TrustedKey[] = keys.filter((k) =>
            dsList.some((ds) => isSupportedDs(ds) && dsMatches(zoneName, k, ds))
        );
        if (entries.length === 0) {
            throw bogus(`no DNSKEY of zone ${label} matches its DS record`);
        }
        const sigs: DnsRecord[] = message.answer.filter((r) => r.type === RRTYPE.RRSIG);
        let failure: DnssecError | undefined;
        for (const entry of entries) {
            try {
                const validation: RrsetValidation = validateRrset({
                    name: zoneName,
                    type: RRTYPE.DNSKEY,
                    records,
                    sigs,
                    zone: zoneName,
                    keys: [entry],
                    now: this.clock(),
                });
                return { name: zoneName, keys, expiresAt: this.bound([validation], parent) };
            } catch (err: unknown) {
                if (!(err instanceof DnssecError) || err.kind !== "bogus") {
                    throw err;
                }
                failure = err;
            }
        }
        throw bogus(
            `the DNSKEY RRset of zone ${label} is not signed by the key its DS vouches for (${failure?.reason})`
        );
    }

    /**
     * Establishes what the DS query for `name` (a child name of the secure `zone`) tells: a secure child zone, a proven
     * unsigned delegation, a name that is no zone cut, or a name that does not exist.
     */
    private async dsVerdict(ctx: Context, zone: ZoneInfo, name: DnsName): Promise<DsVerdict> {
        const key = `${this.anchorId}|ds|${name}`;
        const cached: DsVerdict | undefined = ctx.cache.get<DsVerdict>(key, this.nowMs());
        if (cached) {
            return cached;
        }
        const [verdict, expiresAt] = await this.queryDs(ctx, zone, name);
        ctx.cache.set(key, verdict, expiresAt);
        return verdict;
    }

    private async queryDs(ctx: Context, zone: ZoneInfo, name: DnsName): Promise<[DsVerdict, number]> {
        const message: DnsMessage = await this.fetch(ctx, name, RRTYPE.DS);
        const answerSigs: DnsRecord[] = message.answer.filter((r) => r.type === RRTYPE.RRSIG);
        const ds: DnsRecord[] = rrsetOf(message.answer, name, RRTYPE.DS);
        if (ds.length > 0) {
            const validation: RrsetValidation = validateRrset({
                name,
                type: RRTYPE.DS,
                records: ds,
                sigs: answerSigs,
                zone: zone.name,
                keys: zone.keys,
                now: this.clock(),
            });
            const parsed: DsRecord[] = ds.map((r) => parseDs(r.rdata)).filter((d): d is DsRecord => d !== undefined);
            if (parsed.length === 0) {
                throw bogus(`the DS RRset of ${name} is malformed`);
            }
            const usable: DsRecord[] = parsed.filter(isSupportedDs);
            if (usable.length === 0) {
                // RFC 4035 section 5.2: a zone whose every DS names an algorithm or digest the validator lacks is treated as unsigned.
                return [{ kind: "insecure" }, this.bound([validation], zone)];
            }
            const child: ZoneInfo = await this.establishZone(ctx, name, usable, zone);
            return [{ kind: "zone", zone: child }, Math.min(child.expiresAt, this.bound([validation], zone))];
        }
        const cname: DnsRecord[] = rrsetOf(message.answer, name, RRTYPE.CNAME);
        if (cname.length > 0) {
            // A CNAME cannot coexist with a delegation, so a validated one shows that the name is not a zone cut.
            const validation: RrsetValidation = validateRrset({
                name,
                type: RRTYPE.CNAME,
                records: cname,
                sigs: answerSigs,
                zone: zone.name,
                keys: zone.keys,
                now: this.clock(),
            });
            return [{ kind: "same" }, this.bound([validation], zone)];
        }
        const proof = this.buildDenial(zone, [...message.answer, ...message.authority]);
        const types: Set<number> | undefined = proof.denial.matching(name);
        if (types) {
            if (types.has(RRTYPE.DS)) {
                throw bogus(`the DS answer for ${name} was withheld: its own record says a DS exists`);
            }
            if (types.has(RRTYPE.SOA)) {
                throw bogus(`the proof of no DS at ${name} is the child zone's apex record, not the parent's`);
            }
            if (types.has(RRTYPE.NXNAME)) {
                return [{ kind: "nonexistent" }, proof.expiresAt];
            }
            return [types.has(RRTYPE.NS) ? { kind: "insecure" } : { kind: "same" }, proof.expiresAt];
        }
        const absent = proof.denial.nonexistence(name);
        if (!absent) {
            throw proof.failure(`no valid proof that ${name} has no DS record`);
        }
        return [absent.optOut ? { kind: "insecure" } : { kind: "nonexistent" }, proof.expiresAt];
    }

    /**
     * Validates every NSEC and NSEC3 RRset of the response against `zone` and gathers the valid ones into a proof. Records
     * that fail validation are dropped, never trusted, so a forged proof simply leaves the proof insufficient.
     */
    private buildDenial(
        zone: ZoneInfo,
        records: DnsRecord[]
    ): { denial: CompositeDenial; expiresAt: number; failure: (what: string) => DnssecError } {
        const sigs: DnsRecord[] = records.filter((r) => r.type === RRTYPE.RRSIG);
        const groups = new Map<string, DnsRecord[]>();
        for (const record of records) {
            if ((record.type === RRTYPE.NSEC || record.type === RRTYPE.NSEC3) && record.cls === CLASS_IN) {
                const key = `${record.type}|${record.name}`;
                groups.set(key, [...(groups.get(key) ?? []), record]);
            }
        }
        const nsec: NsecRecord[] = [];
        const nsec3: Nsec3Record[] = [];
        const validations: RrsetValidation[] = [];
        const notes: string[] = [];
        let unsupported: string | undefined;
        for (const group of [...groups.values()].slice(0, MAX_PROOF_RRSETS)) {
            const type: number = group[0].type;
            const name: DnsName = group[0].name;
            if (group.length !== 1) {
                notes.push(`ignored ${group.length} records at ${name} of type ${type}`);
                continue;
            }
            let validation: RrsetValidation;
            try {
                validation = validateRrset({
                    name,
                    type,
                    records: group,
                    sigs,
                    zone: zone.name,
                    keys: zone.keys,
                    now: this.clock(),
                });
            } catch (err: unknown) {
                if (err instanceof DnssecError && err.kind === "bogus") {
                    notes.push(err.reason);
                    continue;
                }
                throw err;
            }
            if (type === RRTYPE.NSEC) {
                const parsed: NsecRecord | undefined = parseNsec(name, group[0].rdata);
                if (parsed) {
                    nsec.push(parsed);
                    validations.push(validation);
                }
            } else {
                const parsed: Nsec3Record | undefined = parseNsec3(name, zone.name, group[0].rdata);
                if (!parsed) {
                    continue;
                }
                if (parsed.algorithm !== 1) {
                    unsupported = `NSEC3 hash algorithm ${parsed.algorithm} is not supported`;
                } else if (parsed.iterations > MAX_NSEC3_ITERATIONS) {
                    unsupported = `NSEC3 with ${parsed.iterations} iterations exceeds the limit of ${MAX_NSEC3_ITERATIONS}`;
                } else {
                    nsec3.push(parsed);
                    validations.push(validation);
                }
            }
        }
        const proofs: DenialProof[] = [];
        if (nsec.length > 0) {
            proofs.push(new NsecDenial(zone.name, nsec));
        }
        // All NSEC3 records used together must share one parameter set (RFC 5155 section 8.2).
        const byParameters = new Map<string, Nsec3Record[]>();
        for (const record of nsec3) {
            const key = `${record.iterations}|${record.salt.toString("hex")}`;
            byParameters.set(key, [...(byParameters.get(key) ?? []), record]);
        }
        for (const set of byParameters.values()) {
            proofs.push(new Nsec3Denial(zone.name, set));
        }
        const denial = new CompositeDenial(proofs, unsupported);
        return {
            denial,
            expiresAt: validations.length > 0 ? this.bound(validations, zone) : this.nowMs(),
            failure: (what: string): DnssecError => {
                if (denial.unsupported && nsec.length === 0 && nsec3.length === 0) {
                    return indeterminate(denial.unsupported);
                }
                return bogus(`${what}${notes.length > 0 ? ` (${notes.join("; ")})` : ""}`);
            },
        };
    }

    ///////////////////////////////////////////////////////////////////////////
    // Lookup
    ///////////////////////////////////////////////////////////////////////////

    /**
     * Walks from the root to the deepest secure zone containing `labels`' name. Returns that zone, or `undefined` when a
     * validated unsigned delegation is met on the way (everything below it is insecure).
     */
    private async walk(ctx: Context, labels: string[], upto: number): Promise<ZoneInfo | undefined> {
        let zone: ZoneInfo = await this.rootZone(ctx);
        for (let depth = 1; depth <= upto; depth++) {
            const name: DnsName = labelsToName(labels.slice(labels.length - depth));
            const verdict: DsVerdict = await this.dsVerdict(ctx, zone, name);
            if (verdict.kind === "zone") {
                zone = verdict.zone;
            } else if (verdict.kind === "insecure") {
                return undefined;
            } else if (verdict.kind === "nonexistent") {
                // Nothing below a name that does not exist can be a delegation.
                break;
            }
        }
        return zone;
    }

    private async lookup(ctx: Context, qname: DnsName, qtype: number, depth: number): Promise<DnssecResult> {
        if (depth > this.maxCnameDepth) {
            throw indeterminate(`CNAME chain longer than ${this.maxCnameDepth}`);
        }
        const labels: string[] = nameToLabels(qname);
        // The DS of a name lives in its parent zone, so a DS lookup stops one label short.
        const upto: number = qtype === RRTYPE.DS ? Math.max(0, labels.length - 1) : labels.length;
        const zone: ZoneInfo | undefined = await this.walk(ctx, labels, upto);
        const message: DnsMessage = await this.fetch(ctx, qname, qtype);
        if (message.answer.some((r) => r.type === RRTYPE.DNAME && r.cls === CLASS_IN)) {
            throw indeterminate("DNAME answers are not supported");
        }
        if (!zone) {
            return this.insecureAnswer(ctx, qname, qtype, message, depth);
        }
        return this.secureAnswer(ctx, zone, qname, qtype, message, depth);
    }

    /** An answer below a proven unsigned delegation: taken as delivered, but never reported as secure. */
    private async insecureAnswer(
        ctx: Context,
        qname: DnsName,
        qtype: number,
        message: DnsMessage,
        depth: number
    ): Promise<DnssecResult> {
        const direct: DnsRecord[] = rrsetOf(message.answer, qname, qtype);
        if (direct.length > 0) {
            return { status: "insecure", rdata: direct.map((r) => r.rdata), nxdomain: false };
        }
        const cname: DnsRecord[] = qtype === RRTYPE.CNAME ? [] : rrsetOf(message.answer, qname, RRTYPE.CNAME);
        if (cname.length > 0) {
            const sub: DnssecResult = await this.lookup(ctx, cnameTarget(cname), qtype, depth + 1);
            return { ...sub, status: "insecure" };
        }
        return { status: "insecure", rdata: [], nxdomain: message.rcode === 3 };
    }

    /**
     * Checks a wildcard expansion (RFC 4035 section 5.3.4, RFC 5155 section 8.8): the exact name must be proven not to exist
     * and the wildcard's parent must be the closest encloser. Returns `insecure` when the proof rests on an opt-out span.
     */
    private checkWildcard(
        zone: ZoneInfo,
        qname: DnsName,
        validation: RrsetValidation,
        message: DnsMessage
    ): DnssecStatus {
        if (validation.wildcardLabels === undefined) {
            return "secure";
        }
        const proof = this.buildDenial(zone, [...message.answer, ...message.authority]);
        const absent = proof.denial.nonexistence(qname);
        if (!absent) {
            throw proof.failure(`${qname} was synthesised from a wildcard without a proof that it does not exist`);
        }
        if (labelCount(absent.closestEncloser) !== validation.wildcardLabels) {
            throw bogus(`the wildcard used for ${qname} is not at its closest encloser`);
        }
        return absent.optOut ? "insecure" : "secure";
    }

    private async secureAnswer(
        ctx: Context,
        zone: ZoneInfo,
        qname: DnsName,
        qtype: number,
        message: DnsMessage,
        depth: number
    ): Promise<DnssecResult> {
        const sigs: DnsRecord[] = message.answer.filter((r) => r.type === RRTYPE.RRSIG);
        const direct: DnsRecord[] = rrsetOf(message.answer, qname, qtype);
        if (direct.length > 0) {
            const validation: RrsetValidation = validateRrset({
                name: qname,
                type: qtype,
                records: direct,
                sigs,
                zone: zone.name,
                keys: zone.keys,
                now: this.clock(),
            });
            const status: DnssecStatus = this.checkWildcard(zone, qname, validation, message);
            return { status, rdata: direct.map((r) => r.rdata), nxdomain: false };
        }
        const cname: DnsRecord[] = qtype === RRTYPE.CNAME ? [] : rrsetOf(message.answer, qname, RRTYPE.CNAME);
        if (cname.length > 0) {
            if (cname.length !== 1) {
                throw bogus(`${qname} has more than one CNAME record`);
            }
            const validation: RrsetValidation = validateRrset({
                name: qname,
                type: RRTYPE.CNAME,
                records: cname,
                sigs,
                zone: zone.name,
                keys: zone.keys,
                now: this.clock(),
            });
            const status: DnssecStatus = this.checkWildcard(zone, qname, validation, message);
            const sub: DnssecResult = await this.lookup(ctx, cnameTarget(cname), qtype, depth + 1);
            return { ...sub, status: weakest(status, sub.status) };
        }
        return this.negativeAnswer(zone, qname, qtype, message);
    }

    /** Validates a NODATA or NXDOMAIN answer from its NSEC/NSEC3 proof (RFC 4035 section 5.4, RFC 5155 sections 8.5-8.7). */
    private negativeAnswer(zone: ZoneInfo, qname: DnsName, qtype: number, message: DnsMessage): DnssecResult {
        const { denial, failure } = this.buildDenial(zone, [...message.answer, ...message.authority]);
        const types: Set<number> | undefined = denial.matching(qname);
        if (types) {
            if (types.has(qtype)) {
                throw bogus(`the answer for ${qname} type ${qtype} was withheld: its own record says the type exists`);
            }
            if (qtype !== RRTYPE.CNAME && types.has(RRTYPE.CNAME)) {
                throw bogus(`${qname} has a CNAME that the answer left out`);
            }
            if (isDelegation(types) && qtype !== RRTYPE.DS) {
                throw bogus(`${qname} is a delegation point, the proof cannot deny data that lives below it`);
            }
            // RFC 9824: an online-signing zone answers NXDOMAIN with an NSEC that lists the pseudo type NXNAME.
            return { status: "secure", rdata: [], nxdomain: types.has(RRTYPE.NXNAME) };
        }
        const absent = denial.nonexistence(qname);
        if (!absent) {
            throw failure(`no valid proof of non-existence for ${qname} type ${qtype}`);
        }
        const status: DnssecStatus = absent.optOut ? "insecure" : "secure";
        const wildcard: DnsName = prependLabel("*", absent.closestEncloser);
        const wildcardTypes: Set<number> | undefined = denial.matching(wildcard);
        if (wildcardTypes) {
            if (wildcardTypes.has(qtype) || (qtype !== RRTYPE.CNAME && wildcardTypes.has(RRTYPE.CNAME))) {
                throw bogus(`a wildcard applies to ${qname} but the answer left its data out`);
            }
            return { status, rdata: [], nxdomain: false };
        }
        if (!denial.covers(wildcard)) {
            throw failure(`no proof that no wildcard applies to ${qname}`);
        }
        return { status, rdata: [], nxdomain: true };
    }
}

/** The records of one RRset (owner, type, class IN) in a section. */
function rrsetOf(section: DnsRecord[], name: DnsName, type: number): DnsRecord[] {
    return section.filter((r) => r.cls === CLASS_IN && r.type === type && r.name === name);
}

/** The target of a CNAME RRset. */
function cnameTarget(records: DnsRecord[]): DnsName {
    const { name, end } = readPlainName(records[0].rdata, 0);
    if (end !== records[0].rdata.length) {
        throw indeterminate("a CNAME record is malformed");
    }
    return name;
}
