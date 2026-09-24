///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////

/** DNS resource record type numbers this library knows about. */
export const RRTYPE = {
    A: 1,
    NS: 2,
    CNAME: 5,
    SOA: 6,
    PTR: 12,
    MX: 15,
    TXT: 16,
    AAAA: 28,
    SRV: 33,
    DNAME: 39,
    OPT: 41,
    DS: 43,
    RRSIG: 46,
    NSEC: 47,
    DNSKEY: 48,
    NSEC3: 50,
    NSEC3PARAM: 51,
    /** The pseudo type an NSEC record's bitmap uses to say the name does not exist (RFC 9824, compact denial of existence). */
    NXNAME: 128,
    CAA: 257,
} as const;

/** The Internet class, the only one this library answers for. */
export const CLASS_IN = 1;

/** A DS record as a trust anchor or as parsed from a DS RRset. */
export interface DsRecord {
    keyTag: number;
    algorithm: number;
    digestType: number;
    /** The digest, either as raw bytes or as a hexadecimal string. */
    digest: Uint8Array | string;
}

/**
 * How raw DNS messages reach a recursive resolver. Injectable so tests can serve a synthetic signed hierarchy and so an
 * operator can route queries through their own plumbing. The transport owns the wire query (message ID, EDNS0 with DO, CD and
 * RD set) and returns the raw response; it must retry over TCP when the UDP answer is truncated.
 */
export interface DnssecTransport {
    query(
        question: { name: string; type: number },
        opts: { servers: string[]; timeoutMs: number }
    ): Promise<Uint8Array>;
}

/** A CAA record's RDATA (RFC 8659 §4.1). */
export interface CaaRdata {
    critical: number;
    tag: string;
    value: string;
}

/** `secure`: validated to a trust anchor. `insecure`: a validated proof that a delegation on the path is unsigned. */
export type DnssecStatus = "secure" | "insecure";

/**
 * Why a lookup could not be trusted. `bogus` means something is provably wrong (a bad or missing signature, a broken chain
 * of trust, a missing or forged proof of non-existence) and MUST be treated as an attack or a broken zone. `indeterminate`
 * means the network gave no usable answer (timeouts, SERVFAIL, malformed messages, an exhausted query budget) and the
 * lookup may simply be retried.
 *
 * @author Jean-Philippe Steinmetz
 */
export class DnssecError extends Error {
    public readonly kind: "bogus" | "indeterminate";
    public readonly reason: string;

    constructor(kind: "bogus" | "indeterminate", reason: string) {
        super(`DNSSEC ${kind}: ${reason}`);
        this.name = "DnssecError";
        this.kind = kind;
        this.reason = reason;
    }
}

/** Shorthand for the `bogus` error. */
export function bogus(reason: string): DnssecError {
    return new DnssecError("bogus", reason);
}

/** Shorthand for the `indeterminate` error. */
export function indeterminate(reason: string): DnssecError {
    return new DnssecError("indeterminate", reason);
}
