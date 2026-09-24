///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { DnsName, labelsToName, nameToLabels, nameToWire } from "./name.js";
import { CLASS_IN, indeterminate, RRTYPE } from "./types.js";

/** The largest DNS message this codec accepts (the limit of a TCP frame). */
export const MAX_MESSAGE_SIZE = 65535;

/** The EDNS0 UDP payload size announced in queries (the "DNS flag day 2020" value that avoids fragmentation). */
export const EDNS_BUFFER_SIZE = 1232;

/** A resource record as parsed off the wire. Names inside RDATA of the RFC 1035 types are decompressed. */
export interface DnsRecord {
    /** The owner name, normalised (lower-case, no trailing dot). */
    name: DnsName;
    type: number;
    cls: number;
    ttl: number;
    rdata: Buffer;
}

/** A parsed DNS message. */
export interface DnsMessage {
    id: number;
    flags: number;
    /** The message is a response (QR). */
    qr: boolean;
    opcode: number;
    /** The message was truncated (TC). */
    tc: boolean;
    /** The 4-bit RCODE from the header. */
    rcode: number;
    question: Array<{ name: DnsName; type: number; cls: number }>;
    answer: DnsRecord[];
    authority: DnsRecord[];
    additional: DnsRecord[];
}

/** The RDATA types whose embedded names may be compressed on the wire (RFC 3597 section 4, RFC 1035). */
const COMPRESSIBLE = new Set<number>([RRTYPE.NS, RRTYPE.CNAME, RRTYPE.SOA, RRTYPE.PTR, RRTYPE.MX]);

/** Reads a possibly compressed name, returning it in raw (original case) label form and the offset after it. */
function readLabels(msg: Buffer, start: number): { labels: Buffer[]; end: number } {
    const labels: Buffer[] = [];
    let offset: number = start;
    let end = -1;
    let hops = 0;
    let wireLength = 1;
    for (;;) {
        if (offset >= msg.length) {
            throw indeterminate("malformed message: name runs past the end");
        }
        const len: number = msg[offset];
        if ((len & 0xc0) === 0xc0) {
            if (offset + 1 >= msg.length) {
                throw indeterminate("malformed message: truncated compression pointer");
            }
            const target: number = ((len & 0x3f) << 8) | msg[offset + 1];
            if (end < 0) {
                end = offset + 2;
            }
            // Pointers must go strictly backwards, which also rules out every loop.
            if (target >= offset || ++hops > 128) {
                throw indeterminate("malformed message: bad compression pointer");
            }
            offset = target;
        } else if ((len & 0xc0) !== 0) {
            throw indeterminate("malformed message: unsupported label type");
        } else if (len === 0) {
            if (end < 0) {
                end = offset + 1;
            }
            return { labels, end };
        } else {
            if (offset + 1 + len > msg.length) {
                throw indeterminate("malformed message: label runs past the end");
            }
            wireLength += len + 1;
            if (wireLength > 255) {
                throw indeterminate("malformed message: name longer than 255 bytes");
            }
            labels.push(msg.subarray(offset + 1, offset + 1 + len));
            offset += 1 + len;
        }
    }
}

/** Reads a possibly compressed name at `offset`; returns the normalised name and the offset after it. */
export function readName(msg: Buffer, offset: number): { name: DnsName; end: number } {
    const { labels, end } = readLabels(msg, offset);
    return { name: labelsToName(labels.map((l) => l.toString("latin1"))), end };
}

/** Parses an uncompressed name occupying `rdata` from `offset` (RDATA of the types that are never compressed). */
export function readPlainName(rdata: Buffer, offset: number): { name: DnsName; end: number } {
    const labels: string[] = [];
    let at: number = offset;
    let wireLength = 1;
    for (;;) {
        if (at >= rdata.length) {
            throw indeterminate("malformed RDATA: name runs past the end");
        }
        const len: number = rdata[at];
        if ((len & 0xc0) !== 0) {
            throw indeterminate("malformed RDATA: compressed or extended label");
        }
        at++;
        if (len === 0) {
            return { name: labelsToName(labels), end: at };
        }
        if (at + len > rdata.length) {
            throw indeterminate("malformed RDATA: label runs past the end");
        }
        wireLength += len + 1;
        if (wireLength > 255) {
            throw indeterminate("malformed RDATA: name longer than 255 bytes");
        }
        labels.push(rdata.subarray(at, at + len).toString("latin1"));
        at += len;
    }
}

function wireOf(labels: Buffer[]): Buffer {
    const parts: Buffer[] = [];
    for (const label of labels) {
        parts.push(Buffer.from([label.length]), label);
    }
    parts.push(Buffer.from([0]));
    return Buffer.concat(parts);
}

/** Rewrites the RDATA of the RFC 1035 name-bearing types with every embedded name uncompressed (original case kept). */
function expandRdata(type: number, msg: Buffer, start: number, end: number): Buffer {
    if (!COMPRESSIBLE.has(type)) {
        return Buffer.from(msg.subarray(start, end));
    }
    if (type === RRTYPE.NS || type === RRTYPE.CNAME || type === RRTYPE.PTR) {
        const a = readLabels(msg, start);
        if (a.end > end) {
            throw indeterminate("malformed message: name overruns RDATA");
        }
        return wireOf(a.labels);
    }
    if (type === RRTYPE.MX) {
        if (start + 2 > end) {
            throw indeterminate("malformed message: short MX RDATA");
        }
        const a = readLabels(msg, start + 2);
        if (a.end > end) {
            throw indeterminate("malformed message: name overruns RDATA");
        }
        return Buffer.concat([msg.subarray(start, start + 2), wireOf(a.labels)]);
    }
    // SOA: MNAME, RNAME, five 32-bit numbers.
    const m = readLabels(msg, start);
    const r = readLabels(msg, m.end);
    if (r.end + 20 > end) {
        throw indeterminate("malformed message: short SOA RDATA");
    }
    return Buffer.concat([wireOf(m.labels), wireOf(r.labels), msg.subarray(r.end, r.end + 20)]);
}

function readRecord(msg: Buffer, offset: number): { record: DnsRecord; end: number } {
    const { name, end } = readName(msg, offset);
    if (end + 10 > msg.length) {
        throw indeterminate("malformed message: truncated record header");
    }
    const type: number = msg.readUInt16BE(end);
    const cls: number = msg.readUInt16BE(end + 2);
    const rawTtl: number = msg.readUInt32BE(end + 4);
    const rdlength: number = msg.readUInt16BE(end + 8);
    const rdStart: number = end + 10;
    if (rdStart + rdlength > msg.length) {
        throw indeterminate("malformed message: RDATA runs past the end");
    }
    return {
        record: {
            name,
            type,
            cls,
            // RFC 2181 section 8: a TTL with the top bit set is to be treated as zero.
            ttl: rawTtl > 0x7fffffff ? 0 : rawTtl,
            rdata: expandRdata(type, msg, rdStart, rdStart + rdlength),
        },
        end: rdStart + rdlength,
    };
}

/**
 * Parses a DNS message defensively: every read is bounds-checked, compression pointers may only go backwards, the message
 * size is capped and RDATA of the compressible types is rewritten uncompressed so it can be signed and compared as-is.
 *
 * @throws `indeterminate` for anything malformed.
 */
export function parseMessage(bytes: Uint8Array): DnsMessage {
    if (bytes.length < 12) {
        throw indeterminate("malformed message: shorter than a DNS header");
    }
    if (bytes.length > MAX_MESSAGE_SIZE) {
        throw indeterminate("malformed message: larger than 65535 bytes");
    }
    const msg: Buffer = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.length);
    const flags: number = msg.readUInt16BE(2);
    const counts: number[] = [msg.readUInt16BE(4), msg.readUInt16BE(6), msg.readUInt16BE(8), msg.readUInt16BE(10)];
    let offset = 12;
    const question: DnsMessage["question"] = [];
    for (let i = 0; i < counts[0]; i++) {
        const { name, end } = readName(msg, offset);
        if (end + 4 > msg.length) {
            throw indeterminate("malformed message: truncated question");
        }
        question.push({ name, type: msg.readUInt16BE(end), cls: msg.readUInt16BE(end + 2) });
        offset = end + 4;
    }
    const sections: DnsRecord[][] = [[], [], []];
    for (let s = 0; s < 3; s++) {
        for (let i = 0; i < counts[s + 1]; i++) {
            const { record, end } = readRecord(msg, offset);
            sections[s].push(record);
            offset = end;
        }
    }
    return {
        id: msg.readUInt16BE(0),
        flags,
        qr: (flags & 0x8000) !== 0,
        opcode: (flags >> 11) & 0x0f,
        tc: (flags & 0x0200) !== 0,
        rcode: flags & 0x000f,
        question,
        answer: sections[0],
        authority: sections[1],
        additional: sections[2],
    };
}

/**
 * Builds a query: header, one question and an EDNS0 OPT record with DO set (so signatures are returned). RD is set because
 * an ordinary recursive resolver is being asked to do the fetching, and CD is set so that resolver does not withhold data it
 * considers bogus - this library validates by itself and treats the resolver as a mere transport.
 */
export function buildQuery(id: number, name: DnsName, type: number, bufferSize: number = EDNS_BUFFER_SIZE): Buffer {
    const header: Buffer = Buffer.alloc(12);
    header.writeUInt16BE(id, 0);
    header.writeUInt16BE(0x0100 | 0x0010, 2);
    header.writeUInt16BE(1, 4);
    header.writeUInt16BE(1, 10);
    const tail: Buffer = Buffer.alloc(4);
    tail.writeUInt16BE(type, 0);
    tail.writeUInt16BE(CLASS_IN, 2);
    // OPT: root name, TYPE 41, CLASS = UDP payload size, TTL = ext-rcode 0, version 0, DO (0x8000), RDLENGTH 0.
    const opt: Buffer = Buffer.alloc(11);
    opt.writeUInt16BE(RRTYPE.OPT, 1);
    opt.writeUInt16BE(bufferSize, 3);
    opt.writeUInt16BE(0x8000, 7);
    return Buffer.concat([header, nameToWire(name), tail, opt]);
}

/** Parses a presentation-form question name given to a transport (`example.com.`, `.`) into the normalised form. */
export function questionName(name: string): DnsName {
    return labelsToName(nameToLabels(name));
}
