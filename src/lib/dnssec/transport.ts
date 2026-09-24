///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { randomInt } from "node:crypto";
import { createSocket } from "node:dgram";
import { connect, isIP } from "node:net";
import { CLASS_IN, DnssecTransport } from "./types.js";
import { buildQuery, DnsMessage, MAX_MESSAGE_SIZE, parseMessage, questionName } from "./wire.js";

/** Splits a resolver address as `dns.getServers()` prints it (`1.1.1.1`, `1.1.1.1:5353`, `[::1]:53`, `::1`) into host and port. */
export function parseServer(server: string): { host: string; port: number } {
    const trimmed: string = server.trim();
    const bracketed: RegExpMatchArray | null = trimmed.match(/^\[([^\]]+)\](?::(\d+))?$/);
    if (bracketed) {
        return { host: bracketed[1], port: bracketed[2] ? parseInt(bracketed[2], 10) : 53 };
    }
    const single: RegExpMatchArray | null = trimmed.match(/^([^:]+):(\d+)$/);
    if (single) {
        return { host: single[1], port: parseInt(single[2], 10) };
    }
    return { host: trimmed, port: 53 };
}

interface Expectation {
    id: number;
    name: string;
    type: number;
}

/** Whether `bytes` is a response to exactly the query that was sent: same ID, QR set, same single question. */
function isAnswerTo(bytes: Buffer, expected: Expectation): boolean {
    try {
        const message: DnsMessage = parseMessage(bytes);
        return (
            message.id === expected.id &&
            message.qr &&
            message.question.length === 1 &&
            message.question[0].type === expected.type &&
            message.question[0].cls === CLASS_IN &&
            message.question[0].name === expected.name
        );
    } catch {
        return false;
    }
}

function udpExchange(host: string, port: number, packet: Buffer, expected: Expectation, timeoutMs: number): Promise<Buffer> {
    return new Promise<Buffer>((resolve, reject) => {
        const socket = createSocket(isIP(host) === 6 ? "udp6" : "udp4");
        let done = false;
        const finish = (err: Error | undefined, response?: Buffer): void => {
            if (done) {
                return;
            }
            done = true;
            clearTimeout(timer);
            socket.close();
            if (err) {
                reject(err);
            } else {
                resolve(response as Buffer);
            }
        };
        const timer = setTimeout(() => finish(new Error(`UDP query to ${host}:${port} timed out`)), timeoutMs);
        socket.on("error", (err) => finish(err));
        socket.on("message", (msg, rinfo) => {
            // Only the server we asked, from the port we asked, answering this very question: anything else is spoofing noise.
            if (rinfo.address.split("%")[0] !== host.split("%")[0] || rinfo.port !== port) {
                return;
            }
            if (isAnswerTo(msg, expected)) {
                finish(undefined, msg);
            }
        });
        socket.send(packet, port, host, (err) => {
            if (err) {
                finish(err);
            }
        });
    });
}

function tcpExchange(host: string, port: number, packet: Buffer, expected: Expectation, timeoutMs: number): Promise<Buffer> {
    return new Promise<Buffer>((resolve, reject) => {
        const socket = connect({ host, port });
        let done = false;
        let received: Buffer = Buffer.alloc(0);
        const finish = (err: Error | undefined, response?: Buffer): void => {
            if (done) {
                return;
            }
            done = true;
            clearTimeout(timer);
            socket.destroy();
            if (err) {
                reject(err);
            } else {
                resolve(response as Buffer);
            }
        };
        const timer = setTimeout(() => finish(new Error(`TCP query to ${host}:${port} timed out`)), timeoutMs);
        socket.on("error", (err) => finish(err));
        socket.on("close", () => finish(new Error(`TCP connection to ${host}:${port} closed early`)));
        socket.on("connect", () => {
            const framed: Buffer = Buffer.alloc(2 + packet.length);
            framed.writeUInt16BE(packet.length, 0);
            packet.copy(framed, 2);
            socket.write(framed);
        });
        socket.on("data", (chunk: Buffer) => {
            received = Buffer.concat([received, chunk]);
            if (received.length < 2) {
                return;
            }
            const length: number = received.readUInt16BE(0);
            if (length > MAX_MESSAGE_SIZE) {
                finish(new Error("oversized TCP frame"));
            } else if (received.length >= 2 + length) {
                const body: Buffer = received.subarray(2, 2 + length);
                if (isAnswerTo(body, expected)) {
                    finish(undefined, body);
                } else {
                    finish(new Error(`TCP answer from ${host}:${port} does not match the query`));
                }
            }
        });
    });
}

/**
 * The default transport: UDP with EDNS0 first (DO, CD and RD set, 1232-byte buffer), TCP when the answer is truncated or UDP
 * fails, the next resolver when one fails. The resolvers are not trusted with anything but delivery: the returned bytes are
 * validated by the caller, so a lying resolver can cause a failure but never a forged "secure" answer.
 *
 * Only the addressed server's answer to exactly the question asked is accepted (ID, question and source address checked); the
 * ID is random, and the source port is the OS's random ephemeral one.
 */
export class DnssecUdpTcpTransport implements DnssecTransport {
    public async query(
        question: { name: string; type: number },
        opts: { servers: string[]; timeoutMs: number }
    ): Promise<Uint8Array> {
        if (opts.servers.length === 0) {
            throw new Error("no DNS servers configured");
        }
        const name: string = questionName(question.name);
        let lastError: Error = new Error("no DNS server answered");
        for (const server of opts.servers) {
            const { host, port } = parseServer(server);
            const expected: Expectation = { id: randomInt(0, 65536), name, type: question.type };
            const packet: Buffer = buildQuery(expected.id, name, question.type);
            try {
                let response: Buffer | undefined;
                try {
                    response = await udpExchange(host, port, packet, expected, opts.timeoutMs);
                } catch {
                    response = undefined;
                }
                if (response === undefined || (response.readUInt16BE(2) & 0x0200) !== 0) {
                    response = await tcpExchange(host, port, packet, expected, opts.timeoutMs);
                }
                const rcode: number = response.readUInt16BE(2) & 0x000f;
                if (rcode !== 0 && rcode !== 3) {
                    throw new Error(`${server} answered with RCODE ${rcode}`);
                }
                return response;
            } catch (err: any) {
                lastError = err instanceof Error ? err : new Error(String(err));
            }
        }
        throw lastError;
    }
}
