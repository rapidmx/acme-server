///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { createSocket, Socket } from "node:dgram";
import { createServer, Server, Socket as TcpSocket } from "node:net";
import { DnssecUdpTcpTransport, parseServer } from "../../../src/lib/dnssec/transport.js";
import { DnssecError } from "../../../src/lib/dnssec/types.js";
import { parseMessage } from "../../../src/lib/dnssec/wire.js";
import { buildStandardWorld, encodeMessage, makeResolver, StandardWorld, T } from "./zones.js";

type UdpMode = "normal" | "drop" | "truncate" | "spoof-first" | "servfail" | "wrong-question";
type TcpMode = "normal" | "servfail" | "close";

/** A DNS server on 127.0.0.1 (UDP and TCP on one port) that answers from a synthetic hierarchy. */
class LocalDns {
    public udpMode: UdpMode = "normal";
    public tcpMode: TcpMode = "normal";
    public readonly udpQueries: Buffer[] = [];
    public readonly tcpQueries: Buffer[] = [];
    public port = 0;
    private udp?: Socket;
    private tcp?: Server;
    private readonly clients = new Set<TcpSocket>();

    constructor(private readonly std: StandardWorld) {}

    private async answer(query: Buffer, servfail = false): Promise<Buffer> {
        const parsed = parseMessage(query);
        const { name, type } = parsed.question[0];
        const bytes = Buffer.from(await this.std.world.query({ name, type }));
        bytes.writeUInt16BE(parsed.id, 0);
        if (servfail) {
            bytes[3] = (bytes[3] & 0xf0) | 2;
        }
        return bytes;
    }

    public async start(): Promise<void> {
        let lastError = "";
        for (let attempt = 0; attempt < 20; attempt++) {
            const udp: Socket = createSocket("udp4");
            await new Promise<void>((resolve) => udp.bind(0, "127.0.0.1", resolve));
            const port: number = udp.address().port;
            const tcp: Server = createServer((socket) => this.onTcp(socket));
            const listening: boolean = await new Promise<boolean>((resolve) => {
                tcp.once("error", (err: NodeJS.ErrnoException) => {
                    lastError = `${err.code ?? err.message} on port ${port}`;
                    resolve(false);
                });
                tcp.listen(port, "127.0.0.1", () => resolve(true));
            });
            if (!listening) {
                udp.close();
                continue;
            }
            this.udp = udp;
            this.tcp = tcp;
            this.port = port;
            udp.on("message", (msg, rinfo) => {
                void this.onUdp(msg, rinfo.port, rinfo.address);
            });
            return;
        }
        throw new Error(`no free port for the local DNS server (last error: ${lastError})`);
    }

    private async onUdp(msg: Buffer, port: number, address: string): Promise<void> {
        this.udpQueries.push(msg);
        const send = (data: Buffer): void => this.udp?.send(data, port, address);
        switch (this.udpMode) {
            case "drop":
                return;
            case "truncate": {
                const bytes = await this.answer(msg);
                const cut = Buffer.from(bytes.subarray(0, 12 + (msg.length - 12 - 11)));
                cut.writeUInt16BE(0, 6);
                cut.writeUInt16BE(0, 8);
                cut.writeUInt16BE(0, 10);
                cut[2] |= 0x02;
                send(cut);
                return;
            }
            case "spoof-first": {
                const good = await this.answer(msg);
                const spoof = Buffer.from(good);
                spoof.writeUInt16BE((good.readUInt16BE(0) + 1) & 0xffff, 0);
                send(spoof);
                send(good);
                return;
            }
            case "servfail":
                send(await this.answer(msg, true));
                return;
            case "wrong-question": {
                const parsed = parseMessage(msg);
                const other = encodeMessage("other.example", parsed.question[0].type, {
                    rcode: 0,
                    answer: [],
                    authority: [],
                });
                other.writeUInt16BE(parsed.id, 0);
                send(other);
                send(await this.answer(msg));
                return;
            }
            default:
                send(await this.answer(msg));
        }
    }

    private onTcp(socket: TcpSocket): void {
        this.clients.add(socket);
        socket.on("close", () => this.clients.delete(socket));
        socket.on("error", () => undefined);
        let buffer: Buffer = Buffer.alloc(0);
        socket.on("data", (chunk: Buffer) => {
            buffer = Buffer.concat([buffer, chunk]);
            while (buffer.length >= 2 && buffer.length >= 2 + buffer.readUInt16BE(0)) {
                const query: Buffer = buffer.subarray(2, 2 + buffer.readUInt16BE(0));
                buffer = buffer.subarray(2 + buffer.readUInt16BE(0));
                this.tcpQueries.push(Buffer.from(query));
                if (this.tcpMode === "close") {
                    socket.destroy();
                    return;
                }
                void this.answer(query, this.tcpMode === "servfail").then((bytes) => {
                    const framed = Buffer.alloc(2 + bytes.length);
                    framed.writeUInt16BE(bytes.length, 0);
                    bytes.copy(framed, 2);
                    socket.write(framed);
                });
            }
        });
    }

    public async stop(): Promise<void> {
        for (const client of this.clients) {
            client.destroy();
        }
        await new Promise<void>((resolve) => (this.tcp ? this.tcp.close(() => resolve()) : resolve()));
        await new Promise<void>((resolve) => (this.udp ? this.udp.close(() => resolve()) : resolve()));
    }

    public get address(): string {
        return `127.0.0.1:${this.port}`;
    }
}

let std: StandardWorld;
let server: LocalDns;
let second: LocalDns;

beforeAll(() => {
    std = buildStandardWorld();
}, 60000);

beforeEach(async () => {
    server = new LocalDns(std);
    second = new LocalDns(std);
    await server.start();
    await second.start();
});

afterEach(async () => {
    await server.stop();
    await second.stop();
    std.world.queries.length = 0;
});

describe("server addresses", () => {
    it("parses the forms dns.getServers() produces", () => {
        expect(parseServer("8.8.8.8")).toEqual({ host: "8.8.8.8", port: 53 });
        expect(parseServer("8.8.8.8:5353")).toEqual({ host: "8.8.8.8", port: 5353 });
        expect(parseServer("[2001:4860:4860::8888]:53")).toEqual({ host: "2001:4860:4860::8888", port: 53 });
        expect(parseServer("[::1]")).toEqual({ host: "::1", port: 53 });
        expect(parseServer("2001:4860:4860::8888")).toEqual({ host: "2001:4860:4860::8888", port: 53 });
    });
});

describe("the UDP/TCP transport", () => {
    const resolve = (servers: string[], timeoutMs = 1500) =>
        makeResolver(std.world, { transport: new DnssecUdpTcpTransport(), servers, timeoutMs }).resolveCaa(
            "example.com"
        );

    it("asks with RD, CD and an EDNS0 OPT record with DO and a 1232-byte buffer, and yields a validated answer", async () => {
        const result = await resolve([server.address]);
        expect(result).toEqual({ status: "secure", records: [{ critical: 0, tag: "issue", value: "ca.example.com" }] });
        expect(server.udpQueries).toHaveLength(6);
        for (const query of server.udpQueries) {
            expect(query.readUInt16BE(2)).toBe(0x0110);
            const opt = query.subarray(query.length - 11);
            expect([...opt]).toEqual([0, 0, 41, 0x04, 0xd0, 0, 0, 0x80, 0, 0, 0]);
        }
        expect(server.tcpQueries).toHaveLength(0);
    });

    it("retries over TCP when the UDP answer is truncated", async () => {
        server.udpMode = "truncate";
        const result = await resolve([server.address]);
        expect(result.status).toBe("secure");
        expect(server.tcpQueries).toHaveLength(6);
    });

    it("retries over TCP when UDP times out", async () => {
        server.udpMode = "drop";
        const result = await resolve([server.address], 300);
        expect(result.status).toBe("secure");
        expect(server.tcpQueries).toHaveLength(6);
    });

    it("ignores a spoofed answer with the wrong ID and one to the wrong question", async () => {
        server.udpMode = "spoof-first";
        expect((await resolve([server.address])).status).toBe("secure");
        server.udpMode = "wrong-question";
        expect((await resolve([server.address])).status).toBe("secure");
        expect(server.tcpQueries).toHaveLength(0);
    });

    it("moves on to the next server when one answers SERVFAIL or fails", async () => {
        server.udpMode = "servfail";
        server.tcpMode = "servfail";
        expect((await resolve([server.address, second.address])).status).toBe("secure");
        expect(second.udpQueries).toHaveLength(6);
        server.udpMode = "drop";
        server.tcpMode = "close";
        second.udpQueries.length = 0;
        expect((await resolve([server.address, second.address], 300)).status).toBe("secure");
        expect(second.udpQueries).toHaveLength(6);
    });

    it("fails as indeterminate when every server fails", async () => {
        server.udpMode = "servfail";
        server.tcpMode = "servfail";
        second.udpMode = "drop";
        second.tcpMode = "close";
        await expect(resolve([server.address, second.address], 300)).rejects.toMatchObject({ kind: "indeterminate" });
        await expect(resolve([server.address, second.address], 300)).rejects.toBeInstanceOf(DnssecError);
    });

    it("fails when there is no server to ask", async () => {
        await expect(
            new DnssecUdpTcpTransport().query({ name: "example.com.", type: T.CAA }, { servers: [], timeoutMs: 100 })
        ).rejects.toThrow(/no DNS servers/);
    });

    it("returns NXDOMAIN answers rather than treating them as failures", async () => {
        const raw = await new DnssecUdpTcpTransport().query(
            { name: "nope.example.com.", type: T.CAA },
            { servers: [server.address], timeoutMs: 1500 }
        );
        expect(parseMessage(raw).rcode).toBe(3);
    });
});
