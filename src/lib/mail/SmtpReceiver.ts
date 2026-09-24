///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import type { AddressInfo } from "node:net";
import { SMTPServer, type SMTPServerDataStream, type SMTPServerSession } from "smtp-server";

/** The SMTP transaction a message arrived in. Reflects what the peer claimed; none of it is authenticated. */
export interface InboundEnvelope {
    /** MAIL FROM (empty string for the null sender). */
    mailFrom: string;
    /** Accepted RCPT TO addresses, lower-cased. */
    rcptTo: string[];
    /** Address of the connecting peer. */
    remoteAddress: string;
    /** The name the peer gave in EHLO/HELO (a claim, not a verified name). */
    clientHostname?: string;
}

/** Options of `SmtpReceiver`. */
export interface SmtpReceiverOptions {
    /** Interface to bind; all interfaces when absent. */
    host?: string;
    /** Port to bind; `0` picks a free one (see `SmtpReceiver.port`). */
    port: number;
    /** The name announced in the greeting. */
    hostname?: string;
    /** The only RCPT TO addresses accepted (case-insensitive). Everything else is refused, so this is never a relay. */
    recipients: string[];
    /** Largest message accepted, bytes (default 1 MiB). */
    maxSizeBytes?: number;
    /** Offers STARTTLS with this PEM key and certificate. Without it the receiver speaks plain SMTP only. */
    tls?: { key: string; cert: string };
    /** Simultaneous connections (default 50); further connections are answered 421. */
    maxConnections?: number;
    /** Simultaneous connections from one address (default 5): one client must not hold every slot. */
    maxConnectionsPerIp?: number;
    /** Most recipients per message (default 10). */
    maxRecipients?: number;
    /** Idle time after which a connection is dropped, ms (default 30 000). */
    socketTimeoutMs?: number;
    /** Longest a single message may take from DATA to the handler's answer, ms (default 60 000). */
    messageTimeoutMs?: number;
}

const DEFAULT_MAX_SIZE_BYTES: number = 1024 * 1024;
const DEFAULT_MAX_CONNECTIONS: number = 50;
const DEFAULT_MAX_RECIPIENTS: number = 10;
const DEFAULT_MAX_CONNECTIONS_PER_IP: number = 5;
const DEFAULT_SOCKET_TIMEOUT_MS: number = 30_000;
const DEFAULT_MESSAGE_TIMEOUT_MS: number = 60_000;
/** How long `stop()` lets connected peers finish before it closes their sockets. */
const CLOSE_TIMEOUT_MS: number = 3_000;

/** An SMTP reply as smtp-server wants it: the status code, and text that starts with the enhanced status code. */
function smtpError(responseCode: number, message: string): Error {
    return Object.assign(new Error(message), { responseCode });
}

/**
 * A small inbound SMTP server for replies to RFC 8823 challenge e-mails.
 *
 * It exists so the CA can be the MX for its own reply address without a separate MTA, and it is deliberately as narrow
 * as possible: no AUTH, no relaying (a recipient not in `recipients` is refused at RCPT TO), no VRFY/EXPN, bounded
 * message size, recipients, connections and time. It authenticates nothing about the sender - DKIM verification of the
 * reply is the handler's job (`parseInboundReply()`), which is why the handler receives the raw bytes untouched.
 *
 * The handler's outcome decides the SMTP answer: a resolved promise is `250`, a rejected one is
 * `451 4.3.0 try again later`, so a temporary failure on our side makes the sending MTA retry. Consequently the handler
 * must be idempotent, and must resolve (not reject) for a message it merely does not like - that is the CA's answer to
 * give in ACME terms, not the sender's to retry forever. Message contents are never logged here.
 *
 * @author Jean-Philippe Steinmetz
 */
export class SmtpReceiver {
    private readonly server: SMTPServer;
    private readonly options: SmtpReceiverOptions;
    private readonly recipients: Set<string>;
    /** Open connections per remote address (see `maxConnectionsPerIp`). */
    private readonly perIp: Map<string, number> = new Map();
    private started: boolean = false;
    private boundPort: number;

    constructor(
        o: SmtpReceiverOptions,
        private readonly onMessage: (raw: Buffer, envelope: InboundEnvelope) => Promise<void>
    ) {
        this.options = o;
        this.boundPort = o.port;
        this.recipients = new Set(o.recipients.map((r) => r.trim().toLowerCase()));
        const maxSize: number = o.maxSizeBytes ?? DEFAULT_MAX_SIZE_BYTES;
        const maxRecipients: number = o.maxRecipients ?? DEFAULT_MAX_RECIPIENTS;

        this.server = new SMTPServer({
            name: o.hostname,
            banner: "ESMTP",
            logger: false,
            authOptional: true,
            // No reverse DNS lookup per connection: it is slow, attacker-influenced, and nothing here relies on it.
            disableReverseLookup: true,
            // AUTH: nobody logs in here. VRFY/EXPN: no address probing. WIZ/SHELL: sendmail relics smtp-server answers.
            // STARTTLS is only on offer when there is a certificate to present.
            disabledCommands: ["AUTH", "VRFY", "EXPN", "WIZ", "SHELL", ...(o.tls ? [] : ["STARTTLS"])],
            hideSTARTTLS: !o.tls,
            size: maxSize,
            maxClients: o.maxConnections ?? DEFAULT_MAX_CONNECTIONS,
            socketTimeout: o.socketTimeoutMs ?? DEFAULT_SOCKET_TIMEOUT_MS,
            closeTimeout: CLOSE_TIMEOUT_MS,
            maxAllowedUnauthenticatedCommands: 50,
            ...(o.tls ? { key: o.tls.key, cert: o.tls.cert, minVersion: "TLSv1.2" } : {}),
            onConnect: (session: SMTPServerSession, callback: (err?: Error | null) => void) => {
                const ip: string = session.remoteAddress;
                const open: number = this.perIp.get(ip) ?? 0;
                if (open >= (this.options.maxConnectionsPerIp ?? DEFAULT_MAX_CONNECTIONS_PER_IP)) {
                    return callback(smtpError(421, "4.7.0 Too many connections from your address"));
                }
                this.perIp.set(ip, open + 1);
                callback();
            },
            onClose: (session: SMTPServerSession) => {
                const open: number = (this.perIp.get(session.remoteAddress) ?? 1) - 1;
                if (open <= 0) {
                    this.perIp.delete(session.remoteAddress);
                } else {
                    this.perIp.set(session.remoteAddress, open);
                }
            },
            onRcptTo: (address, session, callback) => {
                const rcpts: number = session.envelope.rcptTo.length;
                if (!this.recipients.has(address.address.trim().toLowerCase())) {
                    return callback(smtpError(550, "5.1.1 Mailbox unavailable"));
                }
                if (rcpts >= maxRecipients) {
                    return callback(smtpError(452, "4.5.3 Too many recipients"));
                }
                callback();
            },
            onData: (stream, session, callback) => this.receive(stream, session, maxSize, callback),
        } as any);
        // Connection level failures (resets, TLS handshakes that never complete) are the peer's problem, never ours.
        this.server.on("error", () => undefined);
    }

    /** The port the receiver listens on: the real one after `start()` when `port` was 0. */
    public get port(): number {
        return this.boundPort;
    }

    /**
     * Collects one message's bytes (never more than the size limit is held in memory) and hands it to the handler under
     * the message timeout, translating the outcome into the SMTP answer.
     */
    private receive(
        stream: SMTPServerDataStream,
        session: SMTPServerSession,
        maxSize: number,
        callback: (err?: Error | null) => void
    ): void {
        const chunks: Buffer[] = [];
        let received: number = 0;
        let overflow: boolean = false;
        let finished: boolean = false;
        const finish = (err?: Error): void => {
            if (!finished) {
                finished = true;
                clearTimeout(timer);
                callback(err);
            }
        };
        const timer: NodeJS.Timeout = setTimeout(
            () => finish(smtpError(451, "4.4.2 Timeout, try again later")),
            this.options.messageTimeoutMs ?? DEFAULT_MESSAGE_TIMEOUT_MS
        );

        stream.on("data", (chunk: Buffer) => {
            received += chunk.length;
            if (received > maxSize) {
                // Keep draining so the protocol stays in step, but stop holding the bytes.
                overflow = true;
                chunks.length = 0;
            } else if (!overflow) {
                chunks.push(chunk);
            }
        });
        stream.on("error", () => finish(smtpError(451, "4.3.0 try again later")));
        stream.on("end", () => {
            if (finished) {
                return;
            }
            if (overflow || stream.sizeExceeded) {
                return finish(smtpError(552, "5.3.4 Message size exceeds fixed maximum message size"));
            }
            const envelope: InboundEnvelope = {
                mailFrom: session.envelope.mailFrom ? session.envelope.mailFrom.address : "",
                rcptTo: session.envelope.rcptTo.map((r) => r.address.toLowerCase()),
                remoteAddress: session.remoteAddress,
                ...(session.hostNameAppearsAs ? { clientHostname: session.hostNameAppearsAs } : {}),
            };
            let handled: Promise<void>;
            try {
                handled = Promise.resolve(this.onMessage(Buffer.concat(chunks, received), envelope));
            } catch (err) {
                handled = Promise.reject(err);
            }
            handled.then(
                () => finish(),
                // The reason is deliberately not sent to the peer; the handler owns logging it.
                () => finish(smtpError(451, "4.3.0 try again later"))
            );
        });
    }

    /**
     * Starts listening.
     *
     * @throws If the address cannot be bound (in use, not permitted).
     */
    public async start(): Promise<void> {
        if (this.started) {
            return;
        }
        await new Promise<void>((resolve, reject) => {
            const onError = (err: Error): void => reject(err);
            this.server.server.once("error", onError);
            this.server.listen(this.options.port, this.options.host, () => {
                this.server.server.removeListener("error", onError);
                resolve();
            });
        });
        this.started = true;
        this.boundPort = (this.server.server.address() as AddressInfo).port;
    }

    /**
     * Stops accepting connections, gives connected peers a few seconds to finish and then closes them. Safe to call
     * more than once and on a receiver that never started.
     */
    public async stop(): Promise<void> {
        if (!this.started) {
            return;
        }
        this.started = false;
        await new Promise<void>((resolve) => this.server.close(() => resolve()));
    }
}
