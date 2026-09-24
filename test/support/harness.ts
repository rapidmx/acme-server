///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { mkdtempSync, rmSync } from "fs";
import * as net from "net";
import { tmpdir } from "os";
import { join } from "path";
import nconf from "nconf";
import * as prom from "prom-client";
import { MongoMemoryServer } from "mongodb-memory-server";
import { Logger } from "@rapidrest/core";
import { ObjectFactory, Server } from "@rapidrest/service-core";
import { CaaRecord, CaaValidator, DnsLookup } from "../../src/lib/acme/Dns.js";
import { MemoryChallengeMailer, DnsTxtResolver } from "../../src/lib/mail/index.js";
import { AcmeContext } from "../../src/services/AcmeContext.js";
import { createTestCa } from "./ca.js";
import { makeDkimKey, makeResolver, TestDkimKey } from "../lib/mail/helpers.js";

/** The mail domain the tests' applicants use, whose DKIM key the stub DNS publishes. */
export const APPLICANT_DOMAIN = "example.com";

/** Records the tests set to steer the stub DNS. Reset by `resetDns()`. */
export const dnsState: { caa: Record<string, CaaRecord[]>; noMail: Set<string>; failing: Set<string> } = { caa: {}, noMail: new Set(), failing: new Set() };

export function resetDns(): void {
    dnsState.caa = {};
    dnsState.noMail = new Set();
    dnsState.failing = new Set();
}

/**
 * What the stub DNSSEC validator answers, by name: an entry in `answers` (`insecure` for an unsigned zone) or a failure (`bogus` /
 * `indeterminate`). A name in neither is a validated empty answer. Only used by a CA started with `{ dnssec: true }`.
 */
export const dnssecState: {
    answers: Record<string, { records: Array<{ critical: number; tag: string; value: string }>; insecure?: boolean }>;
    failures: Record<string, "bogus" | "indeterminate">;
    asked: string[];
} = { answers: {}, failures: {}, asked: [] };

export function resetDnssec(): void {
    dnssecState.answers = {};
    dnssecState.failures = {};
    dnssecState.asked = [];
}

/** A `CaaValidator` that answers from `dnssecState` (registered as `CaaValidator` when a CA is started with `{ dnssec: true }`). */
export class TestCaaValidator implements CaaValidator {
    public async resolveCaa(name: string): Promise<{ status: "secure" | "insecure"; records: Array<{ critical: number; tag: string; value: string }> }> {
        dnssecState.asked.push(name);
        const failure = dnssecState.failures[name];
        if (failure) {
            throw Object.assign(new Error(`${failure} (test)`), { kind: failure, reason: `${failure}: test failure at ${name}` });
        }
        const answer = dnssecState.answers[name];
        return { status: answer?.insecure ? "insecure" : "secure", records: answer?.records ?? [] };
    }
}

/** A `DnsLookup` that answers from `dnsState` and never touches the network: every domain has a mail server unless told otherwise. */
export class TestDnsLookup implements DnsLookup {
    public async resolveMx(name: string): Promise<Array<{ exchange: string; priority: number }>> {
        if (dnsState.failing.has(name)) {
            throw Object.assign(new Error("SERVFAIL"), { code: "ESERVFAIL" });
        }
        if (dnsState.noMail.has(name)) {
            throw Object.assign(new Error("no data"), { code: "ENODATA" });
        }
        return [{ exchange: `mx.${name}`, priority: 10 }];
    }
    public async resolve4(name: string): Promise<string[]> {
        if (dnsState.noMail.has(name)) {
            throw Object.assign(new Error("no data"), { code: "ENODATA" });
        }
        return ["192.0.2.1"];
    }
    public async resolve6(): Promise<string[]> {
        throw Object.assign(new Error("no data"), { code: "ENODATA" });
    }
    public async resolveCaa(name: string): Promise<CaaRecord[]> {
        if (dnsState.failing.has(`caa:${name}`)) {
            throw Object.assign(new Error("SERVFAIL"), { code: "ESERVFAIL" });
        }
        const records: CaaRecord[] | undefined = dnsState.caa[name];
        if (!records) {
            throw Object.assign(new Error("no data"), { code: "ENODATA" });
        }
        return records;
    }
}

/** The DKIM key the applicants' mail server signs with, and the resolver that publishes it (registered as `DkimResolver`). */
export const applicantDkim: TestDkimKey = makeDkimKey(APPLICANT_DOMAIN);
/** The DKIM key of an internationalized applicant domain (bücher.com), published under its A-label name. */
export const IDN_DOMAIN = "xn--bcher-kva.com";
export const idnDkim: TestDkimKey = makeDkimKey(IDN_DOMAIN);
export class TestDkimResolver {
    public resolver: DnsTxtResolver = makeResolver(applicantDkim, idnDkim);
}

/** A running CA under test. */
export interface CaHarness {
    baseUrl: string;
    server: Server;
    objectFactory: ObjectFactory;
    ctx: AcmeContext;
    /** Every verification e-mail the CA "sent". */
    mailer: MemoryChallengeMailer;
    manifest: string;
    inboundSecret: string;
    /** The bearer secret of the operator API. */
    adminSecret: string;
    stop(): Promise<void>;
}

async function freePort(): Promise<number> {
    return await new Promise((resolve, reject) => {
        const probe: net.Server = net.createServer();
        probe.once("error", reject);
        probe.listen(0, "127.0.0.1", () => {
            const port: number = (probe.address() as net.AddressInfo).port;
            probe.close(() => resolve(port));
        });
    });
}

/**
 * Starts the whole CA – the real RapidREST server, routes, services and models – against an in-memory MongoDB, a generated
 * CA hierarchy, a stub DNS and an in-memory mailer.
 *
 * @param overrides Extra configuration, keyed like nconf (`"acme:rate_limits:enabled": false`).
 * @param options `issuerDays`: how long the generated issuing CA certificate lasts (default five years).
 */
export async function startCa(overrides: Record<string, unknown> = {}, options: { issuerDays?: number; dnssec?: boolean } = {}): Promise<CaHarness> {
    resetDns();
    const mongod: MongoMemoryServer = await MongoMemoryServer.create({ instance: { dbName: "acme-test" } });
    const port: number = await freePort();
    const baseUrl = `http://127.0.0.1:${port}`;
    const dir: string = mkdtempSync(join(tmpdir(), "acme-test-ca-"));
    const manifest: string = await createTestCa(dir, baseUrl, "test-ca", options.issuerDays);
    const inboundSecret = "test-inbound-secret";
    const adminSecret = "test-admin-secret-0123456789abcdef0123456789";

    const conf = new nconf.Provider();
    conf.use("memory");
    conf.defaults({
        service_name: "acme-test",
        version: "0.0.0",
        port,
        listen_host: "127.0.0.1",
        class_loader: { ignore: [/server\..*/, /config\..*/, /^lib$/] },
        max_body_size: 2 * 1024 * 1024,
        rbac: { enabled: false },
        auth: { strategy: "auth.JWTStrategy", secret: "unused-in-tests", options: { expiresIn: "1 hour", audience: "acme.test", issuer: "acme.test" } },
        trusted_proxies: [],
        datastores: {
            mongo: { type: "mongodb", url: `${mongod.getUri()}acme-test`, synchronize: true },
        },
        logger: { level: "warn" },
        rateLimit: { enabled: false },
        acme: {
            external_url: baseUrl,
            caa_identities: ["rapidmx.io"],
            max_identifiers: 1,
            ca: { manifest },
            mail: {
                from: "acme-challenge@acme.rapidmx.test",
                reply_to: "acme-response@acme.rapidmx.test",
                dkim_alignment: "strict",
                inbound: { http_secret: inboundSecret, smtp: { enabled: false } },
            },
            // Off by default so a test that makes hundreds of requests from one address is not throttled; the rate-limit tests
            // switch it on with startCa({ "acme:rate_limits:enabled": true }).
            rate_limits: { enabled: false, overrides: [] },
            metrics_secret: "test-metrics-secret",
            admin_secret: adminSecret,
        },
    });
    for (const [key, value] of Object.entries(overrides)) {
        conf.set(key, value);
    }

    const logger = Logger("warn");
    const objectFactory: ObjectFactory = new ObjectFactory(conf, logger);
    objectFactory.register(TestDnsLookup, "DnsLookup");
    if (options.dnssec) {
        resetDnssec();
        objectFactory.register(TestCaaValidator, "CaaValidator");
    }
    objectFactory.register(MemoryChallengeMailer, "ChallengeMailTransport");
    objectFactory.register(TestDkimResolver, "DkimResolver");
    // The framework registers its request metrics in prom-client's global registry, which allows one server per process.
    prom.register.clear();
    const server: Server = new Server({ config: conf, basePath: "./src", logger, objectFactory });
    await server.start();

    const ctx: AcmeContext | undefined = objectFactory.getInstance(AcmeContext);
    if (!ctx?.ready) {
        await server.stop();
        await mongod.stop();
        throw new Error("The CA under test did not initialize.");
    }
    const mailer = objectFactory.getInstance<MemoryChallengeMailer>("ChallengeMailTransport")!;

    return {
        baseUrl,
        server,
        objectFactory,
        ctx,
        mailer,
        manifest,
        inboundSecret,
        adminSecret,
        stop: async () => {
            await server.stop();
            await objectFactory.destroy();
            await mongod.stop();
            rmSync(dir, { recursive: true, force: true });
        },
    };
}
