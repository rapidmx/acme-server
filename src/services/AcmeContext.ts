///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { ObjectDecorators } from "@rapidrest/core";
import { DatabaseDecorators, HttpRequest, MongoRepository, NetUtils, ObjectFactory } from "@rapidrest/service-core";
import { AcmeStore, MemoryAcmeStore, RedisAcmeStore, RedisLike } from "../lib/acme/AcmeStore.js";
import { AcmeUrls } from "../lib/acme/AcmeUrls.js";
import { CaaValidator, DnsChecks, DnsLookup, SystemDnsLookup } from "../lib/acme/Dns.js";
import { DnssecResolver } from "../lib/dnssec/index.js";
import { NonceService } from "../lib/acme/Nonces.js";
import { AcmeRateLimiter, ipSubject } from "../lib/acme/RateLimits.js";
import { ChallengeMailTransport, DnsTxtResolver } from "../lib/mail/index.js";
import { IssuerRegistry } from "../lib/pki/index.js";
import { AcmeAccount } from "../models/AcmeAccount.js";
import { AcmeAuthorization } from "../models/AcmeAuthorization.js";
import { AcmeCertificate } from "../models/AcmeCertificate.js";
import { AcmeCrl } from "../models/AcmeCrl.js";
import { AcmeOrder } from "../models/AcmeOrder.js";
import { AccountService } from "./AccountService.js";
import { AdminService } from "./AdminService.js";
import { ReminderService } from "./ReminderService.js";
import { AcmeSettings } from "./AcmeSettings.js";
import { CertificateService } from "./CertificateService.js";
import { ChallengeService } from "./ChallengeService.js";
import { ConfiguredChallengeMailer } from "./ConfiguredChallengeMailer.js";
import { CrlService } from "./CrlService.js";
import { OcspService } from "./OcspService.js";
import { OrderService } from "./OrderService.js";
import { RequestAuthenticator } from "./RequestAuthenticator.js";
const { Config, Init, Logger } = ObjectDecorators;
const { Redis, Repository } = DatabaseDecorators;

/** The DI token a test registers a stub `CaaValidator` (a DNSSEC-validating CAA resolver) under. */
export const CAA_VALIDATOR_TOKEN = "CaaValidator";

/** The DI token a deployment (or a test) registers an alternative `DnsLookup` under. */
export const DNS_LOOKUP_TOKEN = "DnsLookup";
/** The DI token a deployment (or a test) registers an alternative `ChallengeMailTransport` under. */
export const CHALLENGE_MAIL_TOKEN = "ChallengeMailTransport";
/** The DI token a test registers a stub DKIM DNS resolver (`DnsTxtResolver` factory) under. */
export const DKIM_RESOLVER_TOKEN = "DkimResolver";

/**
 * The one object that wires the CA together: settings, the shared store, the issuers, the DNS and mail collaborators,
 * the collections, and the services that hold the protocol logic. Routes inject it and call the services.
 *
 * Built once at startup. If anything essential is wrong (no usable issuer, no database) `init()` throws and `ready`
 * stays `false`; `server.ts` checks it right after the server has started and refuses to run half-configured.
 *
 * @author Jean-Philippe Steinmetz
 */
export class AcmeContext {
    @Config()
    private config: any;

    @Config("trusted_proxies", [])
    private trustedProxies: string[] = [];

    @Logger
    public logger: any;

    @Redis("cache", false)
    private redis?: RedisLike;

    @Repository(AcmeAccount)
    public accountRepo!: MongoRepository<AcmeAccount>;
    @Repository(AcmeOrder)
    public orderRepo!: MongoRepository<AcmeOrder>;
    @Repository(AcmeAuthorization)
    public authzRepo!: MongoRepository<AcmeAuthorization>;
    @Repository(AcmeCertificate)
    public certRepo!: MongoRepository<AcmeCertificate>;
    @Repository(AcmeCrl)
    public crlRepo!: MongoRepository<AcmeCrl>;

    public settings!: AcmeSettings;
    public urls!: AcmeUrls;
    public store!: AcmeStore;
    public nonces!: NonceService;
    public limits!: AcmeRateLimiter;
    public dns!: DnsChecks;
    public mailer!: ChallengeMailTransport;
    public registry!: IssuerRegistry;
    /** A DKIM DNS resolver override (tests); `undefined` uses the system's. */
    public dkimResolver?: DnsTxtResolver;
    public now: () => Date = () => new Date();

    public auth!: RequestAuthenticator;
    public accounts!: AccountService;
    public orders!: OrderService;
    public challenges!: ChallengeService;
    public certificates!: CertificateService;
    public crls!: CrlService;
    public ocsp!: OcspService;
    public admin!: AdminService;
    public reminders!: ReminderService;

    /** `true` once `init()` completed; `false` means the CA must not serve. */
    public ready: boolean = false;

    @Init
    public async init(): Promise<void> {
        const factory: ObjectFactory = (this as any)._objectFactory;
        this.settings = new AcmeSettings(this.config);
        this.urls = new AcmeUrls(this.settings.externalUrl);

        if (this.redis) {
            this.store = new RedisAcmeStore(this.redis);
            this.logger.info("Nonces and rate limits are kept in Redis (shared by every replica).");
        } else {
            this.store = new MemoryAcmeStore();
            this.logger.warn("No 'cache' (Redis) datastore is configured: nonces and rate limits are kept in this process's memory, which is only correct for a single instance.");
        }
        if (!this.settings.development && this.trustedProxies.length === 0) {
            this.logger.warn("trusted_proxies is empty: behind a reverse proxy or gateway every client shares the proxy's address, so the per-IP rate limits apply to everyone together. Set trusted_proxies to the proxy's address(es).");
        }
        this.nonces = new NonceService(this.store, this.settings.nonceTtlSeconds);
        this.limits = new AcmeRateLimiter(this.store, {
            enabled: this.settings.rateLimitsEnabled,
            overrides: this.settings.rateLimitOverrides,
            helpUrl: `${this.settings.externalUrl}/rate-limits`,
        });

        const dnsLookup: DnsLookup = factory.classes.has(DNS_LOOKUP_TOKEN)
            ? await factory.newInstance<DnsLookup>(DNS_LOOKUP_TOKEN, { name: "default" })
            : new SystemDnsLookup(this.settings.dnsServers);
        const caaValidator: CaaValidator | undefined = factory.classes.has(CAA_VALIDATOR_TOKEN)
            ? await factory.newInstance<CaaValidator>(CAA_VALIDATOR_TOKEN, { name: "default" })
            : this.settings.dnssecValidation && !factory.classes.has(DNS_LOOKUP_TOKEN)
              ? new DnssecResolver({ servers: this.settings.dnsServers.length > 0 ? this.settings.dnsServers : undefined })
              : undefined;
        this.dns = new DnsChecks(dnsLookup, this.settings.caaIdentities, caaValidator);

        this.mailer = factory.classes.has(CHALLENGE_MAIL_TOKEN)
            ? await factory.newInstance<ChallengeMailTransport>(CHALLENGE_MAIL_TOKEN, { name: "default" })
            : new ConfiguredChallengeMailer(this.config);
        if (factory.classes.has(DKIM_RESOLVER_TOKEN)) {
            const holder: { resolver: DnsTxtResolver } = await factory.newInstance<{ resolver: DnsTxtResolver }>(DKIM_RESOLVER_TOKEN, { name: "default" });
            this.dkimResolver = holder.resolver;
        }

        this.registry = await IssuerRegistry.fromManifest(this.settings.caManifest);
        const active = this.registry.active();
        this.logger.info(
            `Issuing with '${active.id}' (${this.registry.all().length} issuer(s) loaded); ` +
                `certificates are valid for ${this.settings.validityDays("signing")}/${this.settings.validityDays("encryption")}/${this.settings.validityDays("signing-encryption")} days.`
        );

        this.auth = new RequestAuthenticator(this);
        this.accounts = new AccountService(this);
        this.certificates = new CertificateService(this);
        this.crls = new CrlService(this);
        this.orders = new OrderService(this);
        this.challenges = new ChallengeService(this);
        this.ocsp = new OcspService(this);
        this.admin = new AdminService(this);
        this.reminders = new ReminderService(this);
        this.ready = true;
    }

    /** The address a request comes from, honouring `trusted_proxies`. */
    public clientIp(req: HttpRequest): string | undefined {
        return NetUtils.getIPAddress(req, this.trustedProxies);
    }

    /** The rate-limit subject for the client of `req`. */
    public ipSubject(req: HttpRequest): string {
        return ipSubject(this.clientIp(req));
    }
}
