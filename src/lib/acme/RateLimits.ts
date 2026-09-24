///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import * as net from "net";
import { AcmeProblem } from "./AcmeProblem.js";
import { AcmeStore, BucketPolicy } from "./AcmeStore.js";

/** What a limit's key identifies. */
export type LimitScope = "ip" | "account" | "email" | "domain" | "accountEmail";

/** The name of every limit this CA enforces. */
export type LimitName =
    | "endpointNonce"
    | "endpointNewAccount"
    | "endpointNewOrder"
    | "endpointRevoke"
    | "endpointDirectory"
    | "endpointOther"
    | "newAccountsPerIp"
    | "newOrdersPerAccount"
    | "failedAuthorizations"
    | "certificatesPerEmail"
    | "certificatesPerDomain"
    | "challengeMailsPerAccountEmailHour"
    | "challengeMailsPerEmailHour"
    | "challengeMailsPerEmailDay"
    | "challengeMailsPerDomainHour"
    | "challengeMailsPerAccountHour"
    | "challengeMailsPerIpHour"
    | "reminderMailsPerContactDay"
    | "finalizesPerAccount"
    | "adminAuthFailuresPerIp";

/** One rate limit: `burst` tokens, refilled `count` per `periodSeconds`. */
export interface LimitDefinition {
    scope: LimitScope;
    count: number;
    periodSeconds: number;
    burst: number;
    /** The anchor on the rate-limit page and the human name used in error messages. */
    anchor: string;
    what: string;
}

const HOUR = 3600;
const DAY = 24 * HOUR;

/**
 * The limits, modelled on Let's Encrypt's (https://letsencrypt.org/docs/rate-limits/). The endpoint limits are
 * requests per second per IP address; the rest protect the CA's own resources and – the last four – the third parties
 * this CA sends mail to.
 */
export const DEFAULT_LIMITS: Readonly<Record<LimitName, LimitDefinition>> = {
    endpointNonce: { scope: "ip", count: 20, periodSeconds: 1, burst: 10, anchor: "overall-requests", what: "new-nonce requests" },
    endpointNewAccount: { scope: "ip", count: 5, periodSeconds: 1, burst: 15, anchor: "overall-requests", what: "new-account requests" },
    endpointNewOrder: { scope: "ip", count: 100, periodSeconds: 1, burst: 200, anchor: "overall-requests", what: "new-order requests" },
    endpointRevoke: { scope: "ip", count: 10, periodSeconds: 1, burst: 100, anchor: "overall-requests", what: "revoke-cert requests" },
    endpointDirectory: { scope: "ip", count: 40, periodSeconds: 1, burst: 40, anchor: "overall-requests", what: "directory requests" },
    endpointOther: { scope: "ip", count: 250, periodSeconds: 1, burst: 125, anchor: "overall-requests", what: "ACME requests" },
    newAccountsPerIp: { scope: "ip", count: 10, periodSeconds: 3 * HOUR, burst: 10, anchor: "new-registrations-per-ip-address", what: "new accounts from this IP address" },
    newOrdersPerAccount: { scope: "account", count: 300, periodSeconds: 3 * HOUR, burst: 300, anchor: "new-orders-per-account", what: "new orders from this account" },
    failedAuthorizations: { scope: "accountEmail", count: 5, periodSeconds: HOUR, burst: 5, anchor: "authorization-failures-per-identifier-per-account", what: "failed authorizations for this address from this account" },
    certificatesPerEmail: { scope: "email", count: 5, periodSeconds: 7 * DAY, burst: 5, anchor: "new-certificates-per-email-address", what: "certificates for this address" },
    certificatesPerDomain: { scope: "domain", count: 200, periodSeconds: 7 * DAY, burst: 200, anchor: "new-certificates-per-email-domain", what: "certificates for addresses at this domain" },
    // The mail limits trade two harms against each other: too loose and the CA can be used to flood an inbox; too tight and a
    // stranger can use up the budget of an address (or a big provider's whole domain) and keep its owner from getting a
    // certificate. The tightest budget is therefore per (account, address) - what one stranger can cause alone - while the
    // budgets shared by everybody are much larger and only stop a flood.
    challengeMailsPerAccountEmailHour: { scope: "accountEmail", count: 3, periodSeconds: HOUR, burst: 3, anchor: "challenge-e-mails-per-address", what: "verification e-mails to this address from this account" },
    challengeMailsPerEmailHour: { scope: "email", count: 12, periodSeconds: HOUR, burst: 12, anchor: "challenge-e-mails-per-address", what: "verification e-mails to this address" },
    challengeMailsPerEmailDay: { scope: "email", count: 40, periodSeconds: DAY, burst: 40, anchor: "challenge-e-mails-per-address", what: "verification e-mails to this address" },
    challengeMailsPerDomainHour: { scope: "domain", count: 600, periodSeconds: HOUR, burst: 600, anchor: "challenge-e-mails-per-domain", what: "verification e-mails to addresses at this domain" },
    challengeMailsPerAccountHour: { scope: "account", count: 60, periodSeconds: HOUR, burst: 60, anchor: "challenge-e-mails-per-account", what: "verification e-mails from this account" },
    challengeMailsPerIpHour: { scope: "ip", count: 120, periodSeconds: HOUR, burst: 120, anchor: "challenge-e-mails-per-ip-address", what: "verification e-mails caused from this IP address" },
    // An account's contact address is whatever its holder typed, so a stranger's address can be named: this caps what a flood of
    // accounts could make the reminders send to it (one e-mail per account per run already lists everything that is due).
    reminderMailsPerContactDay: { scope: "email", count: 48, periodSeconds: DAY, burst: 24, anchor: "reminder-e-mails-per-contact-address", what: "expiry reminder e-mails to this address" },
    adminAuthFailuresPerIp: { scope: "ip", count: 20, periodSeconds: HOUR, burst: 10, anchor: "operator-api-authentication-failures", what: "failed operator API authentications from this IP address" },
    finalizesPerAccount: { scope: "account", count: 20, periodSeconds: HOUR, burst: 10, anchor: "finalize-requests-per-account", what: "finalize requests from this account" },
};

/** A configured change to one limit for one subject (`acme.rate_limits.overrides`). */
export interface RateLimitOverride {
    limit: LimitName;
    /** The subject the override applies to: an account id, an address, a domain or a normalized IP. */
    subject: string;
    count?: number;
    period_seconds?: number;
    burst?: number;
}

/** Options of `AcmeRateLimiter`. */
export interface RateLimiterOptions {
    /** `false` turns every limit off (tests, small private CAs). */
    enabled?: boolean;
    overrides?: RateLimitOverride[];
    /** The base URL of the page that documents the limits; each rejection links to `<helpUrl>#<anchor>`. */
    helpUrl?: string;
    /** The limit table to enforce. Defaults to `DEFAULT_LIMITS`. */
    limits?: Readonly<Record<LimitName, LimitDefinition>>;
}

/** Formats a number of seconds like Go's `time.Duration` does in Boulder's messages: `3h0m0s`. */
function duration(seconds: number): string {
    const d: number = Math.floor(seconds / DAY);
    const h: number = Math.floor((seconds % DAY) / HOUR);
    const m: number = Math.floor((seconds % HOUR) / 60);
    const s: number = seconds % 60;
    return `${d > 0 ? `${d * 24 + h}h` : h > 0 ? `${h}h` : ""}${m > 0 || h > 0 || d > 0 ? `${m}m` : ""}${s}s`;
}

/**
 * The address an IP rate limit is counted against: an IPv4 address as is; an IPv4-mapped IPv6 address as its IPv4
 * address; any other IPv6 address as its /48 – one customer typically holds a whole /48 (or /64), so counting single
 * IPv6 addresses would let one host mint unlimited identities.
 */
export function ipSubject(address: string | undefined): string {
    if (!address) {
        return "unknown";
    }
    const mapped: RegExpExecArray | null = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(address);
    if (mapped) {
        return mapped[1];
    }
    if (net.isIPv6(address)) {
        const groups: string[] = expandIpv6(address);
        return `${groups.slice(0, 3).join(":")}::/48`;
    }
    return address;
}

/** Expands an IPv6 address to its 8 groups of 4 hex digits. */
function expandIpv6(address: string): string[] {
    const clean: string = address.split("%")[0].toLowerCase();
    const [head, tail] = clean.split("::");
    const headGroups: string[] = head ? head.split(":") : [];
    const tailGroups: string[] = tail ? tail.split(":") : [];
    const missing: number = 8 - headGroups.length - tailGroups.length;
    const groups: string[] = [...headGroups, ...(clean.includes("::") ? Array(Math.max(missing, 0)).fill("0") : []), ...tailGroups];
    return groups.map((g) => g.padStart(4, "0"));
}

/**
 * Enforces the rate limits with token buckets in an `AcmeStore`.
 *
 * A rejection is an `AcmeProblem` `rateLimited` (HTTP 429) whose `Retry-After` says when a retry can work and whose
 * message names the limit, like Let's Encrypt's. `spend()` takes tokens; `check()` only looks (used to refuse early
 * without consuming); `refund()` gives tokens back (a successful validation refunds its failure token).
 *
 * @author Jean-Philippe Steinmetz
 */
export class AcmeRateLimiter {
    private readonly store: AcmeStore;
    private readonly enabled: boolean;
    private readonly overrides: Map<string, RateLimitOverride> = new Map();
    private readonly helpUrl?: string;
    private readonly limits: Readonly<Record<LimitName, LimitDefinition>>;
    private readonly now: () => number;

    /** @param now The clock (ms since epoch) used only to word the retry time in messages. */
    constructor(store: AcmeStore, options: RateLimiterOptions = {}, now: () => number = Date.now) {
        this.store = store;
        this.enabled = options.enabled !== false;
        this.helpUrl = options.helpUrl;
        this.limits = options.limits ?? DEFAULT_LIMITS;
        this.now = now;
        for (const override of options.overrides ?? []) {
            this.overrides.set(`${override.limit}|${override.subject.toLowerCase()}`, override);
        }
    }

    /** The definition of `name` after any override for `subject`. */
    public definition(name: LimitName, subject: string): LimitDefinition {
        const base: LimitDefinition = this.limits[name];
        const override: RateLimitOverride | undefined = this.overrides.get(`${name}|${subject.toLowerCase()}`);
        if (!override) {
            return base;
        }
        const count: number = override.count ?? base.count;
        return { ...base, count, periodSeconds: override.period_seconds ?? base.periodSeconds, burst: override.burst ?? count };
    }

    private policy(def: LimitDefinition): BucketPolicy {
        return { intervalMs: (def.periodSeconds * 1000) / def.count, burst: def.burst };
    }

    /**
     * Takes `cost` tokens from the bucket for `subject`.
     *
     * @throws `rateLimited` when there are not enough.
     */
    public async spend(name: LimitName, subject: string, cost: number = 1): Promise<void> {
        await this.run(name, subject, cost, "spend");
    }

    /**
     * Looks at the bucket for `subject` without taking anything.
     *
     * @throws `rateLimited` when `cost` tokens are not available.
     */
    public async check(name: LimitName, subject: string, cost: number = 1): Promise<void> {
        await this.run(name, subject, cost, "check");
    }

    /** Gives `cost` tokens back to the bucket for `subject`. */
    public async refund(name: LimitName, subject: string, cost: number = 1): Promise<void> {
        if (this.enabled) {
            await this.store.bucket(`${name}:${subject.toLowerCase()}`, this.policy(this.definition(name, subject)), cost, "refund");
        }
    }

    private async run(name: LimitName, subject: string, cost: number, mode: "spend" | "check"): Promise<void> {
        if (!this.enabled) {
            return;
        }
        const def: LimitDefinition = this.definition(name, subject);
        const result = await this.store.bucket(`${name}:${subject.toLowerCase()}`, this.policy(def), cost, mode);
        if (result.allowed) {
            return;
        }
        // Rounded UP to the second: the time named must never be earlier than a retry can succeed.
        const retryAt: string = new Date(Math.ceil((this.now() + result.retryAfterMs) / 1000) * 1000).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
        const window: string = def.periodSeconds === 1 ? "second" : `${duration(def.periodSeconds)}`;
        const detail: string =
            `too many ${def.what} (${def.count}${def.periodSeconds === 1 ? "/s" : ` in the last ${window}`}), retry after ${retryAt}` +
            (this.helpUrl ? `: see ${this.helpUrl}#${def.anchor}` : "");
        throw AcmeProblem.rateLimited(detail, result.retryAfterMs / 1000, this.helpUrl ? `${this.helpUrl}#${def.anchor}` : undefined);
    }
}
