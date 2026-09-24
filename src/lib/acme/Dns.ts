///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { Resolver } from "dns/promises";
import { AcmeProblem } from "./AcmeProblem.js";

/** A CAA resource record as Node's resolver returns it: the property tag is the key of the value. */
export interface CaaRecord {
    critical?: number;
    [tag: string]: unknown;
}

/** The DNS look-ups this CA does. Injectable so tests never touch the network. */
export interface DnsLookup {
    resolveMx(name: string): Promise<Array<{ exchange: string; priority: number }>>;
    resolve4(name: string): Promise<string[]>;
    resolve6(name: string): Promise<string[]>;
    resolveCaa(name: string): Promise<CaaRecord[]>;
}

/** A `DnsLookup` backed by Node's resolver (c-ares), optionally against specific servers. */
export class SystemDnsLookup implements DnsLookup {
    private readonly resolver: Resolver = new Resolver({ timeout: 4000, tries: 2 });

    constructor(servers: string[] = []) {
        if (servers.length > 0) {
            this.resolver.setServers(servers);
        }
    }

    public resolveMx(name: string): Promise<Array<{ exchange: string; priority: number }>> {
        return this.resolver.resolveMx(name);
    }

    public resolve4(name: string): Promise<string[]> {
        return this.resolver.resolve4(name);
    }

    public resolve6(name: string): Promise<string[]> {
        return this.resolver.resolve6(name);
    }

    public resolveCaa(name: string): Promise<CaaRecord[]> {
        return this.resolver.resolveCaa(name) as Promise<CaaRecord[]>;
    }
}

/** The tags this CA understands. A critical record with any other tag forbids issuance (RFC 8659 §4.2). */
const KNOWN_CAA_TAGS: readonly string[] = ["issue", "issuewild", "iodef", "issuemail", "contactemail", "contactphone"];

/** DNS errors that mean "there is no such record", as opposed to "the lookup failed". */
function isNoData(err: any): boolean {
    return err?.code === "ENODATA" || err?.code === "ENOTFOUND" || err?.code === "ENOENT";
}

/**
 * Evaluates a CAA record set for a mailbox certificate (RFC 8659 with RFC 9495's `issuemail` property).
 *
 * Only `issuemail` restricts e-mail certificates: a domain with no `issuemail` record allows any CA, a domain with one
 * allows exactly the CAs it names (`issuemail ";"` allows none). A critical record with a tag this CA does not
 * understand forbids issuance.
 *
 * @param records The relevant CAA record set (the closest one to the domain).
 * @param identities The names this CA is known by in CAA records.
 * @returns `true` if the record set permits this CA.
 */
export function caaPermits(records: CaaRecord[], identities: readonly string[]): boolean {
    const wanted: string[] = identities.map((i) => i.trim().toLowerCase().replace(/\.$/, ""));
    let restricted = false;
    let allowed = false;
    for (const record of records) {
        const critical: boolean = ((record.critical ?? 0) & 0x80) !== 0;
        const tags: string[] = Object.keys(record).filter((k) => k !== "critical");
        for (const tag of tags) {
            const lower: string = tag.toLowerCase();
            if (!KNOWN_CAA_TAGS.includes(lower)) {
                if (critical) {
                    return false;
                }
                continue;
            }
            if (lower === "issuemail") {
                restricted = true;
                const issuer: string = String(record[tag]).split(";")[0].trim().toLowerCase().replace(/\.$/, "");
                if (issuer !== "" && wanted.includes(issuer)) {
                    allowed = true;
                }
            }
        }
    }
    return !restricted || allowed;
}

/**
 * The look-ups a mailbox certificate order depends on: can the domain receive the verification e-mail at all, and does
 * its CAA policy allow this CA.
 *
 * @author Jean-Philippe Steinmetz
 */
export class DnsChecks {
    private readonly lookup: DnsLookup;
    private readonly caaIdentities: readonly string[];

    constructor(lookup: DnsLookup, caaIdentities: readonly string[]) {
        this.lookup = lookup;
        this.caaIdentities = caaIdentities;
    }

    /**
     * Refuses a domain that cannot receive mail (no MX and no address records, or a null MX per RFC 7505), so this CA never
     * tries to deliver a verification e-mail into the void and cannot be used to probe arbitrary names.
     *
     * @throws `rejectedIdentifier` when the domain cannot receive mail, `dns` when the lookup itself failed.
     */
    public async assertDeliverable(domain: string): Promise<void> {
        try {
            const mx = await this.lookup.resolveMx(domain);
            if (mx.length > 0) {
                if (mx.every((record) => record.exchange === "" || record.exchange === ".")) {
                    throw new AcmeProblem("rejectedIdentifier", `The domain ${domain} does not accept mail (null MX).`);
                }
                return;
            }
        } catch (err: any) {
            if (err instanceof AcmeProblem) {
                throw err;
            }
            if (!isNoData(err)) {
                throw new AcmeProblem("dns", `DNS lookup for the mail servers of ${domain} failed: ${err?.code ?? "error"}.`);
            }
        }
        for (const resolve of [() => this.lookup.resolve4(domain), () => this.lookup.resolve6(domain)]) {
            try {
                if ((await resolve()).length > 0) {
                    return;
                }
            } catch (err: any) {
                if (!isNoData(err)) {
                    throw new AcmeProblem("dns", `DNS lookup for ${domain} failed: ${err?.code ?? "error"}.`);
                }
            }
        }
        throw new AcmeProblem("rejectedIdentifier", `The domain ${domain} has no mail servers or address records, so it cannot receive mail.`);
    }

    /**
     * Checks the domain's CAA policy (RFC 8659 §3: the closest record set found climbing from the domain to the root).
     *
     * @throws `caa` when the policy forbids this CA, `dns` when a lookup failed (failing closed: issuing without knowing the
     * policy is worse than asking the applicant to retry).
     */
    public async assertCaaPermits(domain: string): Promise<void> {
        const labels: string[] = domain.toLowerCase().split(".");
        for (let i = 0; i < labels.length; i++) {
            const name: string = labels.slice(i).join(".");
            let records: CaaRecord[];
            try {
                records = await this.lookup.resolveCaa(name);
            } catch (err: any) {
                if (isNoData(err)) {
                    continue;
                }
                throw new AcmeProblem("dns", `DNS CAA lookup for ${name} failed: ${err?.code ?? "error"}.`);
            }
            if (records.length === 0) {
                continue;
            }
            if (!caaPermits(records, this.caaIdentities)) {
                throw new AcmeProblem("caa", `The CAA records at ${name} do not authorize this CA to issue e-mail certificates (issuemail: ${this.caaIdentities.join(", ")}).`);
            }
            return;
        }
    }
}
