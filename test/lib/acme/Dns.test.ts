///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { AcmeProblem } from "../../../src/lib/acme/AcmeProblem.js";
import { caaPermits, CaaRecord, CaaValidator, DnsChecks, DnsLookup, SystemDnsLookup } from "../../../src/lib/acme/Dns.js";

const ME = ["rapidmx.io"];

describe("caaPermits (RFC 8659 / RFC 9495)", () => {
    it("allows everything when no record restricts e-mail issuance", () => {
        expect(caaPermits([], ME)).toBe(true);
        expect(caaPermits([{ critical: 0, issue: "letsencrypt.org" }], ME)).toBe(true);
        expect(caaPermits([{ critical: 0, issuewild: ";" }, { critical: 0, iodef: "mailto:a@example.com" }], ME)).toBe(true);
    });

    it("allows only the CAs an issuemail record names", () => {
        expect(caaPermits([{ critical: 0, issuemail: "rapidmx.io" }], ME)).toBe(true);
        expect(caaPermits([{ critical: 0, issuemail: "other.example" }], ME)).toBe(false);
        expect(caaPermits([{ critical: 0, issuemail: "other.example" }, { critical: 0, issuemail: "rapidmx.io" }], ME)).toBe(true);
    });

    it("reads the issuer domain before any parameters, ignoring case and a trailing dot", () => {
        expect(caaPermits([{ critical: 0, issuemail: "RapidMX.io.; account=1234" }], ME)).toBe(true);
        expect(caaPermits([{ critical: 0, issuemail: " rapidmx.io ;validationmethods=email-reply-00" }], ME)).toBe(true);
        expect(caaPermits([{ critical: 0, issuemail: "evil-rapidmx.io" }], ME)).toBe(false);
        expect(caaPermits([{ critical: 0, issuemail: "rapidmx.io.evil.example" }], ME)).toBe(false);
    });

    it("treats issuemail \";\" as forbidding every CA", () => {
        expect(caaPermits([{ critical: 0, issuemail: ";" }], ME)).toBe(false);
        expect(caaPermits([{ critical: 0, issuemail: "" }], ME)).toBe(false);
    });

    it("refuses on a critical property it does not understand, and ignores a non-critical one", () => {
        expect(caaPermits([{ critical: 128, tbs: "x" }], ME)).toBe(false);
        expect(caaPermits([{ critical: 0, tbs: "x" }], ME)).toBe(true);
        expect(caaPermits([{ critical: 128, issuemail: "rapidmx.io" }], ME)).toBe(true);
    });

    it("matches any of several CA identities", () => {
        expect(caaPermits([{ critical: 0, issuemail: "acme.rapidmx.io" }], ["rapidmx.io", "acme.rapidmx.io"])).toBe(true);
    });
});

const lookup = (overrides: Partial<DnsLookup>): DnsLookup => ({
    resolveMx: async () => {
        throw Object.assign(new Error(), { code: "ENODATA" });
    },
    resolve4: async () => {
        throw Object.assign(new Error(), { code: "ENODATA" });
    },
    resolve6: async () => {
        throw Object.assign(new Error(), { code: "ENODATA" });
    },
    resolveCaa: async () => {
        throw Object.assign(new Error(), { code: "ENODATA" });
    },
    ...overrides,
});

const problemOf = async (promise: Promise<unknown>): Promise<string | undefined> => {
    try {
        await promise;
        return undefined;
    } catch (err) {
        return err instanceof AcmeProblem ? err.errorType : "not-a-problem";
    }
};

describe("DnsChecks.assertDeliverable", () => {
    it("accepts a domain with an MX, or with only an address record", async () => {
        expect(await problemOf(new DnsChecks(lookup({ resolveMx: async () => [{ exchange: "mx.example.org", priority: 10 }] }), ME).assertDeliverable("example.org"))).toBeUndefined();
        expect(await problemOf(new DnsChecks(lookup({ resolve4: async () => ["192.0.2.1"] }), ME).assertDeliverable("example.org"))).toBeUndefined();
        expect(await problemOf(new DnsChecks(lookup({ resolve6: async () => ["2001:db8::1"] }), ME).assertDeliverable("example.org"))).toBeUndefined();
        expect(await problemOf(new DnsChecks(lookup({ resolveMx: async () => [], resolve4: async () => ["192.0.2.1"] }), ME).assertDeliverable("example.org"))).toBeUndefined();
    });

    it("rejects a domain with no mail servers and no addresses, and a null MX", async () => {
        expect(await problemOf(new DnsChecks(lookup({}), ME).assertDeliverable("example.org"))).toBe("rejectedIdentifier");
        expect(await problemOf(new DnsChecks(lookup({ resolveMx: async () => [{ exchange: "", priority: 0 }] }), ME).assertDeliverable("example.org"))).toBe("rejectedIdentifier");
        expect(await problemOf(new DnsChecks(lookup({ resolveMx: async () => [{ exchange: ".", priority: 0 }] }), ME).assertDeliverable("example.org"))).toBe("rejectedIdentifier");
    });

    it("distinguishes a failed lookup from an empty answer", async () => {
        const servfail = Object.assign(new Error("boom"), { code: "ESERVFAIL" });
        expect(await problemOf(new DnsChecks(lookup({ resolveMx: async () => Promise.reject(servfail) }), ME).assertDeliverable("example.org"))).toBe("dns");
        expect(await problemOf(new DnsChecks(lookup({ resolve4: async () => Promise.reject(servfail) }), ME).assertDeliverable("example.org"))).toBe("dns");
        expect(await problemOf(new DnsChecks(lookup({ resolve6: async () => Promise.reject(servfail) }), ME).assertDeliverable("example.org"))).toBe("dns");
    });
});

describe("DnsChecks.assertCaaPermits", () => {
    const withCaa = (records: Record<string, CaaRecord[]>, calls: string[] = []) =>
        new DnsChecks(
            lookup({
                resolveCaa: async (name) => {
                    calls.push(name);
                    if (records[name]) {
                        return records[name];
                    }
                    throw Object.assign(new Error(), { code: "ENODATA" });
                },
            }),
            ME,
        );

    it("climbs from the domain to its parents and stops at the first record set (RFC 8659 §3)", async () => {
        const calls: string[] = [];
        const checks = withCaa({ "example.org": [{ critical: 0, issuemail: "rapidmx.io" }] }, calls);
        expect(await problemOf(checks.assertCaaPermits("a.b.example.org"))).toBeUndefined();
        expect(calls).toEqual(["a.b.example.org", "b.example.org", "example.org"]);
    });

    it("lets the closest record set win over a stricter parent", async () => {
        const checks = withCaa({ "example.org": [{ critical: 0, issuemail: ";" }], "mail.example.org": [{ critical: 0, issuemail: "rapidmx.io" }] });
        expect(await problemOf(checks.assertCaaPermits("mail.example.org"))).toBeUndefined();
        expect(await problemOf(checks.assertCaaPermits("other.example.org"))).toBe("caa");
    });

    it("permits a domain with no CAA records anywhere", async () => {
        expect(await problemOf(withCaa({}).assertCaaPermits("mail.example.org"))).toBeUndefined();
    });

    it("fails closed when a lookup fails", async () => {
        const checks = new DnsChecks(lookup({ resolveCaa: async () => Promise.reject(Object.assign(new Error(), { code: "ETIMEOUT" })) }), ME);
        expect(await problemOf(checks.assertCaaPermits("example.org"))).toBe("dns");
    });
});

describe("SystemDnsLookup", () => {
    it("wraps the resolver and takes explicit servers", () => {
        expect(() => new SystemDnsLookup(["127.0.0.1"])).not.toThrow();
        const system = new SystemDnsLookup();
        expect(typeof system.resolveMx).toBe("function");
        expect(typeof system.resolve4).toBe("function");
        expect(typeof system.resolve6).toBe("function");
        expect(typeof system.resolveCaa).toBe("function");
    });
});

describe("DnsChecks.assertCaaPermits with a DNSSEC validator", () => {
    type Answer = { status: "secure" | "insecure"; records: Array<{ critical: number; tag: string; value: string }> };
    const fail = (kind: string, reason: string) => Object.assign(new Error(reason), { kind, reason });

    /** A validator answering from a table; a name not in it is a validated empty answer. */
    const validator = (table: Record<string, Answer | Error>, calls: string[] = []): CaaValidator => ({
        resolveCaa: async (name) => {
            calls.push(name);
            const answer = table[name];
            if (answer instanceof Error) {
                throw answer;
            }
            return answer ?? { status: "secure", records: [] };
        },
    });
    const neverAsked: DnsLookup = lookup({
        resolveCaa: async () => {
            throw new Error("the unvalidated resolver must not be used for CAA");
        },
    });
    const checks = (table: Record<string, Answer | Error>, calls: string[] = []) => new DnsChecks(neverAsked, ME, validator(table, calls));

    it("uses the validator instead of the system resolver, climbing to the first record set", async () => {
        const calls: string[] = [];
        const c = checks({ "example.org": { status: "secure", records: [{ critical: 0, tag: "issuemail", value: "rapidmx.io" }] } }, calls);
        expect(await c.assertCaaPermits("a.example.org")).toBe("secure");
        expect(calls).toEqual(["a.example.org", "example.org"]);
    });

    it("enforces the policy of a validated record set", async () => {
        const c = checks({ "example.org": { status: "secure", records: [{ critical: 0, tag: "issuemail", value: "other.example" }] } });
        expect(await problemOf(c.assertCaaPermits("example.org"))).toBe("caa");
        const critical = checks({ "example.org": { status: "secure", records: [{ critical: 128, tag: "futureprop", value: "x" }] } });
        expect(await problemOf(critical.assertCaaPermits("example.org"))).toBe("caa");
    });

    it("reports secure only when every look-up was validated, insecure when one came from an unsigned zone", async () => {
        expect(await checks({}).assertCaaPermits("a.example.org")).toBe("secure");
        expect(await checks({ "example.org": { status: "insecure", records: [] } }).assertCaaPermits("a.example.org")).toBe("insecure");
        expect(await new DnsChecks(lookup({}), ME).assertCaaPermits("example.org")).toBe("unvalidated");
    });

    it("refuses the order when validation fails (bogus) or cannot be completed (indeterminate)", async () => {
        const bogus = checks({ "example.org": fail("bogus", "RRSIG has expired") });
        await expect(bogus.assertCaaPermits("example.org")).rejects.toThrow(/DNSSEC validation .*RRSIG has expired/);
        expect(await problemOf(bogus.assertCaaPermits("example.org"))).toBe("dns");
        const unknown = checks({ org: fail("indeterminate", "no answer from any server") });
        expect(await problemOf(unknown.assertCaaPermits("example.org"))).toBe("dns");
        const plain = checks({ "example.org": new Error("boom") });
        expect(await problemOf(plain.assertCaaPermits("example.org"))).toBe("dns");
    });

    it("bounds the length of an error reason that reaches the applicant", async () => {
        const c = checks({ "example.org": fail("bogus", "x".repeat(5000)) });
        await expect(c.assertCaaPermits("example.org")).rejects.toSatisfy((err: Error) => err.message.length < 500);
    });
});

describe("DnsChecks.assertCaaPermits deadline", () => {
    it("refuses with a dns problem when the validator never answers", async () => {
        vi.useFakeTimers();
        try {
            const hung: CaaValidator = { resolveCaa: () => new Promise(() => undefined) };
            const pending = problemOf(new DnsChecks(lookup({}), ME, hung).assertCaaPermits("example.org"));
            await vi.advanceTimersByTimeAsync(31_000);
            expect(await pending).toBe("dns");
        } finally {
            vi.useRealTimers();
        }
    });
});
