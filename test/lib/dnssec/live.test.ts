///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { DnssecError, DnssecResolver, RRTYPE } from "../../../src/lib/dnssec/index.js";

/**
 * Tests against the real DNS and the real root trust anchor. They need the network and the resolvers of this machine (or
 * 8.8.8.8 and 1.1.1.1 when it has none), so they only run when `ACME_LIVE_DNS=1` is set.
 */
describe.skipIf(process.env.ACME_LIVE_DNS !== "1")("live DNSSEC validation against the real root", () => {
    const resolver = (): DnssecResolver => new DnssecResolver({ timeoutMs: 6000 });

    it("validates the CAA records of a signed zone that has them (cloudflare.com)", async () => {
        const result = await resolver().resolveCaa("cloudflare.com");
        expect(result.status).toBe("secure");
        expect(result.records.length).toBeGreaterThan(0);
        expect(result.records.some((r) => r.tag === "issue")).toBe(true);
    }, 30000);

    it("validates the absence of CAA records in a signed zone (example.com)", async () => {
        expect(await resolver().resolveCaa("example.com")).toEqual({ status: "secure", records: [] });
    }, 30000);

    it("accepts the unsigned answer of an unsigned zone as insecure (google.com)", async () => {
        const result = await resolver().resolveCaa("google.com");
        expect(result.status).toBe("insecure");
    }, 30000);

    it("validates NXDOMAIN under a signed zone", async () => {
        const name = `does-not-exist-${Math.random().toString(36).slice(2)}.example.com`;
        expect(await resolver().resolve(name, RRTYPE.CAA)).toEqual({ status: "secure", rdata: [], nxdomain: true });
    }, 30000);

    it("validates an ancestor of a signed name and a TLD", async () => {
        expect((await resolver().resolveCaa("www.cloudflare.com")).status).toBe("secure");
        expect((await resolver().resolveCaa("org")).status).toBe("secure");
    }, 30000);

    it("rejects the deliberately broken dnssec-failed.org as bogus, even though the resolver is asked not to check (CD)", async () => {
        const error = await resolver()
            .resolveCaa("dnssec-failed.org")
            .then(
                () => undefined,
                (err: unknown) => err
            );
        expect(error).toBeInstanceOf(DnssecError);
        expect((error as DnssecError).kind).toBe("bogus");
    }, 30000);
});
