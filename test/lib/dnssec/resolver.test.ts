///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { DnssecError } from "../../../src/lib/dnssec/types.js";
import { DnssecResolver, DnssecResolverOptions } from "../../../src/lib/dnssec/validator.js";
import {
    aRdata,
    buildStandardWorld,
    caaRdata,
    makeResolver,
    signRrset,
    StandardWorld,
    T,
    T0,
    TestWorld,
    TestZone,
    txtRdata,
} from "./zones.js";

let std: StandardWorld;

beforeAll(() => {
    std = buildStandardWorld();
}, 60000);

afterEach(() => {
    std.world.hook = undefined;
    std.world.compress = true;
    std.world.queries.length = 0;
});

function resolver(overrides: Partial<DnssecResolverOptions> = {}): DnssecResolver {
    return makeResolver(std.world, overrides);
}

async function failure(promise: Promise<unknown>): Promise<DnssecError> {
    try {
        await promise;
    } catch (err) {
        expect(err).toBeInstanceOf(DnssecError);
        return err as DnssecError;
    }
    throw new Error("expected the lookup to fail");
}

function hex(rdata: Uint8Array[]): string[] {
    return rdata.map((r) => Buffer.from(r).toString("hex"));
}

describe("secure positive answers", () => {
    it.each([
        ["example.com", "ECDSA P-256"],
        ["p384.com", "ECDSA P-384"],
        ["ed25519.com", "Ed25519"],
        ["ed448.com", "Ed448"],
        ["rsa.com", "RSASHA256"],
        ["rsa512.com", "RSASHA512"],
        ["sha384.com", "a SHA-384 DS"],
        ["secure.net", "an NSEC zone under an NSEC zone"],
        ["secure.org", "an NSEC3 zone under an NSEC3 zone"],
        ["roll.com", "a key rollover with two published KSKs"],
    ])("validates the CAA record of %s (%s)", async (name) => {
        const result = await resolver().resolveCaa(name);
        expect(result.status).toBe("secure");
        expect(result.records).toEqual([{ critical: 0, tag: "issue", value: `ca.${name}` }]);
    });

    it("asks only for the root DNSKEY, the DS and DNSKEY of each zone, and the final RRset", async () => {
        await resolver().resolveCaa("example.com");
        expect(std.world.queries.map((q) => `${q.name}/${q.type}`)).toEqual([
            "/48",
            "com/43",
            "com/48",
            "example.com/43",
            "example.com/48",
            "example.com/257",
        ]);
    });

    it("returns the raw RDATA from resolve()", async () => {
        const result = await resolver().resolve("host.example.com", T.A);
        expect(result).toEqual({ status: "secure", rdata: [expect.anything()], nxdomain: false });
        expect(hex(result.rdata)).toEqual(["c0000201"]);
    });

    it("accepts names in any case with a trailing dot", async () => {
        const result = await resolver().resolveCaa("EXAMPLE.Com.");
        expect(result.status).toBe("secure");
        expect(result.records).toHaveLength(1);
    });

    it("validates TXT, MX and DNSKEY RRsets, and the DS RRset from the parent", async () => {
        expect((await resolver().resolve("txt.example.com", T.TXT)).status).toBe("secure");
        const mx = await resolver().resolve("mx.example.com", T.MX);
        expect(mx.status).toBe("secure");
        expect(hex(mx.rdata)).toEqual(["000a04686f7374076578616d706c6503636f6d00"]);
        const dnskey = await resolver().resolve("example.com", T.DNSKEY);
        expect(dnskey).toMatchObject({ status: "secure", nxdomain: false });
        expect(dnskey.rdata).toHaveLength(2);
        const ds = await resolver().resolve("example.com", T.DS);
        expect(ds).toMatchObject({ status: "secure" });
        expect(ds.rdata).toHaveLength(1);
    });

    it("works without name compression and with mixed-case names inside RDATA", async () => {
        std.world.compress = false;
        const result = await resolver().resolve("mixed.example.com", T.A);
        expect(result.status).toBe("secure");
        expect(hex(result.rdata)).toEqual(["c0000201"]);
    });

    it("refuses an RR type it cannot canonicalise instead of guessing", async () => {
        const err = await failure(resolver().resolve("hinfo.example.com", 13));
        expect(err.kind).toBe("indeterminate");
    });
});

describe("secure denial of existence", () => {
    it("NODATA through NSEC", async () => {
        const result = await resolver().resolve("host.example.com", T.TXT);
        expect(result).toEqual({ status: "secure", rdata: [], nxdomain: false });
    });

    it("NXDOMAIN through NSEC, with the wildcard proof", async () => {
        const result = await resolver().resolve("nope.example.com", T.CAA);
        expect(result).toEqual({ status: "secure", rdata: [], nxdomain: true });
        expect(await resolver().resolveCaa("nope.example.com")).toEqual({ status: "secure", records: [] });
    });

    it("NODATA at the apex through NSEC (example.com has no TXT)", async () => {
        expect(await resolver().resolve("example.com", T.TXT)).toEqual({
            status: "secure",
            rdata: [],
            nxdomain: false,
        });
    });

    it("NODATA and NXDOMAIN through NSEC3", async () => {
        expect(await resolver().resolve("host.p384.com", T.TXT)).toEqual({
            status: "secure",
            rdata: [],
            nxdomain: false,
        });
        expect(await resolver().resolve("nope.p384.com", T.CAA)).toEqual({
            status: "secure",
            rdata: [],
            nxdomain: true,
        });
        expect(await resolver().resolve("nope.secure.org", T.CAA)).toEqual({
            status: "secure",
            rdata: [],
            nxdomain: true,
        });
        expect(await resolver().resolve("nope.rsa512.com", T.CAA)).toEqual({
            status: "secure",
            rdata: [],
            nxdomain: true,
        });
    });

    it("compact denial of existence (RFC 9824): NXNAME in the NSEC bitmap means NXDOMAIN, an NSEC without it means NODATA", async () => {
        expect(await resolver().resolve("nope.compact.com", T.CAA)).toEqual({
            status: "secure",
            rdata: [],
            nxdomain: true,
        });
        expect(await resolver().resolve("host.compact.com", T.TXT)).toEqual({
            status: "secure",
            rdata: [],
            nxdomain: false,
        });
        expect(await resolver().resolve("a.b.nope.compact.com", T.CAA)).toEqual({
            status: "secure",
            rdata: [],
            nxdomain: true,
        });
        expect((await resolver().resolveCaa("compact.com")).records).toHaveLength(1);
    });

    it("an NXDOMAIN under a name that does not exist either", async () => {
        expect(await resolver().resolve("a.b.c.example.com", T.CAA)).toEqual({
            status: "secure",
            rdata: [],
            nxdomain: true,
        });
        expect(await resolver().resolve("a.b.c.p384.com", T.CAA)).toEqual({
            status: "secure",
            rdata: [],
            nxdomain: true,
        });
    });

    it("an empty non-terminal has no data but exists (NSEC and NSEC3)", async () => {
        expect(await resolver().resolve("ent.example.com", T.CAA)).toEqual({
            status: "secure",
            rdata: [],
            nxdomain: false,
        });
        expect(await resolver().resolve("ent.p384.com", T.CAA)).toEqual({
            status: "secure",
            rdata: [],
            nxdomain: false,
        });
        expect(await resolver().resolve("ent.secure.net", T.CAA)).toEqual({
            status: "secure",
            rdata: [],
            nxdomain: false,
        });
        expect(await resolver().resolve("ent.secure.org", T.CAA)).toEqual({
            status: "secure",
            rdata: [],
            nxdomain: false,
        });
    });

    it("an ancestor lookup as the caller climbs it: the parent zone's apex is validated on its own", async () => {
        expect((await resolver().resolveCaa("com")).status).toBe("secure");
        expect((await resolver().resolveCaa("org")).status).toBe("secure");
        expect(await resolver().resolveCaa("host.example.com")).toEqual({ status: "secure", records: [] });
    });

    it("NXDOMAIN inside an opt-out zone cannot be proven secure: the name may be an unsigned delegation", async () => {
        const result = await resolver().resolve("nope.ed25519.com", T.CAA);
        expect(result).toEqual({ status: "insecure", rdata: [], nxdomain: true });
    });

    it("NXDOMAIN inside an opt-out TLD for a name that is not registered is insecure too", async () => {
        const result = await resolver().resolve("not-registered.com", T.CAA);
        expect(result.status).toBe("insecure");
        expect(result.rdata).toEqual([]);
    });
});

describe("wildcards", () => {
    it.each(["example.com", "p384.com", "secure.net", "secure.org", "rsa.com"])(
        "a wildcard expansion in %s is secure with its proof of non-existence",
        async (zone) => {
            const result = await resolver().resolveCaa(`foo.wild.${zone}`);
            expect(result).toEqual({ status: "secure", records: [{ critical: 0, tag: "issue", value: "wild.test" }] });
        }
    );

    it("expands below a name that does not exist either", async () => {
        const result = await resolver().resolveCaa("x.y.wild.example.com");
        expect(result.status).toBe("secure");
        expect(result.records).toHaveLength(1);
    });

    it("does not expand over a name that exists", async () => {
        expect(await resolver().resolve("a.wild.example.com", T.CAA)).toEqual({
            status: "secure",
            rdata: [],
            nxdomain: false,
        });
    });

    it("a wildcard without the requested type is NODATA (NSEC and NSEC3)", async () => {
        expect(await resolver().resolve("foo.wild.example.com", T.A)).toEqual({
            status: "secure",
            rdata: [],
            nxdomain: false,
        });
        expect(await resolver().resolve("foo.wild.p384.com", T.A)).toEqual({
            status: "secure",
            rdata: [],
            nxdomain: false,
        });
    });

    it("a wildcard at the apex level does not cover a name below an existing empty non-terminal", async () => {
        const top = await resolver().resolve("foo.wc.com", T.TXT);
        expect(top.status).toBe("secure");
        expect(hex(top.rdata)).toEqual([Buffer.from(txtRdata("top")).toString("hex")]);
        expect(await resolver().resolve("foo.mid.wc.com", T.TXT)).toEqual({
            status: "secure",
            rdata: [],
            nxdomain: true,
        });
    });
});

describe("CNAME", () => {
    it("follows a chain within a zone", async () => {
        const result = await resolver().resolveCaa("c1.example.com");
        expect(result).toEqual({ status: "secure", records: [{ critical: 0, tag: "issue", value: "chained.test" }] });
    });

    it("follows a CNAME into another signed zone with a fresh chain of trust", async () => {
        const result = await resolver().resolve("xz.example.com", T.A);
        expect(result.status).toBe("secure");
        expect(hex(result.rdata)).toEqual(["c0000201"]);
        expect(std.world.queries.some((q) => q.name === "p384.com" && q.type === T.DNSKEY)).toBe(true);
    });

    it("reports the weakest status of the chain when the target is in an unsigned zone", async () => {
        const result = await resolver().resolve("toinsecure.example.com", T.A);
        expect(result.status).toBe("insecure");
        expect(hex(result.rdata)).toEqual(["c0000201"]);
    });

    it("validates a CNAME synthesised from a wildcard", async () => {
        const result = await resolver().resolve("foo.cwild.example.com", T.A);
        expect(result.status).toBe("secure");
        expect(hex(result.rdata)).toEqual(["c0000201"]);
    });

    it("gives up on a loop and on a chain longer than allowed", async () => {
        const loop = await failure(resolver().resolveCaa("loop1.example.com"));
        expect(loop.kind).toBe("indeterminate");
        expect(loop.reason).toMatch(/CNAME/);
        const shallow = await failure(resolver({ maxCnameDepth: 1 }).resolveCaa("c1.example.com"));
        expect(shallow.kind).toBe("indeterminate");
    });

    it("does not follow a CNAME when the CNAME itself is asked for", async () => {
        const result = await resolver().resolve("www.example.com", T.CNAME);
        expect(result.status).toBe("secure");
        expect(result.rdata).toHaveLength(1);
    });
});

describe("insecure delegations", () => {
    it.each([
        ["unsigned.com", "an NSEC3 opt-out span in the parent"],
        ["unsigned.net", "an NSEC record matching the delegation"],
        ["unsigned.org", "an NSEC3 record matching the delegation"],
        ["below.example.insecure", "an unsigned TLD (NSEC at the root) and an unsigned zone below it"],
        ["unsupported.com", "a DS RRset with only unsupported algorithms and digests"],
        ["insecure", "the unsigned TLD's own apex"],
    ])("accepts the unsigned answer for %s (%s)", async (name) => {
        const result = await resolver().resolveCaa(name);
        expect(result.status).toBe("insecure");
        expect(result.records).toEqual([
            { critical: 0, tag: "issue", value: name === "insecure" ? "ca.insecure" : `ca.${name}` },
        ]);
    });

    it("stops walking at the insecure delegation and never asks for the child's DNSKEY", async () => {
        await resolver().resolveCaa("unsigned.net");
        expect(std.world.queries.map((q) => `${q.name}/${q.type}`)).toEqual([
            "/48",
            "net/43",
            "net/48",
            "unsigned.net/43",
            "unsigned.net/257",
        ]);
    });

    it("keeps names below an insecure delegation insecure, including a name that does not exist there", async () => {
        expect(await resolver().resolve("a.b.unsigned.net", T.CAA)).toEqual({
            status: "insecure",
            rdata: [],
            nxdomain: true,
        });
        expect(await resolver().resolve("host.unsigned.org", T.A)).toMatchObject({ status: "insecure" });
    });

    it("treats a DS that names a SHA-1 based algorithm as unusable even with a good digest type (RFC 8624)", async () => {
        for (const algorithm of [5, 7]) {
            std.world.hook = (q, response) => {
                if (q.name === "example.com" && q.type === T.DS) {
                    const ds = [
                        {
                            ...response.answer[0],
                            rdata: Buffer.concat([Buffer.from([0x04, 0xd2, algorithm, 2]), Buffer.alloc(32, 1)]),
                        },
                    ];
                    response.answer = [...ds, signRrset("com", std.com.zsk, ds)];
                }
            };
            expect((await resolver().resolveCaa("example.com")).status).toBe("insecure");
        }
    });

    it("uses the supported DS of a set that also holds unsupported ones", async () => {
        std.world.hook = (q, response) => {
            if (q.name === "example.com" && q.type === T.DS) {
                const ds = response.answer.filter((r) => r.type === T.DS);
                ds.push({ ...ds[0], rdata: Buffer.concat([Buffer.from([0x04, 0xd2, 5, 1]), Buffer.alloc(20, 1)]) });
                response.answer = [...ds, signRrset("com", std.com.zsk, ds)];
            }
        };
        const result = await resolver().resolveCaa("example.com");
        expect(result.status).toBe("secure");
    });
});

describe("resolver options and errors", () => {
    it("rejects names that are not valid without touching the network", async () => {
        for (const bad of ["a..b", ".a", "a".repeat(64) + ".com", "ü.com", `${"a.".repeat(130)}com`]) {
            const err = await failure(resolver().resolveCaa(bad));
            expect(err.kind).toBe("indeterminate");
        }
        expect(std.world.queries).toHaveLength(0);
    });

    it("turns every unexpected failure into an indeterminate DnssecError", async () => {
        std.world.hook = () => {
            throw new Error("boom");
        };
        const err = await failure(resolver().resolveCaa("example.com"));
        expect(err.kind).toBe("indeterminate");
        expect(err.reason).toMatch(/boom/);
    });

    it("fails with a wrong trust anchor", async () => {
        const other: TestWorld = std.world;
        const anchors = other.anchors();
        anchors[0] = { ...anchors[0], digest: Buffer.alloc(32, 1) };
        const err = await failure(resolver({ trustAnchors: anchors }).resolveCaa("example.com"));
        expect(err.kind).toBe("bogus");
    });

    it("cannot use trust anchors that are all unsupported", async () => {
        const anchors = [{ keyTag: 1, algorithm: 5, digestType: 1, digest: "00" }];
        const err = await failure(resolver({ trustAnchors: anchors }).resolveCaa("example.com"));
        expect(err.kind).toBe("indeterminate");
    });

    it("accepts a trust anchor digest as hex text as well as bytes", async () => {
        const anchors = std.world
            .anchors()
            .map((a) => ({ ...a, digest: Buffer.from(a.digest).toString("hex").toUpperCase() }));
        expect((await resolver({ trustAnchors: anchors }).resolveCaa("example.com")).status).toBe("secure");
    });

    it("exhausting the query budget is indeterminate, not a partial answer", async () => {
        const err = await failure(resolver({ maxQueries: 3 }).resolveCaa("example.com"));
        expect(err.kind).toBe("indeterminate");
        expect(err.reason).toMatch(/budget/);
        expect(std.world.queries).toHaveLength(3);
        await expect(resolver({ maxQueries: 6 }).resolveCaa("example.com")).resolves.toMatchObject({
            status: "secure",
        });
    });

    it("does not follow DNAME", async () => {
        std.world.hook = (q, response) => {
            if (q.name === "example.com" && q.type === T.CAA) {
                response.answer.push({ name: "example.com", type: T.DNAME, ttl: 300, rdata: Buffer.from([0]) });
            }
        };
        const err = await failure(resolver().resolveCaa("example.com"));
        expect(err.kind).toBe("indeterminate");
        expect(err.reason).toMatch(/DNAME/);
    });

    it("uses the default trust anchors of the IANA root when none are given", async () => {
        // The synthetic root has other keys, so the built-in anchors must not validate it.
        const err = await failure(makeResolver(std.world, { trustAnchors: undefined }).resolveCaa("example.com"));
        expect(err.kind).toBe("bogus");
    });

    it("malformed CAA data in a validated RRset is refused", async () => {
        std.world.hook = (q, response) => {
            if (q.name === "example.com" && q.type === T.CAA) {
                const bad = [{ ...response.answer[0], rdata: Buffer.from([0, 9, 1]) }];
                response.answer = [...bad, signRrset("example.com", std.example.zsk, bad)];
            }
        };
        const err = await failure(resolver().resolveCaa("example.com"));
        expect(err.kind).toBe("indeterminate");
    });

    it("leaves nothing behind in the world between tests", () => {
        expect(std.world.queries).toHaveLength(0);
        expect(aRdata("1.2.3.4")).toHaveLength(4);
        expect(caaRdata(0, "a", "b")).toHaveLength(4);
    });
});

describe("caching", () => {
    it("reuses validated keys and verdicts, so a repeat lookup costs only the final query", async () => {
        const r = resolver({ cacheSeconds: 300 });
        await r.resolveCaa("example.com");
        std.world.queries.length = 0;
        await r.resolveCaa("example.com");
        expect(std.world.queries.map((q) => `${q.name}/${q.type}`)).toEqual(["example.com/257"]);
        std.world.queries.length = 0;
        await r.resolveCaa("host.example.com");
        expect(std.world.queries.map((q) => `${q.name}/${q.type}`)).toEqual([
            "host.example.com/43",
            "host.example.com/257",
        ]);
    });

    it("lets concurrent lookups share one resolver and its cache", async () => {
        const r = resolver({ cacheSeconds: 300 });
        const names = [
            "example.com",
            "p384.com",
            "unsigned.net",
            "foo.wild.example.com",
            "nope.secure.org",
            "c1.example.com",
        ];
        const results = await Promise.all(names.map((n) => r.resolveCaa(n)));
        expect(results.map((x) => x.status)).toEqual(["secure", "secure", "insecure", "secure", "secure", "secure"]);
        expect(results.map((x) => x.records.length)).toEqual([1, 1, 1, 1, 0, 1]);
    });

    it("does not cache when disabled", async () => {
        const r = resolver({ cacheSeconds: 0 });
        await r.resolveCaa("example.com");
        std.world.queries.length = 0;
        await r.resolveCaa("example.com");
        expect(std.world.queries).toHaveLength(6);
    });

    it("shares work inside one lookup even with the cache disabled", async () => {
        await resolver().resolve("xz.example.com", T.A);
        const roots = std.world.queries.filter((q) => q.name === "" && q.type === T.DNSKEY);
        expect(roots).toHaveLength(1);
    });

    it("lets a verdict die after the configured time", async () => {
        let now = T0.getTime();
        const r = resolver({ cacheSeconds: 60, now: () => new Date(now) });
        await r.resolveCaa("example.com");
        std.world.queries.length = 0;
        now += 30_000;
        await r.resolveCaa("example.com");
        expect(std.world.queries).toHaveLength(1);
        std.world.queries.length = 0;
        now += 61_000;
        await r.resolveCaa("example.com");
        expect(std.world.queries).toHaveLength(6);
    });

    it("never serves a verdict past its signatures' expiration or its TTL", async () => {
        const world = new TestWorld();
        const expiration = Math.floor(T0.getTime() / 1000) + 600;
        const root = world.add({ name: "", ttl: 100000, expiration });
        const tld = world.add({ name: "test", ttl: 100000, expiration });
        const leaf = world.add({ name: "leaf.test", ttl: 100000, expiration });
        world.delegate(root, tld);
        world.delegate(tld, leaf);
        leaf.add("@", T.CAA, caaRdata(0, "issue", "ca.test"));
        world.build();
        let now = T0.getTime();
        const r = makeResolver(world, { cacheSeconds: 1_000_000, now: () => new Date(now) });
        await r.resolveCaa("leaf.test");
        world.queries.length = 0;
        now += 500_000;
        await r.resolveCaa("leaf.test");
        expect(world.queries).toHaveLength(1);
        now += 101_000;
        const err = await failure(r.resolveCaa("leaf.test"));
        expect(err.kind).toBe("bogus");
        expect(err.reason).toMatch(/expired/);
        expect(world.queries.length).toBeGreaterThan(1);
    });

    it("caches per resolver instance, keyed on that instance's own trust anchors", async () => {
        const good = resolver({ cacheSeconds: 300 });
        await good.resolveCaa("example.com");
        const anchors = std.world.anchors();
        anchors[0] = { ...anchors[0], digest: Buffer.alloc(32, 2) };
        const bad = resolver({ cacheSeconds: 300, trustAnchors: anchors });
        const err = await failure(bad.resolveCaa("example.com"));
        expect(err.kind).toBe("bogus");
    });
});

describe("iteration limit", () => {
    it("refuses to validate NSEC3 records with more iterations than the limit, as indeterminate", async () => {
        const err = await failure(resolver().resolve("nope.iter.com", T.CAA));
        expect(err.kind).toBe("indeterminate");
        expect(err.reason).toMatch(/iterations/);
    });

    it("still validates positive data of such a zone", async () => {
        expect((await resolver().resolveCaa("iter.com")).status).toBe("secure");
    });
});
