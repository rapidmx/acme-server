///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { DnssecError } from "../../../src/lib/dnssec/types.js";
import { DnssecResult } from "../../../src/lib/dnssec/validator.js";
import {
    aRdata,
    buildStandardWorld,
    corrupt,
    encodeBitmap,
    encodeMessage,
    makeKey,
    makeResolver,
    recordsOf,
    RR,
    signRrset,
    sigsOf,
    StandardWorld,
    T,
    T0,
    TestResponse,
    TestZone,
    wireName,
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

const NOW = Math.floor(T0.getTime() / 1000);

/** Installs a hook that only touches the response to one question. */
function onQuery(name: string, type: number, edit: (response: TestResponse) => Uint8Array | void): void {
    std.world.hook = (q, response) => (q.name === name && q.type === type ? edit(response) : undefined);
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

/** Resolves the CAA record and expects a `bogus` failure. */
async function expectBogus(name = "example.com", type: number = T.CAA): Promise<DnssecError> {
    const err = await failure(makeResolver(std.world).resolve(name, type));
    expect(err.kind).toBe("bogus");
    return err;
}

async function expectIndeterminate(name = "example.com", type: number = T.CAA): Promise<DnssecError> {
    const err = await failure(makeResolver(std.world).resolve(name, type));
    expect(err.kind).toBe("indeterminate");
    return err;
}

/** Replaces the RRSIGs of one RRset in a response with a fresh one. */
function resign(
    response: TestResponse,
    zone: TestZone,
    name: string,
    type: number,
    options = {},
    signer = zone.zsk
): void {
    const records: RR[] = recordsOf(response.answer, name, type);
    response.answer = [
        ...response.answer.filter((r) => !(r.type === T.RRSIG && r.name === name && r.rdata.readUInt16BE(0) === type)),
        signRrset(zone.name, signer, records, options),
    ];
}

describe("forged or damaged signatures are bogus", () => {
    it("a flipped signature bit in the answer", async () => {
        onQuery("example.com", T.CAA, (r) => corrupt(sigsOf(r.answer, "example.com", T.CAA)[0]));
        expect((await expectBogus()).reason).toMatch(/does not verify/);
    });

    it("a flipped signature bit anywhere on the chain: root DNSKEY, DS, zone DNSKEY", async () => {
        for (const [name, type] of [
            ["", T.DNSKEY],
            ["com", T.DS],
            ["com", T.DNSKEY],
            ["example.com", T.DS],
            ["example.com", T.DNSKEY],
        ] as Array<[string, number]>) {
            onQuery(name, type, (r) => corrupt(sigsOf(r.answer, name, type)[0]));
            await expectBogus();
        }
    });

    it("an expired signature", async () => {
        onQuery("example.com", T.CAA, (r) => resign(r, std.example, "example.com", T.CAA, { expiration: NOW - 10 }));
        expect((await expectBogus()).reason).toMatch(/expired/);
    });

    it("a signature that is not valid yet", async () => {
        onQuery("example.com", T.CAA, (r) => resign(r, std.example, "example.com", T.CAA, { inception: NOW + 3600 }));
        expect((await expectBogus()).reason).toMatch(/not yet valid/);
    });

    it("a signature valid until exactly now is still good, one second later it is not", async () => {
        onQuery("example.com", T.CAA, (r) => resign(r, std.example, "example.com", T.CAA, { expiration: NOW }));
        expect((await makeResolver(std.world).resolveCaa("example.com")).status).toBe("secure");
        onQuery("example.com", T.CAA, (r) => resign(r, std.example, "example.com", T.CAA, { expiration: NOW - 1 }));
        await expectBogus();
    });

    it("a signature that is valid from exactly now", async () => {
        onQuery("example.com", T.CAA, (r) => resign(r, std.example, "example.com", T.CAA, { inception: NOW }));
        expect((await makeResolver(std.world).resolveCaa("example.com")).status).toBe("secure");
        onQuery("example.com", T.CAA, (r) => resign(r, std.example, "example.com", T.CAA, { inception: NOW + 1 }));
        await expectBogus();
    });

    it("the clock deciding: everything is expired a month later and not yet valid a day before", async () => {
        const later = makeResolver(std.world, { now: () => new Date(T0.getTime() + 31 * 86400_000) });
        expect((await failure(later.resolveCaa("example.com"))).kind).toBe("bogus");
        const earlier = makeResolver(std.world, { now: () => new Date(T0.getTime() - 86400_000) });
        expect((await failure(earlier.resolveCaa("example.com"))).kind).toBe("bogus");
    });

    it("an expired signature on the root DNSKEY RRset", async () => {
        onQuery("", T.DNSKEY, (r) => resign(r, std.root, "", T.DNSKEY, { expiration: NOW - 5 }, std.root.ksk));
        await expectBogus();
    });

    it("a signature by a key that is not in the DNSKEY set", async () => {
        onQuery("example.com", T.CAA, (r) => resign(r, std.example, "example.com", T.CAA, {}, makeKey("p256", 256)));
        expect((await expectBogus()).reason).toMatch(/no validated zone key/);
    });

    it("a signature by a key of the parent zone", async () => {
        onQuery("example.com", T.CAA, (r) =>
            resign(r, std.example, "example.com", T.CAA, { signer: "com" }, std.com.zsk)
        );
        expect((await expectBogus()).reason).toMatch(/signer/);
    });

    it("a signature naming the wrong signer, even by the right key", async () => {
        onQuery("example.com", T.CAA, (r) => resign(r, std.example, "example.com", T.CAA, { signer: "com" }));
        expect((await expectBogus()).reason).toMatch(/signer com is not the zone example.com/);
    });

    it("a signature made over a different type", async () => {
        onQuery("example.com", T.CAA, (r) => resign(r, std.example, "example.com", T.CAA, { typeCovered: T.TXT }));
        expect((await expectBogus()).reason).toMatch(/no RRSIG covers/);
        const host: RR[] = recordsOf(std.example.rrsetWithSigs("host.example.com", T.A), "host.example.com", T.A);
        onQuery("example.com", T.CAA, (r) => {
            const caa = recordsOf(r.answer, "example.com", T.CAA);
            const forged = signRrset(
                "example.com",
                std.example.zsk,
                host.map((h) => ({ ...h, name: "example.com" })),
                { typeCovered: T.CAA }
            );
            r.answer = [...caa, forged];
        });
        await expectBogus();
    });

    it("a signature over a different owner name, presented at this one", async () => {
        const apex: RR = sigsOf(std.example.rrsetWithSigs("example.com", T.CAA), "example.com", T.CAA)[0];
        onQuery("c3.example.com", T.CAA, (r) => {
            r.answer = [...recordsOf(r.answer, "c3.example.com", T.CAA), { ...apex, name: "c3.example.com" }];
        });
        await expectBogus("c3.example.com");
    });

    it("a signature by an algorithm the resolver does not support, alone", async () => {
        onQuery("example.com", T.CAA, (r) => {
            sigsOf(r.answer, "example.com", T.CAA)[0].rdata[2] = 5;
        });
        expect((await expectBogus()).reason).toMatch(/not supported/);
    });

    it("a signature by a different algorithm than the key claims, with the right tag", async () => {
        onQuery("example.com", T.CAA, (r) => {
            sigsOf(r.answer, "example.com", T.CAA)[0].rdata[2] = 14;
        });
        await expectBogus();
    });

    it("altered answer data under an untouched signature", async () => {
        onQuery("example.com", T.CAA, (r) => {
            const record = recordsOf(r.answer, "example.com", T.CAA)[0];
            record.rdata[record.rdata.length - 1] ^= 0x01;
        });
        await expectBogus();
    });

    it("a record injected into a signed RRset", async () => {
        onQuery("example.com", T.CAA, (r) => {
            r.answer.push({
                name: "example.com",
                type: T.CAA,
                ttl: 300,
                rdata: Buffer.from([0, 5, ...Buffer.from("issue"), ...Buffer.from("evil.example")]),
            });
        });
        await expectBogus();
    });

    it("a record removed from a signed RRset", async () => {
        onQuery("example.com", T.DNSKEY, (r) => {
            r.answer = r.answer.filter((x) => x.type !== T.DNSKEY || x.rdata.readUInt16BE(0) !== 256);
        });
        await expectBogus();
    });

    it("a valid answer for a different type in place of the one asked for", async () => {
        onQuery("txt.example.com", T.TXT, (r) => {
            r.answer = std.example
                .rrsetWithSigs("host.example.com", T.A)
                .map((x) => ({ ...x, name: "txt.example.com" }));
        });
        await expectBogus("txt.example.com", T.TXT);
        onQuery("txt.example.com", T.TXT, (r) => {
            r.answer = [];
            r.authority = std.example.rrsetWithSigs("example.com", T.SOA);
        });
        await expectBogus("txt.example.com", T.TXT);
    });
});

describe("downgrades are bogus", () => {
    it("stripping the signatures from the answer of a secure zone", async () => {
        onQuery("example.com", T.CAA, (r) => {
            r.answer = r.answer.filter((x) => x.type !== T.RRSIG);
        });
        expect((await expectBogus()).reason).toMatch(/no RRSIG/);
    });

    it("stripping the signatures from the DS, the DNSKEY RRset or the root", async () => {
        for (const [name, type] of [
            ["com", T.DS],
            ["example.com", T.DS],
            ["example.com", T.DNSKEY],
            ["", T.DNSKEY],
        ] as Array<[string, number]>) {
            onQuery(name, type, (r) => {
                r.answer = r.answer.filter((x) => x.type !== T.RRSIG);
            });
            await expectBogus();
        }
    });

    it("answering the DS query with an empty NODATA and no proof", async () => {
        onQuery("example.com", T.DS, (r) => {
            r.answer = [];
            r.authority = [];
        });
        await expectBogus();
    });

    it("answering the DS query with NXDOMAIN and only a SOA", async () => {
        onQuery("example.com", T.DS, (r) => {
            r.answer = [];
            r.rcode = 3;
            r.authority = std.com.rrsetWithSigs("com", T.SOA);
        });
        await expectBogus();
    });

    it("presenting the genuine opt-out proof of another name as proof that example.com has no DS", async () => {
        onQuery("example.com", T.DS, (r) => {
            r.answer = [];
            r.authority = [
                ...std.com.rrsetWithSigs("com", T.SOA),
                ...std.com.proofAt("com"),
                ...std.com.proofCovering("unsigned.com"),
            ];
        });
        await expectBogus();
    });

    it("keeping the closest-encloser record but replacing the real record with its predecessor (opt-out claim without a cover)", async () => {
        onQuery("example.com", T.DS, (r) => {
            r.answer = [];
            r.authority = [
                ...std.com.rrsetWithSigs("com", T.SOA),
                ...std.com.proofAt("com"),
                ...std.com.proofPreceding("example.com"),
            ];
        });
        await expectBogus();
    });

    it("dropping the DNSKEY of a zone that has a DS", async () => {
        onQuery("example.com", T.DNSKEY, (r) => {
            r.answer = [];
        });
        expect((await expectBogus()).reason).toMatch(/no DNSKEY/);
    });

    it("an unsigned NXDOMAIN with only a SOA where a signed proof is required", async () => {
        onQuery("nope.example.com", T.CAA, (r) => {
            r.authority = r.authority.filter(
                (x) => x.type === T.SOA || (x.type === T.RRSIG && x.rdata.readUInt16BE(0) === T.SOA)
            );
        });
        await expectBogus("nope.example.com");
    });

    it("stripping the signatures from the NSEC records of a proof", async () => {
        onQuery("nope.example.com", T.CAA, (r) => {
            r.authority = r.authority.filter((x) => x.type !== T.RRSIG);
        });
        await expectBogus("nope.example.com");
    });
});

describe("the DNSKEY RRset must match the DS", () => {
    it("a different, self-consistent key set", async () => {
        onQuery("example.com", T.DNSKEY, (r) => {
            const ksk = makeKey("p256", 257);
            const zsk = makeKey("p256", 256);
            const keys: RR[] = [ksk, zsk].map((k) => ({
                name: "example.com",
                type: T.DNSKEY,
                ttl: 300,
                rdata: k.rdata,
            }));
            r.answer = [...keys, signRrset("example.com", ksk, keys)];
        });
        expect((await expectBogus()).reason).toMatch(/matches its DS/);
    });

    it("the right KSK in the set, but the RRset signed by another key", async () => {
        onQuery("example.com", T.DNSKEY, (r) => resign(r, std.example, "example.com", T.DNSKEY, {}, std.example.zsk));
        expect((await expectBogus()).reason).toMatch(/not signed by the key its DS vouches for/);
    });

    it("a DS whose digest is wrong (re-signed by the parent as a broken zone would)", async () => {
        onQuery("sha384.com", T.DS, (r) => {
            const ds = recordsOf(r.answer, "sha384.com", T.DS);
            ds[0].rdata[ds[0].rdata.length - 1] ^= 0xff;
            r.answer = [...ds, signRrset("com", std.com.zsk, ds)];
        });
        await expectBogus("sha384.com");
    });

    it("a DS naming the right key with the wrong key tag", async () => {
        onQuery("example.com", T.DS, (r) => {
            const ds = recordsOf(r.answer, "example.com", T.DS);
            ds[0].rdata[1] ^= 0x01;
            r.answer = [...ds, signRrset("com", std.com.zsk, ds)];
        });
        await expectBogus();
    });

    it("keys without the zone flag, with a revoked flag or with another protocol are not used", async () => {
        for (const patch of [
            (rdata: Buffer): void => {
                rdata.writeUInt16BE(rdata.readUInt16BE(0) & ~0x0100, 0);
            },
            (rdata: Buffer): void => {
                rdata.writeUInt16BE(rdata.readUInt16BE(0) | 0x0080, 0);
            },
            (rdata: Buffer): void => {
                rdata[2] = 4;
            },
        ]) {
            onQuery("example.com", T.DNSKEY, (r) => {
                const keys = recordsOf(r.answer, "example.com", T.DNSKEY);
                for (const k of keys) {
                    if (k.rdata.readUInt16BE(0) === 257) {
                        patch(k.rdata);
                    }
                }
                // Signed by the (now unusable, and anyway mismatching) KSK: nothing validates.
                r.answer = [...keys, sigsOf(r.answer, "example.com", T.DNSKEY)[0]];
            });
            await expectBogus();
        }
    });
});

describe("forged proofs of no DS", () => {
    function forgedNsec(zone: TestZone, owner: string, next: string, types: number[], sign = true): RR[] {
        const rr: RR = {
            name: owner,
            type: T.NSEC,
            ttl: 300,
            rdata: Buffer.concat([wireName(next), encodeBitmap(types)]),
        };
        return sign ? [rr, signRrset(zone.name, zone.zsk, [rr])] : [rr];
    }

    it("an NSEC that says a DS exists is not a proof that there is none", async () => {
        onQuery("secure.net", T.DS, (r) => {
            r.answer = [];
            r.authority = [...std.net.rrsetWithSigs("net", T.SOA), ...std.net.proofAt("secure.net")];
        });
        expect((await expectBogus("secure.net")).reason).toMatch(/DS exists/);
    });

    it("an NSEC of a different name does not prove anything about this one", async () => {
        onQuery("secure.net", T.DS, (r) => {
            r.answer = [];
            r.authority = [...std.net.rrsetWithSigs("net", T.SOA), ...std.net.proofAt("unsigned.net")];
        });
        await expectBogus("secure.net");
    });

    it("an NSEC claiming the name is no zone cut is caught when the zone's real answer is not signed by the parent", async () => {
        onQuery("secure.net", T.DS, (r) => {
            r.answer = [];
            r.authority = [
                ...std.net.rrsetWithSigs("net", T.SOA),
                ...forgedNsec(std.net, "secure.net", "unsigned.net", [T.A, T.RRSIG, T.NSEC]),
            ];
        });
        expect((await expectBogus("secure.net")).reason).toMatch(/signer secure.net is not the zone net/);
    });

    it("an NSEC with the SOA bit is the child apex's record, not proof of no DS", async () => {
        onQuery("secure.net", T.DS, (r) => {
            r.answer = [];
            r.authority = [
                ...std.net.rrsetWithSigs("net", T.SOA),
                ...forgedNsec(std.net, "secure.net", "unsigned.net", [T.NS, T.SOA, T.RRSIG, T.NSEC]),
            ];
        });
        expect((await expectBogus("secure.net")).reason).toMatch(/child zone/);
    });

    it("an unsigned NSEC is worthless", async () => {
        onQuery("secure.net", T.DS, (r) => {
            r.answer = [];
            r.authority = [
                ...std.net.rrsetWithSigs("net", T.SOA),
                ...forgedNsec(std.net, "secure.net", "unsigned.net", [T.NS, T.RRSIG, T.NSEC], false),
            ];
        });
        await expectBogus("secure.net");
    });

    it("an NSEC signed by a key that is not the zone's is worthless", async () => {
        onQuery("secure.net", T.DS, (r) => {
            const rr: RR = {
                name: "secure.net",
                type: T.NSEC,
                ttl: 300,
                rdata: Buffer.concat([wireName("unsigned.net"), encodeBitmap([T.NS, T.RRSIG, T.NSEC])]),
            };
            r.answer = [];
            r.authority = [rr, signRrset("net", makeKey("p256", 256), [rr])];
        });
        await expectBogus("secure.net");
    });

    it("an NSEC3 for the wrong hash", async () => {
        onQuery("secure.org", T.DS, (r) => {
            r.answer = [];
            r.authority = [...std.org.rrsetWithSigs("org", T.SOA), ...std.org.proofAt("unsigned.org")];
        });
        await expectBogus("secure.org");
    });

    it("an NSEC3 matching but claiming no NS where the parent zone has a delegation (forged bitmap, unsigned)", async () => {
        onQuery("unsigned.org", T.DS, (r) => {
            const match = std.org.proofAt("unsigned.org");
            match[0].rdata[match[0].rdata.length - 1] ^= 0x10;
            r.authority = [...std.org.rrsetWithSigs("org", T.SOA), ...match];
        });
        await expectBogus("unsigned.org");
    });

    it("replacing an insecure proof with one from another zone", async () => {
        onQuery("unsigned.net", T.DS, (r) => {
            r.authority = [...std.net.rrsetWithSigs("net", T.SOA), ...std.root.proofAt("net")];
        });
        await expectBogus("unsigned.net");
    });
});

describe("wildcards need their proof", () => {
    it("a wildcard answer with no proof that the name does not exist", async () => {
        onQuery("foo.wild.example.com", T.CAA, (r) => {
            r.authority = [];
        });
        expect((await expectBogus("foo.wild.example.com")).reason).toMatch(/wildcard/);
    });

    it("a wildcard answer with the proof of a different name (NSEC and NSEC3)", async () => {
        onQuery("foo.wild.example.com", T.CAA, (r) => {
            r.authority = std.example.proofCovering("aaa.example.com");
        });
        await expectBogus("foo.wild.example.com");
        onQuery("foo.wild.p384.com", T.CAA, (r) => {
            r.authority = std.p384.proofCovering("aaa.p384.com");
        });
        await expectBogus("foo.wild.p384.com");
    });

    it("a wildcard answer with the proof stripped of its signatures", async () => {
        onQuery("foo.wild.example.com", T.CAA, (r) => {
            r.authority = r.authority.filter((x) => x.type !== T.RRSIG);
        });
        await expectBogus("foo.wild.example.com");
    });

    it("an expansion of a wildcard that is not at the closest encloser", async () => {
        onQuery("foo.mid.wc.com", T.TXT, (r) => {
            r.rcode = 0;
            r.answer = std.wc.rrsetWithSigs("*.wc.com", T.TXT).map((x) => ({ ...x, name: "foo.mid.wc.com" }));
            r.authority = std.wc.proofCovering("foo.mid.wc.com");
        });
        expect((await expectBogus("foo.mid.wc.com", T.TXT)).reason).toMatch(/closest encloser/);
    });

    it("the same wildcard answer is fine for a name that really has no closer match", async () => {
        onQuery("foo.wc.com", T.TXT, (r) => {
            expect(r.answer.some((x) => x.type === T.TXT && x.name === "foo.wc.com")).toBe(true);
        });
        expect((await makeResolver(std.world).resolve("foo.wc.com", T.TXT)).status).toBe("secure");
    });

    it("a wildcard signature presented for a name whose real record exists (labels field lies about the owner)", async () => {
        onQuery("a.wild.example.com", T.CAA, (r) => {
            r.answer = std.example
                .rrsetWithSigs("*.wild.example.com", T.CAA)
                .map((x) => ({ ...x, name: "a.wild.example.com" }));
            r.authority = std.example.proofCovering("a.wild.example.com");
        });
        // The genuine NSEC chain has a.wild.example.com, so nothing covers it: no valid proof exists.
        await expectBogus("a.wild.example.com");
    });

    it("an RRSIG whose labels field exceeds the owner's labels", async () => {
        onQuery("example.com", T.CAA, (r) => resign(r, std.example, "example.com", T.CAA, { labels: 5 }));
        await expectBogus();
    });
});

describe("answers that contradict their own proof", () => {
    it("NODATA when the NSEC bitmap lists the type", async () => {
        onQuery("example.com", T.CAA, (r) => {
            r.answer = [];
            r.authority = [...std.example.rrsetWithSigs("example.com", T.SOA), ...std.example.proofAt("example.com")];
        });
        expect((await expectBogus()).reason).toMatch(/withheld/);
    });

    it("NODATA at a name that has a CNAME", async () => {
        onQuery("www.example.com", T.A, (r) => {
            r.answer = [];
            r.authority = [
                ...std.example.rrsetWithSigs("example.com", T.SOA),
                ...std.example.proofAt("www.example.com"),
            ];
        });
        expect((await expectBogus("www.example.com", T.A)).reason).toMatch(/CNAME/);
    });

    it("NXDOMAIN for a name that exists (NSEC and NSEC3)", async () => {
        onQuery("host.example.com", T.A, (r) => {
            r.answer = [];
            r.rcode = 3;
            r.authority = [
                ...std.example.rrsetWithSigs("example.com", T.SOA),
                ...std.example.proofCovering("host.example.com"),
            ];
        });
        await expectBogus("host.example.com", T.A);
        onQuery("host.p384.com", T.A, (r) => {
            r.answer = [];
            r.rcode = 3;
            r.authority = [...std.p384.rrsetWithSigs("p384.com", T.SOA), ...std.p384.proofPreceding("host.p384.com")];
        });
        await expectBogus("host.p384.com", T.A);
    });

    it("NXDOMAIN for an empty non-terminal: the proof itself shows the name exists, so the lie changes nothing", async () => {
        onQuery("ent.example.com", T.A, (r) => {
            r.answer = [];
            r.rcode = 3;
            r.authority = [
                ...std.example.rrsetWithSigs("example.com", T.SOA),
                ...std.example.proofCovering("ent.example.com"),
            ];
        });
        // The covering record's next name is below ent.example.com, which shows it exists.
        expect(await makeResolver(std.world).resolve("ent.example.com", T.A)).toEqual({
            status: "secure",
            rdata: [],
            nxdomain: false,
        });
    });

    it("NXDOMAIN without the proof that no wildcard applies", async () => {
        onQuery("nope.example.com", T.CAA, (r) => {
            r.authority = [
                ...std.example.rrsetWithSigs("example.com", T.SOA),
                ...std.example.proofCovering("nope.example.com"),
            ];
        });
        expect((await expectBogus("nope.example.com")).reason).toMatch(/wildcard/);
        onQuery("nope.p384.com", T.CAA, (r) => {
            r.authority = [
                ...std.p384.rrsetWithSigs("p384.com", T.SOA),
                ...std.p384.proofAt("p384.com"),
                ...std.p384.proofCovering("nope.p384.com"),
            ];
        });
        expect((await expectBogus("nope.p384.com")).reason).toMatch(/wildcard/);
    });

    it("NXDOMAIN for a name where a wildcard applies", async () => {
        onQuery("foo.wild.example.com", T.CAA, (r) => {
            r.answer = [];
            r.rcode = 3;
            r.authority = [
                ...std.example.rrsetWithSigs("example.com", T.SOA),
                ...std.example.proofCovering("foo.wild.example.com"),
            ];
        });
        await expectBogus("foo.wild.example.com");
    });

    it("proof records taken from another zone", async () => {
        onQuery("nope.example.com", T.CAA, (r) => {
            r.authority = [
                ...r.authority.filter((x) => x.type === T.SOA || (x.type === T.RRSIG && x.name === "example.com")),
                ...std.rsa.proofCovering("nope.rsa.com"),
            ];
        });
        await expectBogus("nope.example.com");
    });
});

describe("the resolvers' answers are only transport", () => {
    it("ignores records for other names and additional records", async () => {
        onQuery("example.com", T.CAA, (r) => {
            r.answer.push({
                name: "other.example.com",
                type: T.CAA,
                ttl: 1,
                rdata: Buffer.from([0, 5, ...Buffer.from("issueevil.example")]),
            });
            r.additional = [
                {
                    name: "example.com",
                    type: T.CAA,
                    ttl: 1,
                    rdata: Buffer.from([0, 5, ...Buffer.from("issueevil.example")]),
                },
            ];
            r.authority.push({ name: "example.com", type: T.A, ttl: 1, rdata: aRdata("6.6.6.6") });
        });
        const result = await makeResolver(std.world).resolveCaa("example.com");
        expect(result).toEqual({ status: "secure", records: [{ critical: 0, tag: "issue", value: "ca.example.com" }] });
    });

    it("tolerates a few junk RRSIGs in front of the good one", async () => {
        onQuery("example.com", T.CAA, (r) => {
            const good: RR = sigsOf(r.answer, "example.com", T.CAA)[0];
            const junk: RR[] = [1, 2, 3].map((i) => {
                const copy: RR = { ...good, rdata: Buffer.from(good.rdata) };
                copy.rdata[copy.rdata.length - i] ^= 0x55;
                return copy;
            });
            r.answer = [...r.answer.filter((x) => x !== good), ...junk, good];
        });
        expect((await makeResolver(std.world).resolveCaa("example.com")).status).toBe("secure");
    });

    it("refuses to burn CPU on a flood of colliding signatures (key trap)", async () => {
        onQuery("example.com", T.CAA, (r) => {
            const good: RR = sigsOf(r.answer, "example.com", T.CAA)[0];
            const junk: RR[] = Array.from({ length: 40 }, (_v, i) => {
                const copy: RR = { ...good, rdata: Buffer.from(good.rdata) };
                copy.rdata[copy.rdata.length - 1 - (i % 30)] ^= (i % 7) + 1;
                copy.rdata[copy.rdata.length - 40] ^= i + 1;
                return copy;
            });
            r.answer = [...r.answer.filter((x) => x !== good), ...junk, good];
        });
        expect((await expectBogus()).reason).toMatch(/too many/);
    });

    it("refuses a DNSKEY RRset stuffed with keys", async () => {
        onQuery("example.com", T.DNSKEY, (r) => {
            const keys = recordsOf(r.answer, "example.com", T.DNSKEY);
            for (let i = 0; i < 40; i++) {
                keys.push({
                    ...keys[0],
                    rdata: Buffer.concat([keys[0].rdata.subarray(0, 4), Buffer.alloc(64, i + 1)]),
                });
            }
            r.answer = [...keys, ...sigsOf(r.answer, "example.com", T.DNSKEY)];
        });
        expect((await expectBogus()).reason).toMatch(/too many DNSKEY/);
    });
});

describe("network failures and hostile messages are indeterminate", () => {
    it("SERVFAIL, REFUSED, FORMERR and NOTIMP", async () => {
        for (const rcode of [1, 2, 4, 5]) {
            onQuery("example.com", T.CAA, (r) => {
                r.rcode = rcode;
                r.answer = [];
                r.authority = [];
            });
            expect((await expectIndeterminate()).reason).toMatch(/RCODE/);
        }
    });

    it("SERVFAIL at any point of the chain", async () => {
        for (const [name, type] of [
            ["", T.DNSKEY],
            ["com", T.DS],
            ["com", T.DNSKEY],
            ["example.com", T.DS],
            ["example.com", T.DNSKEY],
        ] as Array<[string, number]>) {
            onQuery(name, type, (r) => {
                r.rcode = 2;
            });
            await expectIndeterminate();
        }
    });

    it("a timeout or a network error from the transport", async () => {
        std.world.hook = () => {
            throw new Error("query timed out");
        };
        expect((await expectIndeterminate()).reason).toMatch(/timed out/);
        std.world.hook = async () => Promise.reject(new Error("ECONNREFUSED"));
        await expectIndeterminate();
    });

    it("a truncated answer that the transport could not complete", async () => {
        onQuery("example.com", T.CAA, (r) => {
            r.tc = true;
        });
        expect((await expectIndeterminate()).reason).toMatch(/truncated/);
    });

    it("garbage, short and truncated messages", async () => {
        const valid = (r: TestResponse): Buffer => encodeMessage("example.com", T.CAA, r);
        const cases: Array<(r: TestResponse) => Uint8Array> = [
            () => Buffer.alloc(0),
            () => Buffer.from("deadbeef", "hex"),
            () => Buffer.alloc(11),
            () => Buffer.alloc(200, 0xff),
            () => Buffer.from(Array.from({ length: 150 }, (_v, i) => (i * 37 + 11) & 0xff)),
            (r) => valid(r).subarray(0, valid(r).length - 5),
            (r) => valid(r).subarray(0, 40),
            (r) => valid(r).subarray(0, 12),
            (r) => Buffer.concat([valid(r).subarray(0, 6), Buffer.from([0xff, 0xff]), valid(r).subarray(8)]),
        ];
        for (const make of cases) {
            onQuery("example.com", T.CAA, (r) => make(r));
            await expectIndeterminate();
        }
    });

    it("a compression pointer loop or a forward pointer", async () => {
        const question = Buffer.from("00010001", "hex");
        for (const name of ["c00c", "c010", "c0ff", "03616263c00c", "40"]) {
            const message = Buffer.concat([
                Buffer.from("123481800001000000000000", "hex"),
                Buffer.from(name, "hex"),
                question,
            ]);
            onQuery("example.com", T.CAA, () => message);
            expect((await expectIndeterminate()).reason).toMatch(/malformed/);
        }
    });

    it("a pointer loop inside a record's name and inside RDATA", async () => {
        const good = encodeMessage("example.com", T.CAA, {
            rcode: 0,
            answer: [{ name: "example.com", type: T.CNAME, ttl: 1, rdata: wireName("a.example.com") }],
            authority: [],
        });
        // The answer's owner name is a pointer (0xc00c) right after the 4-byte question; point it at itself instead.
        const at = 12 + 13 + 4;
        expect(good.readUInt16BE(at)).toBe(0xc00c);
        const looped = Buffer.from(good);
        looped.writeUInt16BE(0xc000 | at, at);
        onQuery("example.com", T.CAA, () => looped);
        await expectIndeterminate();
    });

    it("a header that promises more records than the message holds", async () => {
        onQuery("example.com", T.CAA, (r) => {
            const message = Buffer.from(encodeMessage("example.com", T.CAA, r));
            message.writeUInt16BE(500, 6);
            return message;
        });
        await expectIndeterminate();
    });

    it("an RDLENGTH that runs past the end", async () => {
        onQuery("example.com", T.CAA, (r) => {
            const message = Buffer.from(encodeMessage("example.com", T.CAA, r));
            message.writeUInt16BE(message.readUInt16BE(message.length - 13 - 0) + 0, message.length - 13);
            return message.subarray(0, message.length - 20);
        });
        await expectIndeterminate();
    });

    it("an answer to another question, or something that is not a response", async () => {
        onQuery("example.com", T.CAA, (r) => encodeMessage("other.example.com", T.CAA, r));
        expect((await expectIndeterminate()).reason).toMatch(/does not answer/);
        onQuery("example.com", T.CAA, (r) => encodeMessage("example.com", T.TXT, r));
        await expectIndeterminate();
        onQuery("example.com", T.CAA, (r) => {
            const message = Buffer.from(encodeMessage("example.com", T.CAA, r));
            message[2] &= 0x7f;
            return message;
        });
        expect((await expectIndeterminate()).reason).toMatch(/not a query response/);
        onQuery("example.com", T.CAA, (r) => {
            const message = Buffer.from(encodeMessage("example.com", T.CAA, r));
            message[2] |= 0x08;
            return message;
        });
        await expectIndeterminate();
    });

    it("a response with no question at all", async () => {
        onQuery("example.com", T.CAA, () => Buffer.from("123481800000000000000000", "hex"));
        await expectIndeterminate();
    });

    it("an unresponsive resolver during the walk is indeterminate, never insecure", async () => {
        std.world.hook = (q) => {
            if (q.type === T.DS) {
                throw new Error("timeout");
            }
        };
        expect((await expectIndeterminate("unsigned.net")).kind).toBe("indeterminate");
    });
});

describe("random damage to any single response is never accepted as a different answer", () => {
    function prng(seed: number): () => number {
        let a = seed >>> 0;
        return () => {
            a = (a + 0x6d2b79f5) >>> 0;
            let t = a;
            t = Math.imul(t ^ (t >>> 15), t | 1);
            t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
            return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
        };
    }

    const targets: Array<[string, number]> = [
        ["example.com", T.CAA],
        ["foo.wild.example.com", T.CAA],
        ["nope.example.com", T.CAA],
        ["c1.example.com", T.CAA],
        ["nope.p384.com", T.CAA],
        ["unsigned.net", T.CAA],
        ["secure.org", T.CAA],
        ["unsigned.com", T.CAA],
    ];

    it.each(targets)("%s type %i", async (name, type) => {
        const baseline = await makeResolver(std.world).resolve(name, type);
        const queries = std.world.queries.length;
        const random = prng(name.length * 7919 + type);
        let rejected = 0;
        for (let round = 0; round < 150; round++) {
            const which = Math.floor(random() * queries);
            let seen = -1;
            std.world.hook = (q, response) => {
                seen++;
                if (seen !== which) {
                    return undefined;
                }
                const message = Buffer.from(encodeMessage(q.name, q.type, response));
                const flips = 1 + Math.floor(random() * 3);
                for (let i = 0; i < flips; i++) {
                    message[Math.floor(random() * message.length)] ^= 1 << Math.floor(random() * 8);
                }
                return message;
            };
            let result: DnssecResult | undefined;
            try {
                result = await makeResolver(std.world).resolve(name, type);
            } catch (err) {
                expect(err).toBeInstanceOf(DnssecError);
                rejected++;
            }
            if (result) {
                // Damage must never turn the verdict into a different one. Unsigned data (insecure) has nothing to protect it,
                // so only its status is pinned down there.
                expect(result.status).toBe(baseline.status);
                if (baseline.status === "secure") {
                    expect(result.nxdomain).toBe(baseline.nxdomain);
                    expect(result.rdata.map((r) => Buffer.from(r).toString("hex"))).toEqual(
                        baseline.rdata.map((r) => Buffer.from(r).toString("hex"))
                    );
                }
            }
        }
        expect(rejected).toBeGreaterThan(20);
    });
});
