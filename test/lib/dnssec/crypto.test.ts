///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { generateKeyPairSync } from "node:crypto";
import {
    dsDigest,
    dsMatches,
    importPublicKey,
    isSupportedAlgorithm,
    isSupportedDigest,
    keyTag,
    parseDnskey,
    parseDs,
    verifySignature,
} from "../../../src/lib/dnssec/keys.js";
import {
    base32hexDecode,
    base32hexEncode,
    NsecDenial,
    Nsec3Denial,
    Nsec3Record,
    nsec3Hash,
    parseNsec,
    parseNsec3,
    parseTypeBitmap,
} from "../../../src/lib/dnssec/nsec.js";
import { canonicalRdata, parseRrsig, signedData, TrustedKey, validateRrset } from "../../../src/lib/dnssec/rrset.js";
import { DnssecError } from "../../../src/lib/dnssec/types.js";
import { IANA_ROOT_TRUST_ANCHORS } from "../../../src/lib/dnssec/validator.js";
import { DnsRecord } from "../../../src/lib/dnssec/wire.js";
import { aRdata, caaRdata, encodeBitmap, KeyKind, makeDs, makeKey, RR, signRrset, T, u16, wireName } from "./zones.js";

function hex(text: string): Buffer {
    return Buffer.from(text.replace(/\s+/g, ""), "hex");
}

/** The IANA root KSKs as published in the root DNSKEY RRset (flags 257, protocol 3, algorithm 8). */
const ROOT_KSK_2017 = Buffer.from(
    "AQEDCAMBAAGs/7QJvMk5+DH3oeXsiPelklXsUwQL5DICc5Ckzoltb5CG88Xhd/v+EYFjqux68UYsR5RZRMTiwCa+Xpi7ze0ll4Jy4ePgecUJTVc/DoPJLwKzLTUTsVULgmkpyA3Q+Syslm0Xdp/VhntkfD84Apq9xIFS648gcVnsxdIyx8FTfHn0t6wo/xFoLyFoG/bWq6VVAyv2+fA2vrKqpbN3jW7r+6a/nqGRvkqwyup1ni93Oh+QKcc+y41XNbkyHbCF8bji2AOP4pQZklSM7g1n3UVH4R3WOvnJ/BxUZvtoTPAJ1xl8LPeeeSq1AeaoocpRmvLLm19jZ+lMDUdQJFE1e+G1",
    "base64"
);
const ROOT_KSK_2024 = Buffer.from(
    "AQEDCAMBAAGveo3rpJ2ZWnkq78gCY+mR79vIYTipMd6yxl1Wguq107A3OOPf3InZbaZMhsAiTZzgJRTShdowaLGQVOXnh7KWkFjpjhJWbIyAjEDAt2nh2xokob2bMeMDGEox/Hu1a4W7uoq8As1QQKREo21HaVlphJ4WrYVrtY6PrIhVIkQAMZvasiTYP8Dmaqsy/3S/6vD5HEVOaFChKVIHu9TN3o9v+wj6qXVcLjKE76AfmTk+GHhssTLx5m68ZRcxjhzoo7czfrtU0DWrV9lwbs2TUNSvrNgl5DyGaO7OiYGcr2gXr2LcT72C8OM/Zkeytr2hdfFGB/WfRjVFHmsn3ygu9z2H",
    "base64"
);

describe("key tags and DS digests", () => {
    it("computes the RFC 4034 section 5.4 example: key tag 60485 and its SHA-1 DS digest", () => {
        const key = Buffer.concat([
            Buffer.from([1, 0, 3, 5]),
            Buffer.from(
                "AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/2pHm822aJ5iI9BMzNXxeYCmZDRD99WYwYqUSdjMmmAphXdvxegXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9XzcnOf+EPbtG9DMBmADjFDc2w/rljwvFw==",
                "base64"
            ),
        ]);
        expect(keyTag(key)).toBe(60485);
        expect(dsDigest("dskey.example.com", key, 1)?.toString("hex")).toBe("2bb183af5f22588179a53b0a98631fad1a292118");
        expect(dsDigest("DSKEY.Example.COM", key, 1)?.toString("hex")).toBe("2bb183af5f22588179a53b0a98631fad1a292118");
    });

    it("the built-in trust anchors are the digests of the IANA root KSKs", () => {
        for (const [rdata, tag] of [
            [ROOT_KSK_2017, 20326],
            [ROOT_KSK_2024, 38696],
        ] as Array<[Buffer, number]>) {
            const key = parseDnskey(rdata);
            expect(key).toMatchObject({ flags: 257, protocol: 3, algorithm: 8, tag });
            const anchor = IANA_ROOT_TRUST_ANCHORS.find((a) => a.keyTag === tag);
            expect(anchor).toMatchObject({ algorithm: 8, digestType: 2 });
            expect(dsDigest("", rdata, 2)?.toString("hex").toUpperCase()).toBe(anchor?.digest);
            expect(dsMatches("", key as NonNullable<typeof key>, anchor as NonNullable<typeof anchor>)).toBe(true);
        }
        expect(IANA_ROOT_TRUST_ANCHORS).toHaveLength(2);
    });

    it("computes SHA-384 digests and refuses unknown types", () => {
        expect(dsDigest("example.com", ROOT_KSK_2024, 4)).toHaveLength(48);
        expect(dsDigest("example.com", ROOT_KSK_2024, 2)).toHaveLength(32);
        expect(dsDigest("example.com", ROOT_KSK_2024, 3)).toBeUndefined();
    });

    it("matches a DS to a key only with the same tag, algorithm and digest", () => {
        const key = parseDnskey(ROOT_KSK_2017) as NonNullable<ReturnType<typeof parseDnskey>>;
        const good = { keyTag: 20326, algorithm: 8, digestType: 2, digest: dsDigest("", ROOT_KSK_2017, 2) as Buffer };
        expect(dsMatches("", key, good)).toBe(true);
        expect(dsMatches("", key, { ...good, keyTag: 1 })).toBe(false);
        expect(dsMatches("", key, { ...good, algorithm: 7 })).toBe(false);
        expect(dsMatches("", key, { ...good, digest: Buffer.alloc(32) })).toBe(false);
        expect(dsMatches("com", key, good)).toBe(false);
        expect(dsMatches("", key, { ...good, digestType: 9 })).toBe(false);
    });

    it("parses DS and DNSKEY RDATA, refusing short ones", () => {
        expect(parseDs(makeDs("x", makeKey("p256", 257)))).toMatchObject({ algorithm: 13, digestType: 2 });
        expect(parseDs(Buffer.alloc(4))).toBeUndefined();
        expect(parseDnskey(Buffer.alloc(4))).toBeUndefined();
    });

    it("knows which algorithms and digests it supports, SHA-1 based ones excluded (RFC 8624)", () => {
        expect([1, 3, 5, 6, 7, 12].some(isSupportedAlgorithm)).toBe(false);
        expect([8, 10, 13, 14, 15, 16].every(isSupportedAlgorithm)).toBe(true);
        expect([1, 3].some(isSupportedDigest)).toBe(false);
        expect([2, 4].every(isSupportedDigest)).toBe(true);
    });
});

describe("public keys and signatures", () => {
    it.each<KeyKind>(["rsa256", "rsa512", "p256", "p384", "ed25519", "ed448"])(
        "imports a %s DNSKEY and verifies its signatures",
        (kind) => {
            const key = makeKey(kind, 256);
            const parsed = parseDnskey(key.rdata) as NonNullable<ReturnType<typeof parseDnskey>>;
            const object = importPublicKey(parsed.algorithm, parsed.key);
            expect(object).toBeDefined();
            const data = Buffer.from("the data that is signed");
            const signature = key.sign(data);
            expect(verifySignature(parsed.algorithm, object as NonNullable<typeof object>, data, signature)).toBe(true);
            const damaged = Buffer.from(signature);
            damaged[damaged.length - 1] ^= 1;
            expect(verifySignature(parsed.algorithm, object as NonNullable<typeof object>, data, damaged)).toBe(false);
            expect(
                verifySignature(parsed.algorithm, object as NonNullable<typeof object>, Buffer.from("other"), signature)
            ).toBe(false);
            expect(
                verifySignature(parsed.algorithm, object as NonNullable<typeof object>, data, signature.subarray(1))
            ).toBe(false);
            expect(verifySignature(parsed.algorithm, object as NonNullable<typeof object>, data, Buffer.alloc(0))).toBe(
                false
            );
        }
    );

    it("does not accept an RSASHA256 signature as RSASHA512 or vice versa", () => {
        const key = makeKey("rsa256", 256);
        const object = importPublicKey(8, parseDnskey(key.rdata)!.key)!;
        expect(verifySignature(10, object, Buffer.from("x"), key.sign(Buffer.from("x")))).toBe(false);
    });

    it("reads RSA keys with the long exponent-length form (RFC 3110)", () => {
        const { publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048, publicExponent: 65537 });
        const jwk = publicKey.export({ format: "jwk" });
        const e = Buffer.from(jwk.e as string, "base64url");
        const n = Buffer.from(jwk.n as string, "base64url");
        expect(importPublicKey(8, Buffer.concat([Buffer.from([e.length]), e, n]))).toBeDefined();
        expect(importPublicKey(8, Buffer.concat([Buffer.from([0]), u16(e.length), e, n]))).toBeDefined();
        // Leading zero bytes in the exponent are harmless.
        expect(importPublicKey(8, Buffer.concat([Buffer.from([e.length + 1, 0]), e, n]))).toBeDefined();
    });

    it("refuses weak or odd RSA keys", () => {
        const weak = generateKeyPairSync("rsa", { modulusLength: 512, publicExponent: 65537 }).publicKey.export({
            format: "jwk",
        });
        const small = Buffer.concat([
            Buffer.from([3]),
            Buffer.from("010001", "hex"),
            Buffer.from(weak.n as string, "base64url"),
        ]);
        expect(importPublicKey(8, small)).toBeUndefined();
        const good = makeKey("rsa256", 256);
        const key = parseDnskey(good.rdata)!.key;
        const modulus = key.subarray(1 + key[0]);
        expect(importPublicKey(8, Buffer.concat([Buffer.from([1, 2]), modulus]))).toBeUndefined();
        expect(importPublicKey(8, Buffer.concat([Buffer.from([1, 1]), modulus]))).toBeUndefined();
        expect(importPublicKey(8, Buffer.concat([Buffer.from([5, 1, 0, 0, 0, 1]), modulus]))).toBeUndefined();
        expect(
            importPublicKey(
                8,
                Buffer.concat([
                    Buffer.from([1, 3]),
                    Buffer.concat([
                        modulus.subarray(0, modulus.length - 1),
                        Buffer.from([modulus[modulus.length - 1] & 0xfe]),
                    ]),
                ])
            )
        ).toBeUndefined();
        expect(importPublicKey(8, Buffer.concat([Buffer.from([1, 3]), Buffer.alloc(600, 0xff)]))).toBeUndefined();
        expect(importPublicKey(8, Buffer.from([1, 3]))).toBeUndefined();
        expect(importPublicKey(8, Buffer.from([0, 0, 0]))).toBeUndefined();
        expect(importPublicKey(8, Buffer.alloc(0))).toBeUndefined();
        expect(importPublicKey(8, Buffer.concat([Buffer.from([0, 0, 200]), modulus]))).toBeUndefined();
    });

    it("refuses malformed ECDSA and EdDSA keys and unsupported algorithms", () => {
        const p256 = parseDnskey(makeKey("p256", 256).rdata)!.key;
        expect(importPublicKey(13, p256.subarray(1))).toBeUndefined();
        expect(importPublicKey(14, p256)).toBeUndefined();
        expect(importPublicKey(13, Buffer.alloc(64, 1))).toBeUndefined();
        expect(importPublicKey(15, Buffer.alloc(31))).toBeUndefined();
        expect(importPublicKey(16, Buffer.alloc(56))).toBeUndefined();
        for (const algorithm of [1, 3, 5, 6, 7, 12, 200]) {
            expect(importPublicKey(algorithm, p256)).toBeUndefined();
        }
        expect(verifySignature(5, importPublicKey(13, p256)!, Buffer.from("x"), Buffer.alloc(64))).toBe(false);
    });
});

describe("NSEC3 hashing and base32hex", () => {
    it("reproduces the RFC 5155 Appendix A hashes (salt aabbccdd, 12 iterations)", () => {
        const salt = hex("aabbccdd");
        const expected: Record<string, string> = {
            example: "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom",
            "a.example": "35mthgpgcu1qg68fab165klnsnk3dpvl",
            "ai.example": "gjeqe526plbf1g8mklp59enfd789njgi",
            "ns1.example": "2t7b4g4vsa5smi47k61mv5bv1a22bojr",
            "ns2.example": "q04jkcevqvmu85r014c7dkba38o0ji5r",
            "w.example": "k8udemvp1j2f7eg6jebps17vp3n8i58h",
            "*.w.example": "r53bq7cc2uvmubfu5ocmm6pers9tk9en",
            "x.w.example": "b4um86eghhds6nea196smvmlo4ors995",
            "y.w.example": "ji6neoaepv8b5o6k4ev33abha8ht9fgc",
            "x.y.w.example": "2vptu5timamqttgl4luu9kg21e0aor3s",
            "xx.example": "t644ebqk9bibcna874givr6joj62mlhv",
        };
        for (const [name, hash] of Object.entries(expected)) {
            expect(base32hexEncode(nsec3Hash(name, salt, 12))).toBe(hash);
        }
        expect(base32hexEncode(nsec3Hash("EXAMPLE", salt, 12))).toBe(expected.example);
    });

    it("hashes without salt and iterations as a plain SHA-1 of the wire name", () => {
        expect(nsec3Hash("example", Buffer.alloc(0), 0)).toHaveLength(20);
        expect(nsec3Hash("example", Buffer.alloc(0), 1).equals(nsec3Hash("example", Buffer.alloc(0), 0))).toBe(false);
    });

    it("encodes and decodes base32hex (RFC 4648 section 10, lower-case)", () => {
        for (const [plain, coded] of [
            ["", ""],
            ["f", "co"],
            ["fo", "cpng"],
            ["foo", "cpnmu"],
            ["foob", "cpnmuog"],
            ["fooba", "cpnmuoj1"],
            ["foobar", "cpnmuoj1e8"],
        ]) {
            expect(base32hexEncode(Buffer.from(plain))).toBe(coded);
            expect(base32hexDecode(coded)?.toString()).toBe(plain);
            expect(base32hexDecode(coded.toUpperCase())?.toString()).toBe(plain);
        }
        expect(base32hexDecode("w")).toBeUndefined();
        expect(base32hexDecode("a-b")).toBeUndefined();
    });
});

describe("type bitmaps and NSEC parsing", () => {
    it("round-trips type sets across windows", () => {
        const types = [1, 2, 6, 16, 46, 47, 48, 257, 65534];
        expect([...(parseTypeBitmap(encodeBitmap(types)) as Set<number>)].sort((a, b) => a - b)).toEqual(types);
        expect(parseTypeBitmap(Buffer.alloc(0))).toEqual(new Set());
        expect(parseTypeBitmap(hex("00 06 40 01 00 00 00 03"))).toEqual(new Set([1, 15, 46, 47]));
    });

    it("rejects malformed bitmaps", () => {
        for (const bad of ["00", "00 00", "00 21 " + "00".repeat(33), "00 02 40", "01 01 40 00 01 40", "00 01 40 00"]) {
            expect(parseTypeBitmap(hex(bad))).toBeUndefined();
        }
    });

    it("parses NSEC and NSEC3 records, refusing malformed ones", () => {
        expect(parseNsec("a.example", Buffer.concat([wireName("b.example"), encodeBitmap([1, 46, 47])]))).toEqual({
            owner: "a.example",
            next: "b.example",
            types: new Set([1, 46, 47]),
        });
        expect(parseNsec("a.example", Buffer.from([3, 97]))).toBeUndefined();
        expect(parseNsec("a.example", Buffer.concat([wireName("b.example"), Buffer.from([0, 0])]))).toBeUndefined();
        const hash = nsec3Hash("a.example", Buffer.alloc(0), 0);
        const owner = `${base32hexEncode(hash)}.example`;
        const rdata = Buffer.concat([Buffer.from([1, 1, 0, 5, 2, 0xaa, 0xbb, 20]), hash, encodeBitmap([1])]);
        expect(parseNsec3(owner, "example", rdata)).toMatchObject({
            algorithm: 1,
            flags: 1,
            iterations: 5,
            types: new Set([1]),
        });
        expect(parseNsec3(owner, "other", rdata)).toBeUndefined();
        expect(parseNsec3(`x.${owner}`, "example", rdata)).toBeUndefined();
        expect(parseNsec3("short.example", "example", rdata)).toBeUndefined();
        expect(parseNsec3(owner, "example", rdata.subarray(0, 20))).toBeUndefined();
        const wrongLength = Buffer.from(rdata);
        wrongLength[7] = 19;
        expect(parseNsec3(owner, "example", wrongLength)).toBeUndefined();
        expect(parseNsec3(owner, "example", Buffer.alloc(3))).toBeUndefined();
    });
});

describe("NSEC denial", () => {
    // example. -> a.example. -> d.example. (delegation) -> dn.example. (DNAME) -> ent's child -> z.example. -> example.
    const chain = [
        ["example", "a.example", [6, 2, 46, 47]],
        ["a.example", "d.example", [1, 46, 47]],
        ["d.example", "dn.example", [2, 43, 46, 47]],
        ["dn.example", "x.ent.example", [39, 46, 47]],
        ["x.ent.example", "z.example", [1, 46, 47]],
        ["z.example", "example", [1, 46, 47]],
    ] as Array<[string, string, number[]]>;
    const denial = new NsecDenial(
        "example",
        chain.map(([owner, next, types]) => ({ owner, next, types: new Set(types) }))
    );

    it("matches the owner's bitmap", () => {
        expect(denial.matching("a.example")).toEqual(new Set([1, 46, 47]));
        expect(denial.matching("q.example")).toBeUndefined();
    });

    it("proves a name does not exist and finds its closest encloser", () => {
        expect(denial.nonexistence("b.example")).toEqual({ closestEncloser: "example", optOut: false });
        expect(denial.nonexistence("y.ent.example")).toEqual({ closestEncloser: "ent.example", optOut: false });
        expect(denial.nonexistence("b.a.example")).toEqual({ closestEncloser: "a.example", optOut: false });
    });

    it("handles the wrap-around record at the end of the zone", () => {
        expect(denial.nonexistence("zz.example")).toEqual({ closestEncloser: "example", optOut: false });
        expect(denial.covers("zz.example")).toBe(true);
        expect(denial.covers("z.example")).toBe(false);
    });

    it("recognises an empty non-terminal from the next name of the covering record", () => {
        expect(denial.matching("ent.example")).toEqual(new Set());
        expect(denial.nonexistence("ent.example")).toBeUndefined();
    });

    it("gives no proof for names below a delegation or a DNAME", () => {
        expect(denial.nonexistence("www.d.example")).toBeUndefined();
        expect(denial.nonexistence("www.dn.example")).toBeUndefined();
        expect(denial.covers("www.d.example")).toBe(false);
    });

    it("gives no proof for names outside the zone, and ignores records outside it", () => {
        expect(denial.nonexistence("b.other")).toBeUndefined();
        const foreign = new NsecDenial("example", [{ owner: "a.other", next: "z.other", types: new Set([1]) }]);
        expect(foreign.matching("a.other")).toBeUndefined();
        expect(foreign.nonexistence("b.other")).toBeUndefined();
    });

    it("a single-record zone covers every other name", () => {
        const single = new NsecDenial("example", [{ owner: "example", next: "example", types: new Set([6, 2]) }]);
        expect(single.nonexistence("a.example")).toEqual({ closestEncloser: "example", optOut: false });
        expect(single.nonexistence("example")).toBeUndefined();
    });
});

describe("NSEC3 denial", () => {
    const salt = hex("abcd");
    const build = (names: Array<[string, number[]]>, flags = 0, iterations = 2): Nsec3Record[] => {
        const hashed = names.map(([name, types]) => ({ hash: nsec3Hash(name, salt, iterations), types }));
        hashed.sort((a, b) => Buffer.compare(a.hash, b.hash));
        return hashed.map((h, i) => ({
            hash: h.hash,
            next: hashed[(i + 1) % hashed.length].hash,
            algorithm: 1,
            iterations,
            salt,
            flags,
            types: new Set(h.types),
        }));
    };
    const records = build([
        ["example", [6, 2, 46]],
        ["a.example", [1, 46]],
        ["b.a.example", []],
        ["c.b.a.example", [1, 46]],
        ["d.example", [2]],
        ["dn.example", [39]],
    ]);
    const denial = new Nsec3Denial("example", records);

    it("matches names by hash", () => {
        expect(denial.matching("a.example")).toEqual(new Set([1, 46]));
        expect(denial.matching("b.a.example")).toEqual(new Set());
        expect(denial.matching("zzz.example")).toBeUndefined();
        expect(denial.matching("a.other")).toBeUndefined();
    });

    it("finds the closest encloser through the next-closer name", () => {
        expect(denial.nonexistence("q.example")).toEqual({ closestEncloser: "example", optOut: false });
        expect(denial.nonexistence("q.b.a.example")).toEqual({ closestEncloser: "b.a.example", optOut: false });
        expect(denial.nonexistence("x.y.a.example")).toEqual({ closestEncloser: "a.example", optOut: false });
        expect(denial.nonexistence("a.example")).toBeUndefined();
        expect(denial.nonexistence("q.other")).toBeUndefined();
    });

    it("refuses a delegation or a DNAME as the closest encloser", () => {
        expect(denial.nonexistence("www.d.example")).toBeUndefined();
        expect(denial.nonexistence("www.dn.example")).toBeUndefined();
    });

    it("reports the opt-out flag of the record covering the next closer", () => {
        const opt = new Nsec3Denial(
            "example",
            build(
                [
                    ["example", [6, 2, 46]],
                    ["a.example", [1]],
                ],
                1
            )
        );
        expect(opt.nonexistence("q.example")).toEqual({ closestEncloser: "example", optOut: true });
        expect(opt.covers("q.example")).toBe(true);
        expect(opt.covers("a.example")).toBe(false);
    });

    it("gives no proof when the covering record is missing", () => {
        const single = new Nsec3Denial("example", build([["example", [6, 2, 46]]]));
        expect(single.nonexistence("q.example")).toEqual({ closestEncloser: "example", optOut: false });
        const partial = new Nsec3Denial(
            "example",
            records.filter((r) => r.hash.equals(nsec3Hash("example", salt, 2)))
        );
        expect(partial.nonexistence("q.example")).toBeUndefined();
        const noApex = new Nsec3Denial(
            "example",
            records.filter((r) => !r.hash.equals(nsec3Hash("example", salt, 2)))
        );
        expect(noApex.nonexistence("q.example")).toBeUndefined();
    });
});

function zoneKey(kind: KeyKind = "p256"): { key: ReturnType<typeof makeKey>; trusted: TrustedKey[] } {
    const key = makeKey(kind, 256);
    return { key, trusted: [parseDnskey(key.rdata) as TrustedKey] };
}

function asRecords(rrs: RR[]): DnsRecord[] {
    return rrs.map((r) => ({ ...r, cls: 1 }));
}

describe("RRset validation", () => {
    const rrset: RR[] = [
        { name: "host.example.com", type: T.A, ttl: 300, rdata: aRdata("192.0.2.1") },
        { name: "host.example.com", type: T.A, ttl: 300, rdata: aRdata("192.0.2.2") },
    ];
    const now = new Date("2026-06-01T00:00:00Z");
    const seconds = Math.floor(now.getTime() / 1000);

    function validate(sig: RR, at: Date = now, keys?: TrustedKey[], name = "host.example.com", records: RR[] = rrset) {
        return validateRrset({
            name,
            type: T.A,
            records: asRecords(records),
            sigs: asRecords([sig]),
            zone: "example.com",
            keys: keys ?? zone.trusted,
            now: at,
        });
    }
    const zone = zoneKey();

    it("validates and reports the signature's expiry and the RRset's TTL", () => {
        const sig = signRrset("example.com", zone.key, rrset, {
            inception: seconds - 100,
            expiration: seconds + 1000,
            originalTtl: 200,
        });
        const result = validate(sig);
        expect(result.wildcardLabels).toBeUndefined();
        expect(result.expiresAt).toBe(now.getTime() + 1000_000);
        expect(result.ttl).toBe(200);
    });

    it("the RRset's own order and duplicates do not matter", () => {
        const sig = signRrset("example.com", zone.key, rrset);
        expect(() => validate(sig, now, undefined, "host.example.com", [rrset[1], rrset[0], rrset[0]])).not.toThrow();
    });

    it("signs the original TTL, not the TTL the RRset arrived with", () => {
        const sig = signRrset("example.com", zone.key, rrset, { originalTtl: 3600 });
        const decremented = rrset.map((r) => ({ ...r, ttl: 17 }));
        expect(validate(sig, now, undefined, "host.example.com", decremented).ttl).toBe(17);
    });

    it("uses RFC 1982 serial arithmetic so times may wrap past 2^32", () => {
        const wrapped = new Date((2 ** 32 + 50) * 1000);
        const sig = signRrset("example.com", zone.key, rrset, { inception: 2 ** 32 - 3000, expiration: 5000 });
        expect(() => validate(sig, wrapped)).not.toThrow();
        expect(() => validate(sig, new Date((2 ** 32 - 100) * 1000))).not.toThrow();
        expect(() => validate(sig, new Date((2 ** 32 + 6000) * 1000))).toThrow(/expired/);
        expect(() => validate(sig, new Date((2 ** 32 - 5000) * 1000))).toThrow(/not yet valid/);
    });

    it("recognises a wildcard expansion and reports the wildcard's parent label count", () => {
        const wildcard: RR[] = rrset.map((r) => ({ ...r, name: "*.example.com" }));
        const sig = signRrset("example.com", zone.key, wildcard);
        const expanded = rrset.map((r) => ({ ...r, name: "foo.bar.example.com" }));
        const result = validate(
            { ...sig, name: "foo.bar.example.com" },
            now,
            undefined,
            "foo.bar.example.com",
            expanded
        );
        expect(result.wildcardLabels).toBe(2);
        // A literal query of the wildcard itself is not an expansion.
        expect(validate(sig, now, undefined, "*.example.com", wildcard).wildcardLabels).toBeUndefined();
    });

    it("insists on the signer being the zone, the name lying inside it, and a matching key", () => {
        const sig = signRrset("example.com", zone.key, rrset);
        expect(() => validate(signRrset("example.com", zone.key, rrset, { signer: "com" }))).toThrow(DnssecError);
        expect(() => validate(sig, now, zoneKey().trusted)).toThrow(/no validated zone key/);
        expect(() => validate(sig, now, [])).toThrow(DnssecError);
        const outside = rrset.map((r) => ({ ...r, name: "host.other.org" }));
        expect(() =>
            validate(signRrset("example.com", zone.key, outside), now, undefined, "host.other.org", outside)
        ).toThrow(/not inside the zone/);
        expect(() => validate({ ...sig, name: "someone.else.example.com" })).toThrow(/no RRSIG/);
        expect(() =>
            validateRrset({
                name: "host.example.com",
                type: T.A,
                records: [],
                sigs: asRecords([sig]),
                zone: "example.com",
                keys: zone.trusted,
                now,
            })
        ).toThrow(DnssecError);
    });

    it("refuses an RRSIG that is truncated or has no signature", () => {
        const sig = signRrset("example.com", zone.key, rrset);
        expect(() => validate({ ...sig, rdata: sig.rdata.subarray(0, 18 + 13) })).toThrow(DnssecError);
        expect(() => validate({ ...sig, rdata: sig.rdata.subarray(0, 10) })).toThrow(DnssecError);
        expect(parseRrsig(sig.rdata.subarray(0, 18 + 13))).toBeUndefined();
        expect(parseRrsig(sig.rdata)).toMatchObject({
            typeCovered: T.A,
            algorithm: 13,
            signer: "example.com",
            keyTag: zone.key.tag,
        });
    });

    it("skips a key that cannot be imported", () => {
        const sig = signRrset("example.com", zone.key, rrset);
        const broken: TrustedKey = { ...(parseDnskey(zone.key.rdata) as TrustedKey), key: Buffer.alloc(10) };
        expect(() => validate(sig, now, [broken])).toThrow(/unusable/);
    });
});

describe("canonical RDATA", () => {
    it("lower-cases the names embedded in NS, CNAME, PTR, DNAME, MX, SRV and SOA", () => {
        const upper = wireName("Foo.EXAMPLE.com", true);
        const lower = wireName("foo.example.com");
        for (const type of [T.NS, T.CNAME, 12, T.DNAME]) {
            expect(canonicalRdata(type, upper)).toEqual(lower);
        }
        expect(canonicalRdata(T.MX, Buffer.concat([u16(10), upper]))).toEqual(Buffer.concat([u16(10), lower]));
        expect(canonicalRdata(33, Buffer.concat([u16(1), u16(2), u16(3), upper]))).toEqual(
            Buffer.concat([u16(1), u16(2), u16(3), lower])
        );
        const numbers = Buffer.alloc(20, 1);
        expect(canonicalRdata(T.SOA, Buffer.concat([upper, wireName("Admin.EXAMPLE.com", true), numbers]))).toEqual(
            Buffer.concat([lower, wireName("admin.example.com"), numbers])
        );
    });

    it("leaves NSEC, DS, DNSKEY, CAA, TXT, A and AAAA RDATA untouched (NSEC's next name keeps its case, RFC 6840)", () => {
        const nsec = Buffer.concat([wireName("Next.Example", true), encodeBitmap([1])]);
        expect(canonicalRdata(T.NSEC, nsec)).toBe(nsec);
        for (const type of [T.DS, T.DNSKEY, T.CAA, T.TXT, T.A, 28, T.NSEC3, T.NSEC3PARAM]) {
            const rdata = Buffer.from("abcdef");
            expect(canonicalRdata(type, rdata)).toBe(rdata);
        }
        expect(canonicalRdata(T.CAA, caaRdata(0, "issue", "CA.Example"))).toEqual(caaRdata(0, "issue", "CA.Example"));
    });

    it("refuses RR types it has no rules for, and malformed name RDATA", () => {
        expect(() => canonicalRdata(13, Buffer.from([1, 2]))).toThrow(DnssecError);
        expect(() => canonicalRdata(T.CNAME, Buffer.concat([wireName("a.b"), Buffer.from([1])]))).toThrow(DnssecError);
        expect(() => canonicalRdata(T.MX, Buffer.from([0, 1]))).toThrow(DnssecError);
        expect(() => canonicalRdata(T.SOA, Buffer.alloc(5))).toThrow(DnssecError);
        expect(() => canonicalRdata(33, Buffer.alloc(3))).toThrow(DnssecError);
    });

    it("signs RRs sorted by canonical RDATA with duplicates removed, after the RRSIG header", () => {
        const sig = parseRrsig(
            signRrset("example.com", makeKey("p256", 256), [
                { name: "h.example.com", type: T.A, ttl: 60, rdata: aRdata("1.1.1.1") },
            ]).rdata
        )!;
        const data = signedData(sig, "h.example.com", T.A, [aRdata("2.2.2.2"), aRdata("1.1.1.1"), aRdata("2.2.2.2")]);
        const owner = wireName("h.example.com");
        const rr = (ip: string): Buffer =>
            Buffer.concat([owner, u16(T.A), u16(1), Buffer.from([0, 0, 0, 60]), u16(4), aRdata(ip)]);
        expect(data).toEqual(Buffer.concat([sig.header, rr("1.1.1.1"), rr("2.2.2.2")]));
    });
});
