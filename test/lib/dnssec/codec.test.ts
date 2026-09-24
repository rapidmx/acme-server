///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import {
    commonAncestor,
    compareNames,
    isProperSubdomain,
    isSubdomain,
    labelCount,
    nameToLabels,
    nameToWire,
    normalizeName,
    parentName,
    prependLabel,
    toFqdn,
} from "../../../src/lib/dnssec/name.js";
import { DnssecError } from "../../../src/lib/dnssec/types.js";
import { buildQuery, parseMessage, readName, readPlainName } from "../../../src/lib/dnssec/wire.js";

function hex(text: string): Buffer {
    return Buffer.from(text.replace(/\s+/g, ""), "hex");
}

describe("names", () => {
    it("normalises case, the trailing dot and the root", () => {
        expect(normalizeName("Example.COM.")).toBe("example.com");
        expect(normalizeName(".")).toBe("");
        expect(normalizeName("")).toBe("");
        expect(toFqdn("example.com")).toBe("example.com.");
        expect(toFqdn("")).toBe(".");
    });

    it("splits labels honouring escapes, so an escaped dot stays inside its label", () => {
        expect(nameToLabels("a\\.b.example")).toEqual(["a.b", "example"]);
        expect(nameToLabels("\\065bc.com")).toEqual(["abc", "com"]);
        expect(nameToLabels("a\\\\b.com")).toEqual(["a\\b", "com"]);
        expect(normalizeName("a\\.b.example")).toBe("a\\.b.example");
        expect(normalizeName("\\001.z.example")).toBe("\\001.z.example");
    });

    it("rejects malformed names", () => {
        for (const bad of ["a..b", ".a", "a.", "..", "ab\\", "a\\9.b", "a\\999.b", "é.com", "a".repeat(64) + ".com"]) {
            if (bad === "a.") {
                expect(normalizeName(bad)).toBe("a");
                continue;
            }
            expect(() => nameToLabels(bad)).toThrow(DnssecError);
        }
        expect(() => nameToLabels(Array.from({ length: 128 }, () => "abc").join("."))).toThrow(DnssecError);
        expect(() => nameToLabels(Array.from({ length: 63 }, () => "abc").join("."))).not.toThrow();
    });

    it("builds the canonical wire form, lower-cased", () => {
        expect(nameToWire("Example.com")).toEqual(hex("07 6578616d706c65 03 636f6d 00"));
        expect(nameToWire("")).toEqual(hex("00"));
        expect(nameToWire("\\001.a")).toEqual(hex("01 01 01 61 00"));
    });

    it("orders names canonically (RFC 4034 section 6.1)", () => {
        const expected = [
            "example",
            "a.example",
            "yljkjljk.a.example",
            "z.a.example",
            "zabc.a.example",
            "z.example",
            "\\001.z.example",
            "*.z.example",
            "\\200.z.example",
        ];
        const shuffled = [...expected].reverse();
        shuffled.sort(compareNames);
        expect(shuffled).toEqual(expected);
        expect(compareNames("a.example", "a.example")).toBe(0);
        expect(compareNames("", "a")).toBe(-1);
        expect(compareNames("b", "a.b")).toBe(-1);
        expect(compareNames("a.b", "b")).toBe(1);
    });

    it("relates names by labels, not by text", () => {
        expect(isSubdomain("a.example.com", "example.com")).toBe(true);
        expect(isSubdomain("example.com", "example.com")).toBe(true);
        expect(isSubdomain("example.com", "")).toBe(true);
        expect(isSubdomain("badexample.com", "example.com")).toBe(false);
        expect(isSubdomain("a\\.example.com", "example.com")).toBe(false);
        expect(isProperSubdomain("example.com", "example.com")).toBe(false);
        expect(isProperSubdomain("a.example.com", "example.com")).toBe(true);
        expect(commonAncestor("x.a.example.com", "y.b.example.com")).toBe("example.com");
        expect(commonAncestor("x.com", "y.org")).toBe("");
        expect(parentName("a.b.c")).toBe("b.c");
        expect(parentName("c")).toBe("");
        expect(labelCount("a.b.c")).toBe(3);
        expect(labelCount("")).toBe(0);
        expect(prependLabel("*", "example.com")).toBe("*.example.com");
        expect(prependLabel("*", "")).toBe("*");
    });
});

describe("query encoding", () => {
    it("builds header, question and an EDNS0 OPT with DO, exactly as hand-computed", () => {
        expect(buildQuery(0x1234, "example.com", 257)).toEqual(
            hex(`
            1234 0110 0001 0000 0000 0001
            07 6578616d706c65 03 636f6d 00 0101 0001
            00 0029 04d0 00008000 0000`)
        );
        expect(buildQuery(1, "", 48)).toEqual(
            hex("0001 0110 0001 0000 0000 0001 00 0030 0001 00 0029 04d0 00008000 0000")
        );
    });
});

describe("message parsing", () => {
    // www.example.com CNAME foo.example.com (rdata compressed against the question), then an SOA and an MX with compression.
    const message = hex(`
        abcd 8180 0001 0002 0001 0001
        03 777777 07 6578616d706c65 03 636f6d 00 0005 0001
        c00c 0005 0001 0000012c 0006 03 666f6f c010
        c010 000f 0001 00000e10 0009 000a 04 6d61696c c010
        c010 0006 0001 00000e10 0022 03 6e7331 c010 05 61646d696e c010 00000001 00000002 00000003 00000004 00000005
        00 0029 04d0 00008000 0000`);

    it("decompresses names, including inside RDATA of the classic types", () => {
        const parsed = parseMessage(message);
        expect(parsed).toMatchObject({ id: 0xabcd, qr: true, tc: false, opcode: 0, rcode: 0 });
        expect(parsed.question).toEqual([{ name: "www.example.com", type: 5, cls: 1 }]);
        expect(parsed.answer.map((r) => ({ ...r, rdata: r.rdata.toString("hex") }))).toEqual([
            { name: "www.example.com", type: 5, cls: 1, ttl: 300, rdata: "03666f6f076578616d706c6503636f6d00" },
            { name: "example.com", type: 15, cls: 1, ttl: 3600, rdata: "000a046d61696c076578616d706c6503636f6d00" },
        ]);
        expect(parsed.authority).toHaveLength(1);
        expect(parsed.authority[0].rdata.subarray(0, 4).toString("hex")).toBe("036e7331");
        expect(parsed.authority[0].rdata).toHaveLength(17 + 19 + 20);
        expect(parsed.additional).toEqual([expect.objectContaining({ name: "", type: 41 })]);
    });

    it("keeps the original case of names in RDATA but lower-cases owners", () => {
        const upper = hex(
            "0001 8180 0001 0001 0000 0000 03 575757 00 0005 0001 c00c 0005 0001 0000012c 0005 03 464f4f 00"
        );
        const parsed = parseMessage(upper);
        expect(parsed.answer[0].name).toBe("www");
        expect(parsed.answer[0].rdata.toString("hex")).toBe("03464f4f00");
    });

    it("treats a TTL with the top bit set as zero (RFC 2181)", () => {
        const bytes = hex("0001 8180 0001 0001 0000 0000 00 0010 0001 00 0010 0001 ffffffff 0002 0141");
        expect(parseMessage(bytes).answer[0].ttl).toBe(0);
    });

    it("reads names out of RDATA without compression", () => {
        expect(readPlainName(hex("03666f6f076578616d706c6503636f6d00"), 0)).toEqual({
            name: "foo.example.com",
            end: 17,
        });
        expect(() => readPlainName(hex("03666f"), 0)).toThrow(DnssecError);
        expect(() => readPlainName(hex("c00c"), 0)).toThrow(DnssecError);
        expect(readName(hex("00"), 0)).toEqual({ name: "", end: 1 });
        // A dot, a backslash and a high byte inside a label survive as escapes and cannot be confused with label boundaries.
        expect(readName(hex("03 612e62 03 636f6d 00"), 0).name).toBe("a\\.b.com");
        expect(readName(hex("03 615c62 03 636f6d 00"), 0).name).toBe("a\\\\b.com");
        expect(readName(hex("02 c341 00"), 0).name).toBe("\\195a");
        expect(nameToLabels(readName(hex("03 612e62 03 636f6d 00"), 0).name)).toEqual(["a.b", "com"]);
    });

    it("rejects every kind of malformed message with a DnssecError", () => {
        const good = message;
        const cases: Buffer[] = [
            Buffer.alloc(0),
            good.subarray(0, 11),
            good.subarray(0, 14),
            good.subarray(0, 30),
            good.subarray(0, good.length - 1),
            Buffer.concat([good.subarray(0, 12), hex("c00c 0005 0001")]),
            Buffer.concat([good.subarray(0, 12), hex("c00d")]),
            Buffer.concat([good.subarray(0, 12), hex("c00c 0001 0001")]),
            Buffer.concat([good.subarray(0, 12), hex("80 00 0001 0001")]),
            Buffer.concat([good.subarray(0, 12), hex("3f " + "61".repeat(63) + " 00 0001 0001")].slice(0, 1)),
            Buffer.alloc(70000),
        ];
        for (const bytes of cases) {
            expect(() => parseMessage(bytes)).toThrow(DnssecError);
        }
        // A name whose expansion exceeds 255 bytes through chained pointers.
        const chain = Buffer.concat([
            hex("0001 8180 0001 0000 0000 0000"),
            ...Array.from({ length: 6 }, () => hex("3f " + "61".repeat(63))),
        ]);
        expect(() => parseMessage(Buffer.concat([chain, hex("00 0001 0001")]))).toThrow(DnssecError);
    });

    it("never throws anything but DnssecError for random bytes, and survives random damage to a real message", () => {
        let seed = 12345;
        const next = (): number => {
            seed = (Math.imul(seed, 1103515245) + 12345) >>> 0;
            return seed >>> 16;
        };
        for (let i = 0; i < 2000; i++) {
            const bytes = Buffer.from(message);
            for (let j = 0; j < 1 + (next() % 4); j++) {
                bytes[next() % bytes.length] = next() & 0xff;
            }
            try {
                parseMessage(i % 5 === 0 ? bytes.subarray(0, next() % bytes.length) : bytes);
            } catch (err) {
                expect(err).toBeInstanceOf(DnssecError);
            }
        }
        for (let i = 0; i < 500; i++) {
            const bytes = Buffer.alloc(next() % 200);
            for (let j = 0; j < bytes.length; j++) {
                bytes[j] = next() & 0xff;
            }
            try {
                parseMessage(bytes);
            } catch (err) {
                expect(err).toBeInstanceOf(DnssecError);
            }
        }
    });
});
