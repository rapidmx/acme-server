///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { derInteger, derLength, derOid, derSequence } from "../../../src/lib/pki/der.js";
import { certificateParts, keyIdentifierOf, readTlv, spkiKeyBits } from "../../../src/lib/pki/certutil.js";
import {
    b64url,
    bytesEqual,
    derToPem,
    floorToSecond,
    fromB64url,
    parseMailbox,
    pemBlocks,
    pemToDer,
    randomSerial,
    serialBytesToHex,
    serialHexToDerContent,
    sha256Hex,
} from "../../../src/lib/pki/util.js";
import { makeHierarchy, newSubjectKey } from "./helpers.js";
import * as crypto from "node:crypto";

describe("PEM helpers", () => {
    it("round trips DER through PEM with 64-column lines", () => {
        const der = new Uint8Array(crypto.randomBytes(150));
        const pem = derToPem(der, "CERTIFICATE");
        expect(pem.startsWith("-----BEGIN CERTIFICATE-----\n")).toBe(true);
        expect(pem.endsWith("-----END CERTIFICATE-----\n")).toBe(true);
        for (const line of pem.split("\n").slice(1, -2)) {
            expect(line.length).toBeLessThanOrEqual(64);
        }
        expect(Buffer.from(pemToDer(pem)).equals(Buffer.from(der))).toBe(true);
    });

    it("selects a block by label and returns them all", () => {
        const a = derToPem(Uint8Array.of(1, 2, 3), "CERTIFICATE");
        const b = derToPem(Uint8Array.of(4, 5, 6), "X509 CRL");
        expect(Array.from(pemToDer(a + b, "X509 CRL"))).toEqual([4, 5, 6]);
        expect(pemBlocks(a + b).map((x) => x.label)).toEqual(["CERTIFICATE", "X509 CRL"]);
        expect(() => pemToDer(a, "X509 CRL")).toThrow(/No PEM block labelled/);
        expect(() => pemToDer("nothing here")).toThrow(/No PEM block/);
    });

    it("rejects invalid base64 inside a PEM block instead of skipping the garbage", () => {
        expect(() => pemToDer("-----BEGIN CERTIFICATE-----\nAA$A\n-----END CERTIFICATE-----")).toThrow(/Invalid base64/);
        expect(() => pemToDer("-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----")).toThrow(/Invalid base64/);
    });
});

describe("base64url", () => {
    it("encodes without padding and decodes back", () => {
        for (const len of [0, 1, 2, 3, 4, 31, 32, 33]) {
            const data = new Uint8Array(crypto.randomBytes(len));
            const s = b64url(data);
            expect(s).not.toMatch(/[=+/]/);
            expect(Buffer.from(fromB64url(s)).equals(Buffer.from(data))).toBe(true);
        }
    });

    it("rejects padding, the standard alphabet, whitespace and non-canonical trailing bits", () => {
        expect(() => fromB64url("AQ==")).toThrow();
        expect(() => fromB64url("+/8")).toThrow();
        expect(() => fromB64url("AQ Q")).toThrow();
        expect(() => fromB64url("A")).toThrow();
        // "AR" decodes to 0x01 but has non-zero trailing bits; the canonical form is "AQ"
        expect(() => fromB64url("AR")).toThrow(/Non-canonical/);
        expect(Array.from(fromB64url("AQ"))).toEqual([1]);
    });
});

describe("misc helpers", () => {
    it("computes SHA-256 hex", () => {
        expect(sha256Hex(new TextEncoder().encode("abc"))).toBe(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    });

    it("compares byte strings", () => {
        expect(bytesEqual(Uint8Array.of(1, 2), Uint8Array.of(1, 2))).toBe(true);
        expect(bytesEqual(Uint8Array.of(1, 2), Uint8Array.of(1, 3))).toBe(false);
        expect(bytesEqual(Uint8Array.of(1, 2), Uint8Array.of(1, 2, 3))).toBe(false);
    });

    it("floors dates to whole seconds", () => {
        expect(floorToSecond(new Date("2030-01-02T03:04:05.999Z")).toISOString()).toBe("2030-01-02T03:04:05.000Z");
    });
});

describe("randomSerial", () => {
    it("is 20 octets, positive, with a non-zero leading octet, and does not repeat", () => {
        const seen = new Set<string>();
        for (let i = 0; i < 2000; i++) {
            const s = randomSerial();
            expect(s.length).toBe(20);
            expect(s[0] & 0x80).toBe(0);
            expect(s[0]).not.toBe(0);
            seen.add(Buffer.from(s).toString("hex"));
        }
        expect(seen.size).toBe(2000);
    });

    it("uses the full 159 bits (top octet takes many distinct values)", () => {
        const tops = new Set<number>();
        for (let i = 0; i < 3000; i++) tops.add(randomSerial()[0]);
        expect(tops.size).toBeGreaterThan(100);
    });
});

describe("serial numbers", () => {
    it("normalizes DER INTEGER content to canonical hex", () => {
        expect(serialBytesToHex(Uint8Array.of(0x00, 0x80, 0x01))).toBe("8001");
        expect(serialBytesToHex(Uint8Array.of(0x05, 0x01))).toBe("0501");
        expect(serialBytesToHex(Uint8Array.of(0x00, 0x00, 0x05))).toBe("05");
    });

    it("refuses values that are not valid positive serials", () => {
        expect(serialBytesToHex(new Uint8Array())).toBeUndefined();
        expect(serialBytesToHex(Uint8Array.of(0))).toBeUndefined();
        // negative INTEGER: must not alias the positive value with the same octets
        expect(serialBytesToHex(Uint8Array.of(0xff))).toBeUndefined();
        expect(serialBytesToHex(new Uint8Array(21).fill(1))).toBeUndefined();
    });

    it("converts hex back to DER content with a sign octet when needed", () => {
        expect(Buffer.from(serialHexToDerContent("8001")).toString("hex")).toBe("008001");
        expect(Buffer.from(serialHexToDerContent("7f01")).toString("hex")).toBe("7f01");
        expect(Buffer.from(serialHexToDerContent("007f")).toString("hex")).toBe("7f");
        expect(() => serialHexToDerContent("")).toThrow();
        expect(() => serialHexToDerContent("abc")).toThrow();
        expect(() => serialHexToDerContent("00")).toThrow();
        expect(() => serialHexToDerContent("zz")).toThrow();
        expect(() => serialHexToDerContent("01".repeat(21))).toThrow();
    });
});

describe("parseMailbox", () => {
    it("accepts ordinary addresses and lower-cases only the domain", () => {
        expect(parseMailbox("Alice.Smith+tag@Example.COM")).toBe("Alice.Smith+tag@example.com");
        expect(parseMailbox("a@b.co")).toBe("a@b.co");
        expect(parseMailbox("o'brien@sub.example.org")).toBe("o'brien@sub.example.org");
        expect(parseMailbox("x@xn--bcher-kva.example")).toBe("x@xn--bcher-kva.example");
    });

    it.each([
        ["no at sign", "alice.example.com"],
        ["two at signs", "a@b@example.com"],
        ["empty local", "@example.com"],
        ["empty domain", "alice@"],
        ["single label domain", "alice@localhost"],
        ["numeric TLD", "alice@example.123"],
        ["IP literal", "alice@[127.0.0.1]"],
        ["leading dot", ".alice@example.com"],
        ["trailing dot", "alice.@example.com"],
        ["double dot", "al..ice@example.com"],
        ["quoted local", '"alice smith"@example.com'],
        ["space", "alice smith@example.com"],
        ["angle brackets", "<alice@example.com>"],
        ["display name", "Alice <alice@example.com>"],
        ["non-ASCII local", "ålice@example.com"],
        ["non-ASCII domain", "alice@exämple.com"],
        ["control character", "alice\u0000@example.com"],
        ["newline injection", "alice@example.com\r\nBcc: x@y.z"],
        ["leading hyphen label", "alice@-example.com"],
        ["trailing dot domain", "alice@example.com."],
        ["underscore in domain", "alice@exa_mple.com"],
        ["local too long", "a".repeat(65) + "@example.com"],
        ["label too long", "a@" + "b".repeat(64) + ".com"],
        ["whole address too long", "a@" + ("b".repeat(60) + ".").repeat(4) + "com" + "c".repeat(20)],
    ])("rejects %s", (_name, address) => {
        expect(parseMailbox(address)).toBeUndefined();
    });

    it("rejects non-strings", () => {
        expect(parseMailbox(undefined as unknown as string)).toBeUndefined();
        expect(parseMailbox(42 as unknown as string)).toBeUndefined();
    });
});

describe("DER helpers", () => {
    it("encodes lengths in short and long form", () => {
        expect(Array.from(derLength(5))).toEqual([5]);
        expect(Array.from(derLength(127))).toEqual([127]);
        expect(Array.from(derLength(128))).toEqual([0x81, 0x80]);
        expect(Array.from(derLength(0x1234))).toEqual([0x82, 0x12, 0x34]);
        expect(() => derLength(-1)).toThrow();
    });

    it("encodes minimal positive INTEGERs", () => {
        expect(Buffer.from(derInteger(0n)).toString("hex")).toBe("020100");
        expect(Buffer.from(derInteger(127n)).toString("hex")).toBe("02017f");
        expect(Buffer.from(derInteger(128n)).toString("hex")).toBe("02020080");
        expect(Buffer.from(derInteger(256n)).toString("hex")).toBe("02020100");
        expect(() => derInteger(-1n)).toThrow();
    });

    it("encodes OBJECT IDENTIFIERS", () => {
        expect(Buffer.from(derOid("1.2.840.113549.1.1.11")).toString("hex")).toBe("06092a864886f70d01010b");
        expect(Buffer.from(derOid("2.5.4.3")).toString("hex")).toBe("0603550403");
        expect(() => derOid("3.1")).toThrow();
        expect(() => derOid("1.40")).toThrow();
        expect(() => derOid("1")).toThrow();
        expect(() => derOid("1.a")).toThrow();
    });
});

describe("certificate helpers", () => {
    it("locates serial, issuer, subject and SPKI without re-encoding, and computes RFC 5280 key identifiers", async () => {
        const h = await makeHierarchy("ecdsa-p256");
        const parts = certificateParts(h.issuerCert.der);
        expect(Buffer.from(parts.spki).equals(Buffer.from(h.issuerSigner.spki))).toBe(true);
        expect(Buffer.from(parts.issuer).equals(Buffer.from(h.rootIssuer.subjectDer))).toBe(true);
        expect(Buffer.from(parts.subject).equals(Buffer.from(h.issuer.subjectDer))).toBe(true);
        expect(serialBytesToHex(parts.serial)).toBe(h.issuerCert.serialHex);
        // For an uncompressed P-256 point the BIT STRING content is the last 65 octets of the SPKI.
        expect(Buffer.from(spkiKeyBits(h.issuerSigner.spki)).equals(Buffer.from(h.issuerSigner.spki.slice(-65)))).toBe(true);
        const expected = crypto.createHash("sha1").update(h.issuerSigner.spki.slice(-65)).digest();
        expect(Buffer.from(keyIdentifierOf(h.issuerSigner.spki)).equals(expected)).toBe(true);
        expect(Buffer.from(h.issuer.keyId).equals(expected)).toBe(true);
    });

    it("rejects truncated and non-certificate input", () => {
        expect(() => readTlv(Uint8Array.of(0x30), 0)).toThrow();
        expect(() => readTlv(Uint8Array.of(0x30, 0x05, 0x01), 0)).toThrow(/Truncated/);
        expect(() => certificateParts(derSequence(derInteger(1n)))).toThrow();
        expect(() => spkiKeyBits(Uint8Array.of(0x30, 0x00))).toThrow();
        const { spki } = newSubjectKey("ec");
        expect(() => certificateParts(spki)).toThrow();
    });
});
