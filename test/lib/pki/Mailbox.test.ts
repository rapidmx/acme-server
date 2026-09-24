///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Internationalized mailboxes (RFC 6531 / RFC 8398 / RFC 8399): the canonical forms, and what goes into a certificate.
import "reflect-metadata";
import { AsnConvert } from "@peculiar/asn1-schema";
import { Certificate, SubjectAlternativeName } from "@peculiar/asn1-x509";
import {
    canonicalMailbox,
    derUtf8String,
    issueLeafCertificate,
    pemToDer,
    readDerUtf8String,
    SMTP_UTF8_MAILBOX_OID,
} from "../../../src/lib/pki/index.js";
import { DAY, HOUR, hasOpenssl, makeHierarchy, newSubjectKey, openssl, put, rmSync, tempDir, URLS, type Hierarchy } from "./helpers.js";

describe("canonicalMailbox", () => {
    it("classifies an ASCII local part as rfc822 and keeps everything else as given", () => {
        expect(canonicalMailbox("Jane.Doe+tag@Mail.Example.COM")).toEqual({
            form: "rfc822",
            local: "Jane.Doe+tag",
            asciiDomain: "mail.example.com",
            unicodeDomain: "mail.example.com",
            canonical: "Jane.Doe+tag@mail.example.com",
            certificateName: "Jane.Doe+tag@mail.example.com",
            key: "jane.doe+tag@mail.example.com",
        });
    });

    it("gives an ASCII local part at an IDN domain an rfc822Name with A-labels (RFC 8399 section 2)", () => {
        const mailbox = canonicalMailbox("user@bücher.example.com")!;
        expect(mailbox.form).toBe("rfc822");
        expect(mailbox.certificateName).toBe("user@xn--bcher-kva.example.com");
        expect(canonicalMailbox("user@xn--bcher-kva.example.com")).toEqual(mailbox);
    });

    it("gives a non-ASCII local part an SmtpUTF8Mailbox with U-labels (RFC 8398 section 3)", () => {
        const mailbox = canonicalMailbox("用户@xn--fsqu00a.example.com")!;
        expect(mailbox.form).toBe("smtputf8");
        expect(mailbox.canonical).toBe("用户@xn--fsqu00a.example.com");
        expect(mailbox.certificateName).toBe("用户@例子.example.com");
        expect(canonicalMailbox("用户@例子.example.com")).toEqual(mailbox);
    });

    it("accepts the whole range of letters, marks and symbols, and every atext character", () => {
        for (const local of ["ålice", "Ünal", "алиса", "アリス", "ali.çe+tag", "a!#$%&'*+/=?^_`{|}~-é", "é".normalize("NFC")]) {
            expect(canonicalMailbox(`${local}@example.com`), local).toBeDefined();
        }
    });

    it("keys the mailbox case-insensitively, NFC, at the A-label domain", () => {
        expect(canonicalMailbox("ÜSER@Bücher.Example.com")!.key).toBe(canonicalMailbox("üser@xn--bcher-kva.example.com")!.key);
    });

    it("refuses what is not a plain, canonical dot-atom mailbox", () => {
        const bad = [
            "ålice@example.com", // decomposed (NFD) local part
            "al\u0007ice@example.com", // control
            "al​ice@example.com", // zero-width space (format)
            "al‮ice@example.com", // bidi override
            "al ice@example.com", // no-break space (separator)
            "al ice@example.com",
            "alice@example.com", // private use
            "al͸ice@example.com", // unassigned
            "ålice@ｅxample.com", // full-width letter: a compatibility mapping, not a lossless IDNA conversion
            "ålice@EXAMPLE.com.", // trailing dot
            "ålice@.example.com",
            "ålice@exa..mple.com",
            "ålice@xn--a.example.com", // Punycode that does not decode
            "ålice@example",
            "ålice@example.123",
            ".ålice@example.com",
            "ålice.@example.com",
            "ål..ice@example.com",
            `${"é".repeat(33)}@example.com`, // 66 octets
            "a@b@example.com",
            "@example.com",
            "ålice@",
            '"å lice"@example.com',
            "<ålice@example.com>",
            "ålice@ex_ample.com",
            "ålice@-example.com",
            "",
            "x",
        ];
        for (const value of bad) {
            expect(canonicalMailbox(value), JSON.stringify(value)).toBeUndefined();
        }
        for (const value of [undefined, null, 5, {}, [], true]) {
            expect(canonicalMailbox(value)).toBeUndefined();
        }
    });

    it("allows a 64-octet local part and refuses 65", () => {
        expect(canonicalMailbox(`${"é".repeat(32)}@example.com`)).toBeDefined();
        expect(canonicalMailbox(`${"é".repeat(31)}ab@example.com`)).toBeDefined();
        expect(canonicalMailbox(`${"é".repeat(32)}a@example.com`)).toBeUndefined();
    });
});

describe("UTF8String DER helpers", () => {
    it("round-trips short, one-byte-length and two-byte-length values", () => {
        for (const text of ["a@example.com", "é".repeat(100), "用".repeat(120)]) {
            const der = derUtf8String(text);
            expect(der[0]).toBe(0x0c);
            expect(readDerUtf8String(der)).toBe(text);
        }
        expect(Array.from(derUtf8String("ab"))).toEqual([0x0c, 2, 0x61, 0x62]);
    });

    it("refuses anything that is not exactly one UTF8String", () => {
        expect(readDerUtf8String(new Uint8Array())).toBeUndefined();
        expect(readDerUtf8String(Uint8Array.of(0x16, 1, 0x61))).toBeUndefined(); // IA5String
        expect(readDerUtf8String(Uint8Array.of(0x0c, 5, 0x61))).toBeUndefined(); // truncated
        expect(readDerUtf8String(Uint8Array.of(0x0c, 1, 0x61, 0x62))).toBeUndefined(); // trailing byte
        expect(readDerUtf8String(Uint8Array.of(0x0c, 1, 0xff))).toBeUndefined(); // invalid UTF-8
        expect(readDerUtf8String(Uint8Array.of(0x0c, 0x81, 0x01, 0x61))).toBeUndefined(); // non-minimal length
        expect(readDerUtf8String(Uint8Array.of(0x0c, 0x83, 0, 0, 1, 0x61))).toBeUndefined(); // over-long length form
    });
});

describe("issuing certificates for internationalized mailboxes", () => {
    let ca: Hierarchy;
    beforeAll(async () => {
        ca = await makeHierarchy("ecdsa-p384");
    });

    const issue = async (email: string) => {
        const key = newSubjectKey("ec");
        return await issueLeafCertificate(ca.issuer, URLS, {
            spki: key.spki,
            email,
            type: "signing",
            notBefore: new Date(Date.now() - HOUR),
            notAfter: new Date(Date.now() + 90 * DAY),
        });
    };

    const sanOf = (der: Uint8Array) => {
        const certificate = AsnConvert.parse(der, Certificate);
        const extension = certificate.tbsCertificate.extensions!.find((e) => e.extnID === "2.5.29.17")!;
        return { extension, names: AsnConvert.parse(extension.extnValue.buffer, SubjectAlternativeName) };
    };

    const subjectCn = (der: Uint8Array): string | undefined => {
        const certificate = AsnConvert.parse(der, Certificate);
        const value = certificate.tbsCertificate.subject[0]?.[0]?.value;
        return value?.utf8String ?? value?.printableString ?? value?.ia5String;
    };

    it("puts a non-ASCII local part in an SmtpUTF8Mailbox otherName with the domain as U-labels, and the same in the CN", async () => {
        const issued = await issue("用户@xn--fsqu00a.example.com");
        const { names } = sanOf(issued.der);
        expect(names).toHaveLength(1);
        expect(names[0].rfc822Name).toBeUndefined();
        expect(names[0].otherName?.typeId).toBe(SMTP_UTF8_MAILBOX_OID);
        expect(readDerUtf8String(new Uint8Array(names[0].otherName!.value))).toBe("用户@例子.example.com");
        expect(subjectCn(issued.der)).toBe("用户@例子.example.com");
    });

    it("puts an ASCII local part at an IDN domain in an rfc822Name with A-labels", async () => {
        const issued = await issue("user@bücher.example.com");
        const { names } = sanOf(issued.der);
        expect(names[0].otherName).toBeUndefined();
        expect(names[0].rfc822Name).toBe("user@xn--bcher-kva.example.com");
        expect(subjectCn(issued.der)).toBe("user@xn--bcher-kva.example.com");
    });

    it("keeps a plain ASCII mailbox as before", async () => {
        const { names } = sanOf((await issue("alice@example.com")).der);
        expect(names[0].rfc822Name).toBe("alice@example.com");
    });

    it("leaves the subject empty and makes the SAN critical when the internationalized name is over 64 octets", async () => {
        const issued = await issue(`${"é".repeat(30)}@xn--fsqu00a.example.com`);
        const { extension } = sanOf(issued.der);
        expect(extension.critical).toBe(true);
        expect(subjectCn(issued.der)).toBeUndefined();
    });

    it("refuses a mailbox that is not canonical", async () => {
        await expect(issue("ålice@example.com")).rejects.toThrow(/not acceptable/);
    });

    it.skipIf(!hasOpenssl)("is read by OpenSSL as an SmtpUTF8Mailbox", async () => {
        const issued = await issue("用户@例子.example.com");
        const dir = tempDir();
        try {
            const file = put(dir, "leaf.pem", issued.pem);
            const result = openssl(["x509", "-in", file, "-noout", "-ext", "subjectAltName"]);
            expect(result?.status).toBe(0);
            expect(result?.stdout).toMatch(/othername:\s*(SmtpUTF8Mailbox|1\.3\.6\.1\.5\.5\.7\.8\.9)/i);
            expect(pemToDer(issued.pem).length).toBeGreaterThan(200);
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });
});
