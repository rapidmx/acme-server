///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { AcmeProblem } from "../../../src/lib/acme/AcmeProblem.js";
import { parseEmailIdentifier, sameAddress } from "../../../src/lib/acme/Identifiers.js";

const typeOf = (value: unknown): string | undefined => {
    try {
        parseEmailIdentifier(value);
        return undefined;
    } catch (err) {
        return err instanceof AcmeProblem ? err.errorType : "not-a-problem";
    }
};

describe("parseEmailIdentifier", () => {
    it("normalizes the domain to lower case and keeps the local part as given", () => {
        expect(parseEmailIdentifier("Jane.Doe+tag@Mail.EXAMPLE.com")).toEqual({
            address: "Jane.Doe+tag@mail.example.com",
            local: "Jane.Doe+tag",
            domain: "mail.example.com",
            normalized: "jane.doe+tag@mail.example.com",
            unicodeDomain: "mail.example.com",
            smtpUtf8: false,
        });
    });

    it("accepts every RFC 5322 atext character in the local part, and punycode domains", () => {
        for (const value of ["a!#$%&'*+/=?^_`{|}~-z@example.com", "x@xn--bcher-kva.example.com", "a@b.co", "a.b.c@d-e.example.org", `${"a".repeat(64)}@example.com`]) {
            expect(typeOf(value), value).toBeUndefined();
        }
    });

    it("rejects what is not a plain address", () => {
        for (const value of ["", "plain", "@example.com", "a@", "a@@example.com", "a@b@example.com", "a b@example.com", "a@example.com ", " a@example.com", ".a@example.com", "a.@example.com", "a..b@example.com", '"a b"@example.com', "a(comment)@example.com", "a,b@example.com", "a;b@example.com", "a\\@example.com", "<a@example.com>", "a@example", "a@.example.com", "a@example..com", "a@-example.com", "a@example-.com", "a@ex ample.com", "a@ex_ample.com", "a@[::1]", `${"a".repeat(65)}@example.com`, `a@${"b".repeat(64)}.com`, `a@${("b".repeat(50) + ".").repeat(6)}com`]) {
            expect(typeOf(value), JSON.stringify(value)).toBe("malformed");
        }
    });

    it("rejects non-strings", () => {
        for (const value of [undefined, null, 5, {}, [], true]) {
            expect(typeOf(value)).toBe("malformed");
        }
    });

    it("accepts internationalized addresses (RFC 6531) and stores them with an A-label domain", () => {
        expect(parseEmailIdentifier("üser@Bücher.Example.com")).toEqual({
            address: "üser@xn--bcher-kva.example.com",
            local: "üser",
            domain: "xn--bcher-kva.example.com",
            unicodeDomain: "bücher.example.com",
            normalized: "üser@xn--bcher-kva.example.com",
            smtpUtf8: true,
        });
        // An ASCII local part at an IDN domain needs no SmtpUTF8Mailbox: it is an rfc822Name with A-labels.
        expect(parseEmailIdentifier("user@bücher.example.com")).toMatchObject({ address: "user@xn--bcher-kva.example.com", smtpUtf8: false });
        // The two spellings of a domain are the same identifier.
        expect(parseEmailIdentifier("用户@xn--fsqu00a.example.com").address).toBe(parseEmailIdentifier("用户@例子.example.com").address);
    });

    it("compares the local part case-insensitively for non-ASCII letters too", () => {
        expect(parseEmailIdentifier("ÜSER@example.com").normalized).toBe(parseEmailIdentifier("üser@example.com").normalized);
    });

    it("rejects internationalized addresses that are not canonical", () => {
        for (const value of ["åalice@example.com", "al​ice@example.com", "alice@example.com", "al ice@example.com", "üser@ｅxample.com", "üser@xn--a.example.com", `${"é".repeat(33)}@example.com`]) {
            expect(typeOf(value), JSON.stringify(value)).toBe("malformed");
        }
    });

    it("rejects reserved top-level domains in either spelling of an IDN", () => {
        expect(typeOf("üser@host.test")).toBe("rejectedIdentifier");
    });

    it("rejects reserved top-level domains, IP addresses and length overflows", () => {
        for (const value of ["a@host.test", "a@host.example", "a@host.invalid", "a@host.localhost", "a@corp.local", "a@x.internal", "a@abc.onion", "a@1.0.0.127.in-addr.arpa", "a@192.0.2.1", "a@1.2.3.4"]) {
            expect(typeOf(value), value).toBe("rejectedIdentifier");
        }
        expect(typeOf(`a@${"b.".repeat(130)}com`)).toBe("malformed");
    });

    it("honours a custom list of forbidden top-level domains", () => {
        expect(() => parseEmailIdentifier("a@mail.corp", ["corp"])).toThrow(AcmeProblem);
        expect(parseEmailIdentifier("a@mail.local", []).domain).toBe("mail.local");
    });
});

describe("sameAddress", () => {
    it("compares whole addresses case-insensitively and ignores surrounding whitespace", () => {
        expect(sameAddress("A@Example.COM", "a@example.com")).toBe(true);
        expect(sameAddress("Üser@Bücher.example.com", "üser@xn--bcher-kva.example.com")).toBe(true);
        expect(sameAddress("åser@example.com", "åser@example.com")).toBe(false);
        expect(sameAddress(" a@example.com", "a@example.com ")).toBe(true);
        expect(sameAddress("a@example.com", "b@example.com")).toBe(false);
        expect(sameAddress("a@example.com", "a@example.org")).toBe(false);
    });
});
