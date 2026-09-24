///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import "reflect-metadata";
import * as x509 from "@peculiar/x509";
import { AsnConvert } from "@peculiar/asn1-schema";
import { Certificate } from "@peculiar/asn1-x509";
import { ariCertId, b64url, issueLeafCertificate, parseAriCertId } from "../../../src/lib/pki/index.js";
import {
    DAY,
    HOUR,
    URLS,
    makeHierarchy,
    newSubjectKey,
    type Hierarchy,
} from "./helpers.js";

x509.cryptoProvider.set(globalThis.crypto);

const bytes = (hex: string) => new Uint8Array(Buffer.from(hex, "hex"));

describe("ARI certificate identifiers (RFC 9773)", () => {
    let h: Hierarchy;
    beforeAll(async () => {
        h = await makeHierarchy("ecdsa-p256");
    });

    async function issue() {
        return issueLeafCertificate(h.issuer, URLS, {
            spki: newSubjectKey("ec").spki,
            email: "ari@example.com",
            type: "signing",
            notBefore: new Date(Date.now() - HOUR),
            notAfter: new Date(Date.now() + 30 * DAY),
        });
    }

    it("is base64url(AKI keyIdentifier) '.' base64url(serial INTEGER content), both unpadded", async () => {
        const issued = await issue();
        const id = ariCertId(new x509.X509Certificate(issued.pem));
        const [aki, serial] = id.split(".");
        expect(id.split(".")).toHaveLength(2);
        expect(id).not.toMatch(/[=+/]/);
        expect(aki).toBe(b64url(h.issuer.keyId));
        // the serial is 20 octets with no sign octet, so the INTEGER content is exactly the serial
        expect(Buffer.from(serial, "base64url").toString("hex")).toBe(issued.serialHex);
    });

    it("round trips through parseAriCertId", async () => {
        const issued = await issue();
        const parsed = parseAriCertId(ariCertId(new x509.X509Certificate(issued.pem)))!;
        expect(parsed).toBeDefined();
        expect(Buffer.from(parsed.authorityKeyId).equals(Buffer.from(h.issuer.keyId))).toBe(true);
        expect(parsed.serialHex).toBe(issued.serialHex);
    });

    it("keeps the DER sign octet in the identifier for a certificate whose serial has the top bit set", async () => {
        // A certificate from another CA (the library never issues one): serial ff0102030405060708090a0b0c0d0e0f10111213
        const serial = "ff0102030405060708090a0b0c0d0e0f10111213";
        const key = await globalThis.crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
        const cert = await x509.X509CertificateGenerator.createSelfSigned({
            serialNumber: serial,
            name: "CN=Foreign CA",
            notBefore: new Date(Date.now() - HOUR),
            notAfter: new Date(Date.now() + DAY),
            signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
            keys: key,
            extensions: [new x509.AuthorityKeyIdentifierExtension("0102030405060708090a0b0c0d0e0f1011121314")],
        });
        const content = new Uint8Array(AsnConvert.parse(new Uint8Array(cert.rawData), Certificate).tbsCertificate.serialNumber);
        expect(Buffer.from(content).toString("hex")).toBe("00" + serial);
        const id = ariCertId(cert);
        expect(id).toBe(`${b64url(bytes("0102030405060708090a0b0c0d0e0f1011121314"))}.${b64url(bytes("00" + serial))}`);
        const parsed = parseAriCertId(id)!;
        expect(parsed.serialHex).toBe(serial); // canonical form drops the sign octet
    });

    it("refuses to compute an id for a certificate without an authorityKeyIdentifier", async () => {
        const key = await globalThis.crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
        const cert = await x509.X509CertificateGenerator.createSelfSigned({
            name: "CN=No AKI",
            notBefore: new Date(Date.now() - HOUR),
            notAfter: new Date(Date.now() + DAY),
            signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
            keys: key,
        });
        expect(() => ariCertId(cert)).toThrow(/authorityKeyIdentifier/);
    });

    describe("parseAriCertId", () => {
        const aki = b64url(bytes("aabbccdd"));
        const serial = b64url(bytes("0123456789"));

        it("parses well-formed identifiers", () => {
            expect(parseAriCertId(`${aki}.${serial}`)).toEqual({ authorityKeyId: bytes("aabbccdd"), serialHex: "0123456789" });
            // a sign octet followed by a byte with the top bit set is minimal DER
            expect(parseAriCertId(`${aki}.${b64url(bytes("00ff01"))}`)!.serialHex).toBe("ff01");
            expect(parseAriCertId(`${aki}.${b64url(bytes("7f"))}`)!.serialHex).toBe("7f");
        });

        it.each([
            ["a missing dot", () => "aabbccdd"],
            ["three segments", () => `${aki}.${serial}.${serial}`],
            ["an empty AKI", () => `.${serial}`],
            ["an empty serial", () => `${aki}.`],
            ["padding", () => `${aki}.${serial}==`],
            ["the standard base64 alphabet", () => `${aki}.+/8`],
            ["a non-canonical encoding (trailing bits)", () => `${aki}.AR`],
            ["whitespace", () => ` ${aki}.${serial}`],
            ["a percent-escaped dot", () => `${aki}%2E${serial}`],
            ["a redundant leading zero (not minimal DER)", () => `${aki}.${b64url(bytes("0001"))}`],
            ["a negative serial (top bit set, no sign octet)", () => `${aki}.${b64url(bytes("ff01"))}`],
            ["a zero serial", () => `${aki}.${b64url(bytes("00"))}`],
            ["a serial longer than 20 octets", () => `${aki}.${b64url(new Uint8Array(21).fill(1))}`],
            ["an AKI longer than 64 octets", () => `${b64url(new Uint8Array(65).fill(1))}.${serial}`],
            ["an over-long string", () => "A".repeat(300)],
        ])("rejects %s", (_name, make) => {
            expect(parseAriCertId(make())).toBeUndefined();
        });

        it("rejects non-strings", () => {
            expect(parseAriCertId(undefined as unknown as string)).toBeUndefined();
            expect(parseAriCertId(42 as unknown as string)).toBeUndefined();
        });
    });
});
