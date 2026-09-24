///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
/* eslint-disable id-denylist -- `number` is the contract's property name for the CRL number */
import "reflect-metadata";
import * as x509 from "@peculiar/x509";
import { AsnConvert } from "@peculiar/asn1-schema";
import { CertificateList } from "@peculiar/asn1-x509";
import * as crypto from "node:crypto";
import { MAX_CRL_VALIDITY_DAYS, buildCrl, issueLeafCertificate, pemToDer, verifySignature } from "../../../src/lib/pki/index.js";
import { readTlv } from "../../../src/lib/pki/certutil.js";
import {
    DAY,
    HOUR,
    URLS,
    hasOpenssl,
    makeHierarchy,
    newSubjectKey,
    openssl,
    put,
    rmSync,
    tempDir,
    type Hierarchy,
} from "./helpers.js";

x509.cryptoProvider.set(globalThis.crypto);

const T0 = new Date("2031-03-04T05:06:07.000Z");
const T1 = new Date(T0.getTime() + 7 * DAY);

/** The DER INTEGER value of the cRLNumber extension, decoded independently of the builder. */
function crlNumber(der: Uint8Array): bigint {
    const list = AsnConvert.parse(der, CertificateList);
    const extension = list.tbsCertList.crlExtensions!.find((e) => e.extnID === "2.5.29.20")!;
    const bytes = new Uint8Array(extension.extnValue.buffer);
    const tlv = readTlv(bytes, 0);
    expect(tlv.tag).toBe(0x02);
    return BigInt("0x" + Buffer.from(bytes.slice(tlv.contentStart, tlv.end)).toString("hex"));
}

describe("buildCrl", () => {
    let ec: Hierarchy;
    let rsa: Hierarchy;
    beforeAll(async () => {
        ec = await makeHierarchy("ecdsa-p384");
        rsa = await makeHierarchy("rsa-2048");
    });

    const entries = [
        { serialHex: "0123456789abcdef0123456789abcdef01234567", revokedAt: new Date("2031-03-01T00:00:01.900Z"), reason: 1 },
        { serialHex: "ff00ff", revokedAt: new Date("2031-03-02T00:00:00Z") }, // top bit set: DER needs a sign octet
        { serialHex: "7f", revokedAt: new Date("2031-03-03T10:00:00Z"), reason: 0 }, // unspecified: reason omitted
        { serialHex: "1000", revokedAt: new Date("2031-03-03T11:00:00Z"), reason: 5 },
        { serialHex: "2000", revokedAt: new Date("2031-03-03T12:00:00Z"), reason: 9 },
    ];

    it("builds a v2 CRL that @peculiar/x509 parses and whose signature verifies with the issuer key", async () => {
        const { der, pem } = await buildCrl(ec.issuer, { number: 42n, thisUpdate: T0, nextUpdate: T1, revoked: entries });
        expect(pem.startsWith("-----BEGIN X509 CRL-----\n")).toBe(true);
        expect(Buffer.from(pemToDer(pem)).equals(Buffer.from(der))).toBe(true);

        const crl = new x509.X509Crl(pem);
        expect(crl.issuer).toBe("CN=Test S/MIME CA");
        expect(crl.thisUpdate.toISOString()).toBe(T0.toISOString());
        expect(crl.nextUpdate!.toISOString()).toBe(T1.toISOString());
        expect(await crl.verify({ publicKey: new x509.X509Certificate(ec.issuerCert.pem).publicKey })).toBe(true);
        expect(await crl.verify({ publicKey: new x509.X509Certificate(ec.rootCert.pem).publicKey })).toBe(false);

        // signature over the exact TBS bytes, checked with Node's crypto and our own verifier
        const list = AsnConvert.parse(der, CertificateList);
        expect(list.tbsCertList.version).toBe(1);
        expect(list.signatureAlgorithm.isEqual(list.tbsCertList.signature)).toBe(true);
        const tbsBytes = new Uint8Array(list.tbsCertListRaw!);
        expect(verifySignature("ecdsa-with-SHA384", ec.issuerSigner.spki, tbsBytes, new Uint8Array(list.signature))).toBe(true);
        const pub = crypto.createPublicKey({ key: Buffer.from(ec.issuerSigner.spki), format: "der", type: "spki" });
        expect(crypto.verify("sha384", tbsBytes, { key: pub, dsaEncoding: "der" }, new Uint8Array(list.signature))).toBe(true);
    });

    it("carries the entries with their revocation times and reasons, sorted by time (unspecified reason omitted)", async () => {
        const { pem } = await buildCrl(ec.issuer, { number: 1n, thisUpdate: T0, nextUpdate: T1, revoked: [...entries].reverse() });
        const crl = new x509.X509Crl(pem);
        expect(crl.entries.map((e) => e.serialNumber.toLowerCase())).toEqual([
            "0123456789abcdef0123456789abcdef01234567",
            "ff00ff",
            "7f",
            "1000",
            "2000",
        ].map((s) => s.toLowerCase()));
        expect(crl.entries.map((e) => e.revocationDate.toISOString())).toEqual([
            "2031-03-01T00:00:01.000Z", // sub-second part is dropped
            "2031-03-02T00:00:00.000Z",
            "2031-03-03T10:00:00.000Z",
            "2031-03-03T11:00:00.000Z",
            "2031-03-03T12:00:00.000Z",
        ]);
        expect(crl.entries.map((e) => e.reason)).toEqual([1, undefined, undefined, 5, 9]);
        expect(crl.entries[1].extensions).toHaveLength(0);
        expect(crl.entries.every((e) => e.extensions.every((x) => !x.critical))).toBe(true);

        // the sign octet of ff00ff is present in the DER, so the INTEGER is positive
        const list = AsnConvert.parse(pemToDer(pem), CertificateList);
        const second = list.tbsCertList.revokedCertificates![1];
        expect(Buffer.from(second.userCertificate).toString("hex")).toBe("00ff00ff");
    });

    it("includes the authorityKeyIdentifier and a cRLNumber extension", async () => {
        const { der, pem } = await buildCrl(ec.issuer, { number: (1n << 158n) + 5n, thisUpdate: T0, nextUpdate: T1, revoked: [] });
        const crl = new x509.X509Crl(pem);
        const aki = crl.extensions.find((e) => e.type === "2.5.29.35") as x509.AuthorityKeyIdentifierExtension;
        expect(aki.keyId).toBe(Buffer.from(ec.issuer.keyId).toString("hex"));
        expect(crl.extensions.map((e) => e.type).sort()).toEqual(["2.5.29.20", "2.5.29.35"]);
        expect(crl.extensions.every((e) => !e.critical)).toBe(true);
        expect(crlNumber(der)).toBe((1n << 158n) + 5n);
        expect((await buildCrl(ec.issuer, { number: 0n, thisUpdate: T0, nextUpdate: T1, revoked: [] })).der.length).toBeGreaterThan(0);
        expect(crlNumber((await buildCrl(ec.issuer, { number: 128n, thisUpdate: T0, nextUpdate: T1, revoked: [] })).der)).toBe(128n);
    });

    it("omits revokedCertificates entirely when nothing is revoked (RFC 5280 s5.1.2.6)", async () => {
        const { der } = await buildCrl(ec.issuer, { number: 1n, thisUpdate: T0, nextUpdate: T1, revoked: [] });
        expect(AsnConvert.parse(der, CertificateList).tbsCertList.revokedCertificates).toBeUndefined();
        expect(new x509.X509Crl(Buffer.from(der)).entries).toHaveLength(0);
    });

    it("produces identical bytes for identical input up to the signature (deterministic ordering)", async () => {
        const a = AsnConvert.parse((await buildCrl(rsa.issuer, { number: 3n, thisUpdate: T0, nextUpdate: T1, revoked: entries })).der, CertificateList);
        const b = AsnConvert.parse((await buildCrl(rsa.issuer, { number: 3n, thisUpdate: T0, nextUpdate: T1, revoked: [...entries].reverse() })).der, CertificateList);
        expect(Buffer.from(a.tbsCertListRaw!).equals(Buffer.from(b.tbsCertListRaw!))).toBe(true);
    });

    it("signs with RSA issuers (sha256WithRSAEncryption) and handles a large list", async () => {
        const many = Array.from({ length: 1000 }, (_v, i) => ({
            serialHex: (0x100000 + i).toString(16).padStart(40, "0"),
            revokedAt: new Date(T0.getTime() - (i + 1) * 1000),
            reason: i % 2 ? 4 : 1,
        }));
        const { pem } = await buildCrl(rsa.issuer, { number: 9n, thisUpdate: T0, nextUpdate: T1, revoked: many });
        const crl = new x509.X509Crl(pem);
        expect(crl.entries).toHaveLength(1000);
        expect(crl.signatureAlgorithm.name).toBe("RSASSA-PKCS1-v1_5");
        expect(await crl.verify({ publicKey: new x509.X509Certificate(rsa.issuerCert.pem).publicKey })).toBe(true);
    });

    it("lists a real issued certificate by its serial", async () => {
        const subject = newSubjectKey("ec");
        const leaf = await issueLeafCertificate(ec.issuer, URLS, {
            spki: subject.spki,
            email: "revoked@example.com",
            type: "signing",
            notBefore: new Date(Date.now() - HOUR),
            notAfter: new Date(Date.now() + DAY),
        });
        const { pem } = await buildCrl(ec.issuer, { number: 1n, thisUpdate: T0, nextUpdate: T1, revoked: [{ serialHex: leaf.serialHex, revokedAt: T0, reason: 1 }] });
        const crl = new x509.X509Crl(pem);
        const revoked = crl.findRevoked(new x509.X509Certificate(leaf.pem));
        expect(revoked).not.toBeNull();
        expect(revoked!.reason).toBe(1);
    });

    it.skipIf(!hasOpenssl)("is accepted by `openssl crl -verify` (EC and RSA issuers) and shows the reasons", async () => {
        const dir = tempDir();
        try {
            for (const h of [ec, rsa]) {
                const { pem } = await buildCrl(h.issuer, { number: 7n, thisUpdate: T0, nextUpdate: T1, revoked: entries });
                const crlFile = put(dir, "test.crl", pem);
                const ca = put(dir, "ca.pem", h.issuerCert.pem);
                const verify = openssl(["crl", "-in", crlFile, "-noout", "-CAfile", ca])!;
                expect(verify.status).toBe(0);
                expect(verify.stdout + verify.stderr).toMatch(/verify OK/);
                const text = openssl(["crl", "-in", crlFile, "-noout", "-text"])!.stdout;
                expect(text).toMatch(/Version 2 \(0x1\)/);
                expect(text).toMatch(/X509v3 CRL Number:\s+7/);
                expect(text).toMatch(/Key Compromise/);
                expect(text).toMatch(/Cessation Of Operation/);
                expect(text).toMatch(/Privilege Withdrawn/);
                expect(text).toMatch(/Serial Number: FF00FF/);
                // wrong CA must not verify
                const other = put(dir, "other.pem", h.rootCert.pem);
                expect(openssl(["crl", "-in", crlFile, "-noout", "-CAfile", other])!.status).not.toBe(0);
            }
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    describe("validation", () => {
        const ok = { number: 1n, thisUpdate: T0, nextUpdate: T1, revoked: [] as typeof entries };

        it.each([
            ["a negative CRL number", { number: -1n }, /CRL number/],
            ["a CRL number of 2^159", { number: 1n << 159n }, /CRL number/],
            ["a non-bigint CRL number", { number: 1 as unknown as bigint }, /CRL number/],
            ["nextUpdate equal to thisUpdate", { nextUpdate: T0 }, /after thisUpdate/],
            ["nextUpdate before thisUpdate", { nextUpdate: new Date(T0.getTime() - 1000) }, /after thisUpdate/],
            ["a nextUpdate more than 10 days out", { nextUpdate: new Date(T0.getTime() + (MAX_CRL_VALIDITY_DAYS + 1) * DAY) }, /at most 10 days/],
            ["invalid dates", { thisUpdate: new Date(NaN) }, /dates/],
            ["a duplicate serial", { revoked: [{ serialHex: "01", revokedAt: T0 }, { serialHex: "0001", revokedAt: T0 }] }, /Duplicate serial/],
            ["an invalid serial", { revoked: [{ serialHex: "xyz", revokedAt: T0 }] }, /serial/],
            ["a zero serial", { revoked: [{ serialHex: "00", revokedAt: T0 }] }, /serial/],
            ["reason 7 (unused)", { revoked: [{ serialHex: "01", revokedAt: T0, reason: 7 }] }, /reason/],
            ["reason 8 (removeFromCRL, delta CRLs only)", { revoked: [{ serialHex: "01", revokedAt: T0, reason: 8 }] }, /reason/],
            ["reason 11", { revoked: [{ serialHex: "01", revokedAt: T0, reason: 11 }] }, /reason/],
            ["a negative reason", { revoked: [{ serialHex: "01", revokedAt: T0, reason: -1 }] }, /reason/],
            ["an invalid revocation time", { revoked: [{ serialHex: "01", revokedAt: new Date(NaN) }] }, /revocation time/],
        ])("rejects %s", async (_name, patch, message) => {
            await expect(buildCrl(ec.issuer, { ...ok, ...patch })).rejects.toThrow(message);
        });

        it("accepts the maximum 10-day validity", async () => {
            await expect(
                buildCrl(ec.issuer, { ...ok, nextUpdate: new Date(T0.getTime() + MAX_CRL_VALIDITY_DAYS * DAY) })
            ).resolves.toBeDefined();
        });
    });
});
