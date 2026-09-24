///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import "reflect-metadata";
import * as x509 from "@peculiar/x509";
import { AsnConvert } from "@peculiar/asn1-schema";
import { Certificate } from "@peculiar/asn1-x509";
import * as crypto from "node:crypto";
import {
    MAX_LEAF_VALIDITY_DAYS,
    PkiPolicyError,
    buildCaCertificate,
    issueLeafCertificate,
    keyUsageFor,
    parseDistinguishedName,
    pemToDer,
    randomSerial,
    sha256Hex,
    type CertificateType,
} from "../../../src/lib/pki/index.js";
import {
    DAY,
    HOUR,
    URLS,
    hasOpenssl,
    makeHierarchy,
    newSubjectKey,
    newSigner,
    openssl,
    put,
    rmSync,
    spkiOf,
    tempDir,
    type Hierarchy,
} from "./helpers.js";

x509.cryptoProvider.set(globalThis.crypto);

const nodeKey = (spki: Uint8Array) => crypto.createPublicKey({ key: Buffer.from(spki), format: "der", type: "spki" });
const ext = (c: x509.X509Certificate, oid: string) => c.getExtension(oid) as x509.Extension;

describe("keyUsageFor", () => {
    it("follows the profile table for every type and key kind", () => {
        expect(keyUsageFor("signing", "rsa")).toEqual(["digitalSignature", "nonRepudiation"]);
        expect(keyUsageFor("signing", "ec")).toEqual(["digitalSignature", "nonRepudiation"]);
        expect(keyUsageFor("encryption", "rsa")).toEqual(["keyEncipherment"]);
        expect(keyUsageFor("encryption", "ec")).toEqual(["keyAgreement"]);
        expect(keyUsageFor("signing-encryption", "rsa")).toEqual(["digitalSignature", "nonRepudiation", "keyEncipherment"]);
        expect(keyUsageFor("signing-encryption", "ec")).toEqual(["digitalSignature", "nonRepudiation", "keyAgreement"]);
    });

    it("rejects unknown inputs", () => {
        expect(() => keyUsageFor("code-signing" as CertificateType, "rsa")).toThrow();
        expect(() => keyUsageFor("signing", "dsa" as "rsa")).toThrow();
    });
});

describe("issueLeafCertificate", () => {
    let ec: Hierarchy;
    let rsaCa: Hierarchy;

    beforeAll(async () => {
        ec = await makeHierarchy("ecdsa-p384");
        rsaCa = await makeHierarchy("rsa-2048");
    });

    const flagsFor = (names: string[]) =>
        names.reduce((acc, n) => acc | (x509.KeyUsageFlags as unknown as Record<string, number>)[n], 0);

    const matrix: Array<[CertificateType, "rsa" | "ec"]> = [];
    for (const type of ["signing", "encryption", "signing-encryption"] as CertificateType[]) {
        for (const kind of ["rsa", "ec"] as const) {
            matrix.push([type, kind]);
        }
    }

    it.each(matrix)("issues a %s certificate for an %s key with the documented profile", async (type, kind) => {
        const subject = newSubjectKey(kind);
        const notBefore = new Date(Date.now() - HOUR);
        const notAfter = new Date(Date.now() + 90 * DAY);
        const issued = await issueLeafCertificate(ec.issuer, URLS, {
            spki: subject.spki,
            email: "Alice@Example.COM",
            type,
            notBefore,
            notAfter,
        });

        // --- Node's own X.509 implementation agrees the certificate is valid and issued by the CA
        const node = new crypto.X509Certificate(Buffer.from(issued.der));
        const issuerNode = new crypto.X509Certificate(Buffer.from(ec.issuerCert.der));
        expect(node.verify(nodeKey(ec.issuerSigner.spki))).toBe(true);
        expect(node.checkIssued(issuerNode)).toBe(true);
        expect(node.checkEmail("Alice@example.com")).toBe("Alice@example.com");
        expect(node.checkEmail("bob@example.com")).toBeUndefined();
        expect(node.ca).toBe(false);
        expect(node.keyUsage).toEqual(["1.3.6.1.5.5.7.3.4"]);
        expect(node.subject).toBe("CN=Alice@example.com");
        expect(node.issuer).toBe("CN=Test S/MIME CA");
        expect(issuerNode.verify(nodeKey(ec.rootSigner.spki))).toBe(true);
        expect(node.publicKey.export({ type: "spki", format: "der" }).equals(Buffer.from(subject.spki))).toBe(true);

        // --- @peculiar/x509 parses it and the content matches the profile
        const cert = new x509.X509Certificate(issued.pem);
        expect(AsnConvert.parse(issued.der, Certificate).tbsCertificate.version).toBe(2); // v3
        expect(cert.subject).toBe("CN=Alice@example.com");
        expect(cert.issuer).toBe("CN=Test S/MIME CA");
        expect(cert.signatureAlgorithm.name).toBe("ECDSA");
        expect(cert.signatureAlgorithm.hash.name).toBe("SHA-384");
        expect(cert.notBefore.getTime()).toBe(Math.floor(notBefore.getTime() / 1000) * 1000);
        expect(cert.notAfter.getTime()).toBe(Math.floor(notAfter.getTime() / 1000) * 1000);
        expect(issued.notBefore.getTime()).toBe(cert.notBefore.getTime());
        expect(issued.notAfter.getTime()).toBe(cert.notAfter.getTime());
        expect(cert.extensions.map((e) => e.type).sort()).toEqual(
            ["2.5.29.19", "2.5.29.15", "2.5.29.37", "2.5.29.17", "2.5.29.14", "2.5.29.35", "2.5.29.31", "1.3.6.1.5.5.7.1.1"].sort()
        );

        const bc = ext(cert, "2.5.29.19") as x509.BasicConstraintsExtension;
        expect(bc.critical).toBe(true);
        expect(bc.ca).toBe(false);
        expect(bc.pathLength).toBeUndefined();

        const ku = ext(cert, "2.5.29.15") as x509.KeyUsagesExtension;
        expect(ku.critical).toBe(true);
        expect(ku.usages).toBe(flagsFor(keyUsageFor(type, kind)));

        const eku = ext(cert, "2.5.29.37") as x509.ExtendedKeyUsageExtension;
        expect(eku.critical).toBe(false);
        expect(eku.usages).toEqual(["1.3.6.1.5.5.7.3.4"]);

        const san = ext(cert, "2.5.29.17") as x509.SubjectAlternativeNameExtension;
        expect(san.critical).toBe(false);
        expect(san.names.items.map((n) => [n.type, n.value])).toEqual([["email", "Alice@example.com"]]);

        const ski = ext(cert, "2.5.29.14") as x509.SubjectKeyIdentifierExtension;
        // The key identifier is the SHA-1 of the subjectPublicKey BIT STRING content: the EC point (last 65 octets of
        // the SPKI) or the DER RSAPublicKey (last 270 octets of a 2048-bit key SPKI).
        const bits = subject.spki.slice(subject.spki.length - (kind === "ec" ? 65 : 270));
        expect(ski.keyId).toBe(crypto.createHash("sha1").update(bits).digest("hex"));
        const aki = ext(cert, "2.5.29.35") as x509.AuthorityKeyIdentifierExtension;
        expect(aki.keyId).toBe(Buffer.from(ec.issuer.keyId).toString("hex"));

        const crldp = ext(cert, "2.5.29.31") as x509.CRLDistributionPointsExtension;
        expect(crldp.distributionPoints).toHaveLength(1);
        expect(crldp.distributionPoints[0].distributionPoint?.fullName?.map((n) => n.uniformResourceIdentifier)).toEqual([URLS.crl]);
        const aia = ext(cert, "1.3.6.1.5.5.7.1.1") as x509.AuthorityInfoAccessExtension;
        expect(aia.caIssuers.map((n) => n.value)).toEqual([URLS.caIssuers]);
        expect(aia.ocsp.map((n) => n.value)).toEqual([URLS.ocsp]);

        // --- Serial and reported fields
        const serial = AsnConvert.parse(issued.der, Certificate).tbsCertificate.serialNumber;
        expect(serial.byteLength).toBe(20);
        expect(new Uint8Array(serial)[0] & 0x80).toBe(0);
        expect(issued.serialHex).toMatch(/^[0-9a-f]{40}$/);
        expect(issued.serialHex).toBe(node.serialNumber.toLowerCase());
        expect(issued.sha256Fingerprint).toBe(sha256Hex(issued.der));
        expect(issued.sha256Fingerprint).toBe(node.fingerprint256.replace(/:/g, "").toLowerCase());
        expect(issued.pem.startsWith("-----BEGIN CERTIFICATE-----\n")).toBe(true);
        expect(Buffer.from(pemToDer(issued.pem)).equals(Buffer.from(issued.der))).toBe(true);
    });

    it("signs with the issuer's key algorithm: RSA issuers produce sha256WithRSAEncryption certificates", async () => {
        const subject = newSubjectKey("ec");
        const issued = await issueLeafCertificate(rsaCa.issuer, URLS, {
            spki: subject.spki,
            email: "carol@example.org",
            type: "signing",
            notBefore: new Date(Date.now() - HOUR),
            notAfter: new Date(Date.now() + 30 * DAY),
        });
        const node = new crypto.X509Certificate(Buffer.from(issued.der));
        expect(node.verify(nodeKey(rsaCa.issuerSigner.spki))).toBe(true);
        const cert = new x509.X509Certificate(issued.pem);
        expect(cert.signatureAlgorithm.name).toBe("RSASSA-PKCS1-v1_5");
        expect(cert.signatureAlgorithm.hash.name).toBe("SHA-256");
        // the inner and outer signature algorithm identifiers must be identical (RFC 5280 s4.1.1.2)
        const parsed = AsnConvert.parse(issued.der, Certificate);
        expect(parsed.signatureAlgorithm.isEqual(parsed.tbsCertificate.signature)).toBe(true);
    });

    it("issues a chain that validates from the root through the issuer to the leaf", async () => {
        const subject = newSubjectKey("rsa");
        const issued = await issueLeafCertificate(ec.issuer, URLS, {
            spki: subject.spki,
            email: "dave@example.net",
            type: "signing-encryption",
            notBefore: new Date(Date.now() - HOUR),
            notAfter: new Date(Date.now() + 30 * DAY),
        });
        const leaf = new x509.X509Certificate(issued.pem);
        const builder = new x509.X509ChainBuilder({ certificates: [new x509.X509Certificate(ec.issuerCert.pem), new x509.X509Certificate(ec.rootCert.pem)] });
        const chain = await builder.build(leaf);
        expect(chain.map((c) => c.subject)).toEqual(["CN=dave@example.net", "CN=Test S/MIME CA", "CN=Test Root CA"]);
        expect(await leaf.verify({ publicKey: chain[1].publicKey })).toBe(true);
        expect(await chain[1].verify({ publicKey: chain[2].publicKey })).toBe(true);
    });

    it.skipIf(!hasOpenssl)("passes `openssl verify -purpose smimesign` (and smimeencrypt for RSA encryption)", async () => {
        const dir = tempDir();
        try {
            const subject = newSubjectKey("rsa");
            const signing = await issueLeafCertificate(ec.issuer, URLS, {
                spki: subject.spki,
                email: "erin@example.com",
                type: "signing-encryption",
                notBefore: new Date(Date.now() - HOUR),
                notAfter: new Date(Date.now() + 30 * DAY),
            });
            const root = put(dir, "root.pem", ec.rootCert.pem);
            const inter = put(dir, "inter.pem", ec.issuerCert.pem);
            const leaf = put(dir, "leaf.pem", signing.pem);
            for (const purpose of ["smimesign", "smimeencrypt"]) {
                const r = openssl(["verify", "-CAfile", root, "-untrusted", inter, "-purpose", purpose, leaf])!;
                expect(r.stderr + r.stdout).toContain("OK");
                expect(r.status).toBe(0);
            }
            const r = openssl(["verify", "-CAfile", root, "-untrusted", inter, "-purpose", "sslserver", leaf])!;
            expect(r.status).not.toBe(0); // emailProtection only: not usable for TLS
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it("uses an empty subject and a critical SAN when the address is longer than the 64-octet CN bound", async () => {
        const subject = newSubjectKey("ec");
        const email = `${"a".repeat(60)}@example.com`;
        expect(email.length).toBeGreaterThan(64);
        const issued = await issueLeafCertificate(ec.issuer, URLS, {
            spki: subject.spki,
            email,
            type: "signing",
            notBefore: new Date(Date.now() - HOUR),
            notAfter: new Date(Date.now() + DAY),
        });
        const node = new crypto.X509Certificate(Buffer.from(issued.der));
        expect(node.subject).toBeFalsy();
        expect(node.checkEmail(email)).toBe(email);
        const cert = new x509.X509Certificate(issued.pem);
        expect((ext(cert, "2.5.29.17") as x509.SubjectAlternativeNameExtension).critical).toBe(true);
        expect(node.verify(nodeKey(ec.issuerSigner.spki))).toBe(true);
    });

    it("keeps a 64-octet address in the CN", async () => {
        const subject = newSubjectKey("ec");
        const email = `${"b".repeat(52)}@example.com`; // 64 octets
        expect(email.length).toBe(64);
        const issued = await issueLeafCertificate(ec.issuer, URLS, {
            spki: subject.spki,
            email,
            type: "signing",
            notBefore: new Date(Date.now() - HOUR),
            notAfter: new Date(Date.now() + DAY),
        });
        expect(new crypto.X509Certificate(Buffer.from(issued.der)).subject).toBe(`CN=${email}`);
    });

    it("draws a distinct random serial for every certificate and honours a caller-supplied one", async () => {
        const subject = newSubjectKey("ec");
        const base = { spki: subject.spki, email: "f@example.com", type: "signing" as const, notBefore: new Date(Date.now() - HOUR), notAfter: new Date(Date.now() + DAY) };
        const serials = new Set<string>();
        for (let i = 0; i < 20; i++) {
            serials.add((await issueLeafCertificate(ec.issuer, URLS, base)).serialHex);
        }
        expect(serials.size).toBe(20);
        const chosen = randomSerial();
        const issued = await issueLeafCertificate(ec.issuer, URLS, { ...base, serial: chosen });
        expect(issued.serialHex).toBe(Buffer.from(chosen).toString("hex"));
        const short = await issueLeafCertificate(ec.issuer, URLS, { ...base, serial: Uint8Array.of(0x7f, 0x01) });
        expect(short.serialHex).toBe("7f01");
    });

    it.each([
        ["empty", new Uint8Array()],
        ["leading zero octet", Uint8Array.of(0, 1, 2)],
        ["negative (top bit set)", Uint8Array.of(0x80, 1)],
        ["longer than 20 octets", new Uint8Array(21).fill(1)],
    ])("rejects a caller-supplied serial that is %s", async (_name, serial) => {
        const subject = newSubjectKey("ec");
        await expect(
            issueLeafCertificate(ec.issuer, URLS, {
                spki: subject.spki,
                email: "g@example.com",
                type: "signing",
                notBefore: new Date(Date.now() - HOUR),
                notAfter: new Date(Date.now() + DAY),
                serial,
            })
        ).rejects.toThrow(/serial/);
    });

    it("floors sub-second validity times and reports exactly what is in the certificate", async () => {
        const subject = newSubjectKey("ec");
        const issued = await issueLeafCertificate(ec.issuer, URLS, {
            spki: subject.spki,
            email: "h@example.com",
            type: "signing",
            notBefore: new Date("2030-01-02T03:04:05.987Z"),
            notAfter: new Date("2030-02-02T03:04:05.999Z"),
        });
        expect(issued.notBefore.toISOString()).toBe("2030-01-02T03:04:05.000Z");
        expect(issued.notAfter.toISOString()).toBe("2030-02-02T03:04:05.000Z");
    });

    describe("input validation", () => {
        const good = () => ({
            spki: newSubjectKey("ec").spki,
            email: "ok@example.com",
            type: "signing" as CertificateType,
            notBefore: new Date(Date.now() - HOUR),
            notAfter: new Date(Date.now() + DAY),
        });

        it.each([
            ["an invalid e-mail address", { email: "not an address" }, /e-mail/],
            ["an e-mail address with a CRLF", { email: "a@example.com\r\nX: y" }, /e-mail/],
            ["an unknown certificate type", { type: "server" as CertificateType }, /certificate type/],
            ["notAfter before notBefore", { notAfter: new Date(Date.now() - 2 * HOUR) }, /after notBefore/],
            ["invalid dates", { notAfter: new Date(NaN) }, /dates/],
            ["a validity above the maximum", { notAfter: new Date(Date.now() + (MAX_LEAF_VALIDITY_DAYS + 1) * DAY) }, /may not exceed/],
            ["a validity beyond the issuer's", { notBefore: new Date(Date.now() + 15 * 365 * DAY), notAfter: new Date(Date.now() + 15 * 365 * DAY + DAY) }, /outlive/],
        ])("rejects %s", async (_name, patch, message) => {
            await expect(issueLeafCertificate(ec.issuer, URLS, { ...good(), ...patch })).rejects.toThrow(message);
        });

        it("re-validates the public key (defence in depth) and reports badPublicKey", async () => {
            const weak = crypto.generateKeyPairSync("rsa", { modulusLength: 1024 }).publicKey;
            const err = await issueLeafCertificate(ec.issuer, URLS, { ...good(), spki: spkiOf(weak) }).catch((e) => e);
            expect(err).toBeInstanceOf(PkiPolicyError);
            expect(err.code).toBe("badPublicKey");
        });

        it.each([
            ["javascript scheme", { crl: "javascript:alert(1)", caIssuers: URLS.caIssuers, ocsp: URLS.ocsp }],
            ["whitespace", { crl: "https://a.test/x y", caIssuers: URLS.caIssuers, ocsp: URLS.ocsp }],
            ["non-ASCII", { crl: URLS.crl, caIssuers: "https://a.test/é", ocsp: URLS.ocsp }],
            ["relative", { crl: URLS.crl, caIssuers: URLS.caIssuers, ocsp: "/ocsp" }],
        ])("rejects an invalid embedded URL (%s)", async (_name, urls) => {
            await expect(issueLeafCertificate(ec.issuer, urls, good())).rejects.toThrow(/URL/);
        });
    });
});

describe("buildCaCertificate", () => {
    let h: Hierarchy;
    beforeAll(async () => {
        h = await makeHierarchy("ecdsa-p256");
    });

    it("builds a self-signed root: CA:TRUE critical, keyCertSign+cRLSign, SKI = AKI, no EKU, subject = issuer", async () => {
        const node = new crypto.X509Certificate(Buffer.from(h.rootCert.der));
        expect(node.ca).toBe(true);
        expect(node.subject).toBe("CN=Test Root CA");
        expect(node.issuer).toBe(node.subject);
        expect(node.verify(nodeKey(h.rootSigner.spki))).toBe(true);
        expect(node.checkIssued(node)).toBe(true);

        const cert = new x509.X509Certificate(h.rootCert.pem);
        const bc = ext(cert, "2.5.29.19") as x509.BasicConstraintsExtension;
        expect(bc.critical).toBe(true);
        expect(bc.ca).toBe(true);
        expect(bc.pathLength).toBeUndefined();
        const ku = ext(cert, "2.5.29.15") as x509.KeyUsagesExtension;
        expect(ku.critical).toBe(true);
        expect(ku.usages).toBe(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign);
        expect(cert.getExtension("2.5.29.37")).toBeNull();
        expect(cert.getExtension("2.5.29.31")).toBeNull();
        const ski = ext(cert, "2.5.29.14") as x509.SubjectKeyIdentifierExtension;
        const aki = ext(cert, "2.5.29.35") as x509.AuthorityKeyIdentifierExtension;
        expect(aki.keyId).toBe(ski.keyId);
        expect(h.rootCert.serialHex).toMatch(/^[0-9a-f]{40}$/);
    });

    it("builds a pathLen 0 intermediate with emailProtection EKU, signed by the root", async () => {
        const node = new crypto.X509Certificate(Buffer.from(h.issuerCert.der));
        expect(node.ca).toBe(true);
        expect(node.verify(nodeKey(h.rootSigner.spki))).toBe(true);
        expect(node.checkIssued(new crypto.X509Certificate(Buffer.from(h.rootCert.der)))).toBe(true);
        expect(node.keyUsage).toEqual(["1.3.6.1.5.5.7.3.4"]);

        const cert = new x509.X509Certificate(h.issuerCert.pem);
        const bc = ext(cert, "2.5.29.19") as x509.BasicConstraintsExtension;
        expect(bc.critical).toBe(true);
        expect(bc.ca).toBe(true);
        expect(bc.pathLength).toBe(0);
        const ku = ext(cert, "2.5.29.15") as x509.KeyUsagesExtension;
        expect(ku.usages).toBe(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign);
        const eku = ext(cert, "2.5.29.37") as x509.ExtendedKeyUsageExtension;
        expect(eku.usages).toEqual(["1.3.6.1.5.5.7.3.4"]);
        const rootSki = ext(new x509.X509Certificate(h.rootCert.pem), "2.5.29.14") as x509.SubjectKeyIdentifierExtension;
        expect((ext(cert, "2.5.29.35") as x509.AuthorityKeyIdentifierExtension).keyId).toBe(rootSki.keyId);
    });

    it("can carry CRLDP/AIA (partial URL sets allowed) and skips EKU by default", async () => {
        const key = newSigner("ecdsa-p256");
        const cert = await buildCaCertificate({
            subject: "CN=Sub CA",
            subjectSpki: key.spki,
            issuer: h.rootIssuer,
            signer: h.rootSigner,
            notBefore: new Date(Date.now() - HOUR),
            notAfter: new Date(Date.now() + 365 * DAY),
            urls: { crl: "https://acme.test/crl/root-r1.crl", caIssuers: "https://acme.test/ca/root-r1.crt" },
        });
        const parsed = new x509.X509Certificate(cert.pem);
        expect(parsed.getExtension("2.5.29.37")).toBeNull();
        expect((ext(parsed, "2.5.29.19") as x509.BasicConstraintsExtension).pathLength).toBeUndefined();
        const aia = ext(parsed, "1.3.6.1.5.5.7.1.1") as x509.AuthorityInfoAccessExtension;
        expect(aia.caIssuers).toHaveLength(1);
        expect(aia.ocsp).toHaveLength(0);
        expect((ext(parsed, "2.5.29.31") as x509.CRLDistributionPointsExtension).distributionPoints).toHaveLength(1);
    });

    it("uses GeneralizedTime past 2049 (RFC 5280 s4.1.2.5) and still verifies", async () => {
        const key = newSigner("ecdsa-p256");
        const cert = await buildCaCertificate({
            subject: "CN=Far Future Root",
            subjectSpki: key.spki,
            signer: key,
            notBefore: new Date("2026-01-01T00:00:00Z"),
            notAfter: new Date("2055-01-01T00:00:00Z"),
        });
        const parsed = new x509.X509Certificate(cert.pem);
        expect(parsed.notAfter.toISOString()).toBe("2055-01-01T00:00:00.000Z");
        const raw = AsnConvert.parse(cert.der, Certificate).tbsCertificate.validity;
        expect(raw.notBefore.utcTime).toBeDefined();
        expect(raw.notAfter.generalTime).toBeDefined();
        expect(new crypto.X509Certificate(Buffer.from(cert.der)).verify(nodeKey(key.spki))).toBe(true);
    });

    it("rejects a signer that is not the certificate's signing key", async () => {
        const key = newSigner("ecdsa-p256");
        const stranger = newSigner("ecdsa-p256");
        const base = { subject: "CN=X", notBefore: new Date(Date.now() - HOUR), notAfter: new Date(Date.now() + DAY) };
        await expect(buildCaCertificate({ ...base, subjectSpki: key.spki, signer: stranger })).rejects.toThrow(/own key/);
        await expect(
            buildCaCertificate({ ...base, subjectSpki: key.spki, issuer: h.rootIssuer, signer: stranger })
        ).rejects.toThrow(/not the issuer's key/);
    });

    it("validates pathLen, validity and the subject key", async () => {
        const key = newSigner("ecdsa-p256");
        const base = { subject: "CN=X", subjectSpki: key.spki, signer: key, notBefore: new Date(Date.now() - HOUR), notAfter: new Date(Date.now() + DAY) };
        await expect(buildCaCertificate({ ...base, pathLen: -1 })).rejects.toThrow(/pathLen/);
        await expect(buildCaCertificate({ ...base, pathLen: 1.5 })).rejects.toThrow(/pathLen/);
        await expect(buildCaCertificate({ ...base, notAfter: new Date(Date.now() - 2 * HOUR) })).rejects.toThrow(/after notBefore/);
        const sub = newSigner("ecdsa-p256");
        await expect(
            buildCaCertificate({ ...base, subjectSpki: sub.spki, issuer: h.rootIssuer, signer: h.rootSigner, notAfter: new Date(Date.now() + 50 * 365 * DAY) })
        ).rejects.toThrow(/outlive/);
        const weak = crypto.generateKeyPairSync("rsa", { modulusLength: 1024 }).publicKey;
        await expect(buildCaCertificate({ ...base, subjectSpki: spkiOf(weak) })).rejects.toThrow(PkiPolicyError);
    });
});

describe("parseDistinguishedName", () => {
    const rdns = (dn: string) =>
        parseDistinguishedName(dn).map((rdn) => rdn.map((a) => `${a.type}=${a.value.toString()}`).join("+"));

    it("keeps RDNs in the written order with the documented string types", () => {
        expect(rdns("C=US, O=Rapid MX, OU=PKI, CN=Root CA")).toEqual(["2.5.4.6=US", "2.5.4.10=Rapid MX", "2.5.4.11=PKI", "2.5.4.3=Root CA"]);
        const name = parseDistinguishedName("C=US,CN=Root,DC=example");
        expect(name[0][0].value.printableString).toBe("US");
        expect(name[1][0].value.utf8String).toBe("Root");
        expect(name[2][0].value.ia5String).toBe("example");
    });

    it("handles escapes, hex escapes and surrounding whitespace", () => {
        expect(rdns("CN=Foo\\, Bar")).toEqual(["2.5.4.3=Foo, Bar"]);
        expect(rdns("CN = a\\+b\\=c\\\\d")).toEqual(["2.5.4.3=a+b=c\\d"]);
        expect(rdns("CN=caf\\c3")).toEqual(["2.5.4.3=cafÃ"]);
        expect(rdns("CN=RapidMX S/MIME CA R1")).toEqual(["2.5.4.3=RapidMX S/MIME CA R1"]);
    });

    it.each([
        ["empty", ""],
        ["no equals sign", "Root CA"],
        ["unknown attribute", "FOO=bar"],
        ["multi-valued RDN", "CN=a+O=b"],
        ["empty value", "CN="],
        ["control character", "CN=a\u0001b"],
        ["dangling escape", "CN=abc\\"],
        ["over-long CN", "CN=" + "x".repeat(65)],
        ["lower-case country", "C=us"],
        ["three-letter country", "C=USA"],
    ])("rejects %s", (_n, dn) => {
        expect(() => parseDistinguishedName(dn)).toThrow();
    });
});
