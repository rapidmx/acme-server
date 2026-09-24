///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import "reflect-metadata";
import * as x509 from "@peculiar/x509";
import * as crypto from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
    Issuer,
    IssuerRegistry,
    LocalKeySigner,
    buildCaCertificate,
    issueLeafCertificate,
    sha256Hex,
} from "../../../src/lib/pki/index.js";
import { keyIdentifierOf } from "../../../src/lib/pki/certutil.js";
import {
    DAY,
    HOUR,
    URLS,
    exportKey,
    makeHierarchy,
    newSigner,
    newSubjectKey,
    privateKeyOf,
    put,
    rmSync,
    tempDir,
    type Hierarchy,
} from "./helpers.js";

x509.cryptoProvider.set(globalThis.crypto);

const nodeKey = (spki: Uint8Array) => crypto.createPublicKey({ key: Buffer.from(spki), format: "der", type: "spki" });

/** A second issuer under the same root as `h`. */
async function siblingIssuer(h: Hierarchy, id: string, active = false): Promise<Issuer> {
    const signer = newSigner("ecdsa-p384");
    const cert = await buildCaCertificate({
        subject: `CN=Sibling ${id}`,
        subjectSpki: signer.spki,
        issuer: h.rootIssuer,
        signer: h.rootSigner,
        notBefore: new Date(Date.now() - HOUR),
        notAfter: new Date(Date.now() + 365 * DAY),
        pathLen: 0,
        ekuEmailProtection: true,
    });
    return new Issuer({ id, name: `Sibling ${id}`, certificate: cert.pem, chain: [h.rootCert.pem], signer, active });
}

describe("Issuer", () => {
    let h: Hierarchy;
    beforeAll(async () => {
        h = await makeHierarchy("ecdsa-p384");
    });

    it("exposes its certificate, chain, signer, active flag and the certificate's subjectKeyIdentifier", () => {
        expect(h.issuer.id).toBe("smime-r1");
        expect(h.issuer.name).toBe("Test S/MIME CA");
        expect(h.issuer.active).toBe(true);
        expect(h.issuer.certificate).toBeInstanceOf(x509.X509Certificate);
        expect(h.issuer.chain.map((c) => c.subject)).toEqual(["CN=Test Root CA"]);
        expect(h.issuer.signer).toBe(h.issuerSigner);
        const ski = h.issuer.certificate.getExtension("2.5.29.14") as x509.SubjectKeyIdentifierExtension;
        expect(Buffer.from(h.issuer.keyId).toString("hex")).toBe(ski.keyId);
        expect(h.rootIssuer.active).toBe(false);
    });

    it("describes itself for the public /ca endpoint", () => {
        const info = h.issuer.info();
        const node = new crypto.X509Certificate(Buffer.from(h.issuerCert.der));
        expect(info.id).toBe("smime-r1");
        expect(info.role).toBe("intermediate");
        expect(h.rootIssuer.info().role).toBe("root");
        expect(info.subject).toBe("CN=Test S/MIME CA");
        expect(info.serialNumber).toBe(h.issuerCert.serialHex);
        expect(info.notBefore).toBe(new Date(node.validFrom).toISOString());
        expect(info.notAfter).toBe(new Date(node.validTo).toISOString());
        expect(info.sha256Fingerprint).toBe(node.fingerprint256.replace(/:/g, "").toLowerCase());
        expect(info.spkiSha256).toBe(sha256Hex(h.issuerSigner.spki));
        expect(info.pem).toBe(h.issuerCert.pem);
        expect(info.jwk).toMatchObject({ kty: "EC", crv: "P-384", kid: "smime-r1", use: "sig", alg: "ES384" });
        // the JWK really is the issuer's public key
        expect(crypto.createPublicKey({ key: info.jwk, format: "jwk" }).export({ type: "spki", format: "der" }).equals(Buffer.from(h.issuerSigner.spki))).toBe(true);
    });

    it("computes OCSP CertID hashes from the certificate's own encoding", () => {
        const spki = h.issuerSigner.spki;
        const keyBits = spki.slice(spki.length - 97); // P-384 uncompressed point
        for (const alg of ["sha1", "sha256", "sha384", "sha512"] as const) {
            expect(Buffer.from(h.issuer.keyHash(alg)).equals(crypto.createHash(alg).update(keyBits).digest())).toBe(true);
        }
        expect(Buffer.from(h.issuer.keyHash()).equals(Buffer.from(h.issuer.keyHash("sha1")))).toBe(true);
        const subject = new x509.X509Certificate(h.issuerCert.pem).subjectName.toArrayBuffer();
        expect(Buffer.from(h.issuer.nameHash("sha256")).equals(crypto.createHash("sha256").update(Buffer.from(subject)).digest())).toBe(true);
        expect(Buffer.from(h.issuer.subjectDer).equals(Buffer.from(subject))).toBe(true);
    });

    it("computes a key identifier when the certificate has no subjectKeyIdentifier", async () => {
        const key = await globalThis.crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
        const cert = await x509.X509CertificateGenerator.createSelfSigned({
            name: "CN=No SKI CA",
            notBefore: new Date(Date.now() - HOUR),
            notAfter: new Date(Date.now() + DAY),
            signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
            keys: key,
            extensions: [new x509.BasicConstraintsExtension(true, undefined, true)],
        });
        const nodePriv = crypto.KeyObject.from(key.privateKey);
        const issuer = new Issuer({ id: "noski", name: "No SKI", certificate: cert.toString("pem"), signer: new LocalKeySigner(nodePriv) });
        expect(Buffer.from(issuer.keyId).equals(Buffer.from(keyIdentifierOf(new Uint8Array(cert.publicKey.rawData))))).toBe(true);
    });

    describe("construction checks", () => {
        it.each(["", "Upper", "has space", "a/b", "a.b", "-lead", "x".repeat(64)])("rejects the id %j", (id) => {
            expect(
                () => new Issuer({ id, name: "n", certificate: h.issuerCert.pem, chain: [h.rootCert.pem], signer: h.issuerSigner })
            ).toThrow(/issuer id/i);
        });

        it("rejects a signer that does not hold the certificate's key", () => {
            expect(
                () => new Issuer({ id: "x", name: "n", certificate: h.issuerCert.pem, chain: [h.rootCert.pem], signer: newSigner("ecdsa-p384") })
            ).toThrow(/does not match/);
        });

        it("rejects a certificate that is not a CA", async () => {
            const subject = newSigner("ecdsa-p256");
            const leaf = await issueLeafCertificate(h.issuer, URLS, {
                spki: subject.spki,
                email: "notca@example.com",
                type: "signing",
                notBefore: new Date(Date.now() - HOUR),
                notAfter: new Date(Date.now() + DAY),
            });
            expect(() => new Issuer({ id: "leaf", name: "n", certificate: leaf.pem, signer: subject })).toThrow(/not a CA/);
        });

        it("rejects a CA certificate whose keyUsage cannot sign certificates and CRLs", async () => {
            const key = await globalThis.crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
            const cert = await x509.X509CertificateGenerator.createSelfSigned({
                name: "CN=Digital Signature Only CA",
                notBefore: new Date(Date.now() - HOUR),
                notAfter: new Date(Date.now() + DAY),
                signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
                keys: key,
                extensions: [
                    new x509.BasicConstraintsExtension(true, undefined, true),
                    new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
                ],
            });
            expect(
                () => new Issuer({ id: "ku", name: "n", certificate: cert.toString("pem"), signer: new LocalKeySigner(crypto.KeyObject.from(key.privateKey)) })
            ).toThrow(/keyCertSign/);
        });

        it("rejects a broken chain (parent did not sign the child) and accepts an empty chain", () => {
            expect(
                () => new Issuer({ id: "x", name: "n", certificate: h.issuerCert.pem, chain: [h.issuerCert.pem], signer: h.issuerSigner })
            ).toThrow(/chain is broken/);
            const noChain = new Issuer({ id: "x", name: "n", certificate: h.issuerCert.pem, signer: h.issuerSigner });
            expect(noChain.chain).toEqual([]);
        });

        it("requires a name and a valid certificate", () => {
            expect(() => new Issuer({ id: "x", name: "", certificate: h.issuerCert.pem, signer: h.issuerSigner })).toThrow(/name/);
            expect(() => new Issuer({ id: "x", name: "n", certificate: "-----BEGIN NOTHING-----", signer: h.issuerSigner })).toThrow();
        });

        it("accepts DER bytes and x509 objects as certificate input", () => {
            const fromDer = new Issuer({ id: "d", name: "n", certificate: h.issuerCert.der, chain: [new x509.X509Certificate(h.rootCert.pem)], signer: h.issuerSigner });
            expect(fromDer.keyId).toEqual(h.issuer.keyId);
        });
    });
});

describe("IssuerRegistry", () => {
    let h: Hierarchy;
    beforeAll(async () => {
        h = await makeHierarchy("ecdsa-p384");
    });

    it("lists, looks up and returns the single active issuer", async () => {
        const older = await siblingIssuer(h, "smime-r0");
        const registry = IssuerRegistry.fromIssuers([older, h.issuer]);
        expect(registry.all().map((i) => i.id)).toEqual(["smime-r0", "smime-r1"]);
        expect(registry.get("smime-r0")).toBe(older);
        expect(registry.get("nope")).toBeUndefined();
        expect(registry.active()).toBe(h.issuer);
        // the returned list is a copy
        registry.all().pop();
        expect(registry.all()).toHaveLength(2);
    });

    it("throws from active() unless exactly one issuer is active", async () => {
        const a = await siblingIssuer(h, "a-one");
        const b = await siblingIssuer(h, "b-two");
        expect(() => IssuerRegistry.fromIssuers([a, b]).active()).toThrow(/exactly one/i);
        const c = await siblingIssuer(h, "c-three", true);
        const d = await siblingIssuer(h, "d-four", true);
        expect(() => IssuerRegistry.fromIssuers([c, d]).active()).toThrow(/exactly one/i);
    });

    it("rejects duplicate ids", () => {
        expect(() => IssuerRegistry.fromIssuers([h.issuer, h.issuer])).toThrow(/Duplicate issuer id/);
    });

    it("returns the de-duplicated chain tops as the roots", async () => {
        const second = await siblingIssuer(h, "smime-r2");
        const other = await makeHierarchy("ecdsa-p256", "other");
        const registry = IssuerRegistry.fromIssuers([h.issuer, second, other.issuer]);
        const roots = registry.roots();
        expect(roots).toHaveLength(2);
        expect(roots.map((r) => r.subject)).toEqual(["CN=Test Root CA", "CN=Test Root CA"]);
        expect(new Set(roots.map((r) => sha256Hex(new Uint8Array(r.rawData)))).size).toBe(2);
        // an issuer without a chain is its own trust anchor
        expect(IssuerRegistry.fromIssuers([h.rootIssuer]).roots().map((r) => r.subject)).toEqual(["CN=Test Root CA"]);
    });

    it("finds issuers by CertID hashes", async () => {
        const second = await siblingIssuer(h, "smime-r2");
        const registry = IssuerRegistry.fromIssuers([h.issuer, second]);
        for (const alg of ["sha1", "sha256"] as const) {
            expect(registry.findByIssuerKeyHash(alg, h.issuer.keyHash(alg))).toBe(h.issuer);
            expect(registry.findByIssuerKeyHash(alg, second.keyHash(alg))).toBe(second);
            expect(registry.findByCertId(alg, second.nameHash(alg), second.keyHash(alg))).toBe(second);
            // right key, wrong name: not this issuer
            expect(registry.findByCertId(alg, second.nameHash(alg), h.issuer.keyHash(alg))).toBeUndefined();
        }
        expect(registry.findByIssuerKeyHash("sha1", new Uint8Array(20))).toBeUndefined();
        expect(registry.findByIssuerKeyHash("sha1", new Uint8Array(3))).toBeUndefined();
    });
});

describe("IssuerRegistry.fromManifest", () => {
    let h: Hierarchy;
    let older: Issuer;
    let dir: string;

    beforeAll(async () => {
        h = await makeHierarchy("ecdsa-p384");
        older = await siblingIssuer(h, "smime-r0");
    });

    /** Writes a CA directory in the ca-init layout plus a manifest, and returns the manifest path. */
    async function layout(entries: (paths: { key1: string; key0: string }) => unknown[]): Promise<string> {
        dir = tempDir();
        mkdirSync(join(dir, "root-r1"), { recursive: true });
        mkdirSync(join(dir, "smime-r1"), { recursive: true });
        mkdirSync(join(dir, "smime-r0"), { recursive: true });
        put(join(dir, "root-r1"), "cert.pem", h.rootCert.pem);
        put(join(dir, "smime-r1"), "cert.pem", h.issuerCert.pem);
        put(join(dir, "smime-r0"), "cert.pem", older.certificate.toString("pem"));
        put(join(dir, "smime-r1"), "key.pem", exportKey(h.issuerSigner));
        put(join(dir, "smime-r0"), "key.pem", exportKey(older.signer));
        return put(dir, "issuers.json", JSON.stringify(entries({ key1: "smime-r1/key.pem", key0: "smime-r0/key.pem" }), null, 2));
    }

    afterEach(() => {
        if (dir) rmSync(dir, { recursive: true, force: true });
    });

    const entry = (id: string, active: boolean, extra: Record<string, unknown> = {}) => ({
        id,
        name: `Issuer ${id}`,
        certificate: `${id}/cert.pem`,
        chain: ["root-r1/cert.pem"],
        key: { type: "file", path: `${id}/key.pem` },
        active,
        ...extra,
    });

    it("loads a manifest with relative paths, keeps older issuers listed, and finds the single active one", async () => {
        const manifest = await layout(() => [entry("smime-r0", false), entry("smime-r1", true)]);
        const registry = await IssuerRegistry.fromManifest(manifest);
        expect(registry.all().map((i) => i.id)).toEqual(["smime-r0", "smime-r1"]);
        expect(registry.active().id).toBe("smime-r1");
        expect(registry.get("smime-r0")!.active).toBe(false);
        expect(registry.get("smime-r1")!.name).toBe("Issuer smime-r1");
        expect(registry.roots()).toHaveLength(1);
        expect(registry.active().chain.map((c) => c.subject)).toEqual(["CN=Test Root CA"]);

        // and the loaded issuer really can issue
        const subject = newSubjectKey("ec");
        const leaf = await issueLeafCertificate(registry.active(), URLS, {
            spki: subject.spki,
            email: "manifest@example.com",
            type: "signing-encryption",
            notBefore: new Date(Date.now() - HOUR),
            notAfter: new Date(Date.now() + 30 * DAY),
        });
        const node = new crypto.X509Certificate(Buffer.from(leaf.der));
        expect(node.verify(nodeKey(h.issuerSigner.spki))).toBe(true);
    });

    it("resolves relative paths against the manifest's directory, not the working directory, and accepts absolute paths", async () => {
        const manifest = await layout(() => [
            entry("smime-r1", true, { certificate: join(dir, "smime-r1", "cert.pem"), chain: [join(dir, "root-r1", "cert.pem")] }),
        ]);
        const cwd = process.cwd();
        expect(cwd).not.toBe(dir);
        await expect(IssuerRegistry.fromManifest(manifest)).resolves.toBeDefined();
    });

    it("decrypts an encrypted key with the passphrase from the named environment variable", async () => {
        const manifest = await layout(() => [entry("smime-r1", true, { key: { type: "file", path: "smime-r1/key.pem", passphrase_env: "TEST_CA_PASS" } })]);
        put(join(dir, "smime-r1"), "key.pem", exportKey(h.issuerSigner, "s3cret-passphrase"));
        const registry = await IssuerRegistry.fromManifest(manifest, { env: { TEST_CA_PASS: "s3cret-passphrase" } });
        expect(registry.active().id).toBe("smime-r1");
    });

    it("explains a missing, empty or wrong passphrase", async () => {
        const manifest = await layout(() => [entry("smime-r1", true, { key: { type: "file", path: "smime-r1/key.pem", passphrase_env: "TEST_CA_PASS" } })]);
        put(join(dir, "smime-r1"), "key.pem", exportKey(h.issuerSigner, "right"));
        await expect(IssuerRegistry.fromManifest(manifest, { env: {} })).rejects.toThrow(/TEST_CA_PASS.*not set/);
        await expect(IssuerRegistry.fromManifest(manifest, { env: { TEST_CA_PASS: "" } })).rejects.toThrow(/TEST_CA_PASS.*not set/);
        await expect(IssuerRegistry.fromManifest(manifest, { env: { TEST_CA_PASS: "wrong" } })).rejects.toThrow(/wrong passphrase/);
        // an encrypted key with no passphrase_env configured at all
        const plain = await layout(() => [entry("smime-r1", true)]);
        put(join(dir, "smime-r1"), "key.pem", exportKey(h.issuerSigner, "right"));
        await expect(IssuerRegistry.fromManifest(plain)).rejects.toThrow(/encrypted and no passphrase/);
    });

    it("names the issuer and the file when something is missing", async () => {
        const manifest = await layout(() => [entry("smime-r1", true, { certificate: "smime-r1/missing.pem" })]);
        await expect(IssuerRegistry.fromManifest(manifest)).rejects.toThrow(/issuer 'smime-r1'.*missing\.pem.*not found/);
        const noKey = await layout(() => [entry("smime-r1", true, { key: { type: "file", path: "smime-r1/nokey.pem" } })]);
        await expect(IssuerRegistry.fromManifest(noKey)).rejects.toThrow(/issuer 'smime-r1'.*nokey\.pem.*not found/);
        const noChain = await layout(() => [entry("smime-r1", true, { chain: ["root-r1/gone.pem"] })]);
        await expect(IssuerRegistry.fromManifest(noChain)).rejects.toThrow(/issuer 'smime-r1'.*gone\.pem/);
        await expect(IssuerRegistry.fromManifest(join(dir, "no-such-manifest.json"))).rejects.toThrow(/no-such-manifest\.json.*not found/);
    });

    it("rejects a key that does not belong to the certificate", async () => {
        const manifest = await layout(() => [entry("smime-r1", true, { key: { type: "file", path: "smime-r0/key.pem" } })]);
        await expect(IssuerRegistry.fromManifest(manifest)).rejects.toThrow(/issuer 'smime-r1'.*does not match/);
    });

    it("rejects malformed manifests", async () => {
        const manifest = await layout(() => []);
        await expect(IssuerRegistry.fromManifest(manifest)).rejects.toThrow(/non-empty JSON array/);
        writeFileSync(manifest, "{not json");
        await expect(IssuerRegistry.fromManifest(manifest)).rejects.toThrow(/not valid JSON/);
        writeFileSync(manifest, JSON.stringify({ id: "x" }));
        await expect(IssuerRegistry.fromManifest(manifest)).rejects.toThrow(/non-empty JSON array/);
        writeFileSync(manifest, JSON.stringify([{ id: "x" }]));
        await expect(IssuerRegistry.fromManifest(manifest)).rejects.toThrow(/'key' object/);
        writeFileSync(manifest, JSON.stringify([entry("smime-r1", true, { active: "yes" })]));
        await expect(IssuerRegistry.fromManifest(manifest)).rejects.toThrow(/'active' must be true or false/);
        writeFileSync(manifest, JSON.stringify([entry("smime-r1", true, { key: { type: "pkcs11" } })]));
        await expect(IssuerRegistry.fromManifest(manifest)).rejects.toThrow(/unknown key type "pkcs11"/);
        writeFileSync(manifest, JSON.stringify([entry("smime-r1", true, { chain: "root-r1/cert.pem" })]));
        await expect(IssuerRegistry.fromManifest(manifest)).rejects.toThrow(/'chain' must be an array/);
        writeFileSync(manifest, JSON.stringify([entry("smime-r1", true, { id: "Bad Id" })]));
        await expect(IssuerRegistry.fromManifest(manifest)).rejects.toThrow(/Invalid issuer id/);
    });

    it("requires exactly one active issuer", async () => {
        const none = await layout(() => [entry("smime-r0", false), entry("smime-r1", false)]);
        await expect(IssuerRegistry.fromManifest(none)).rejects.toThrow(/exactly one issuer "active": true \(found 0\)/);
        const two = await layout(() => [entry("smime-r0", true), entry("smime-r1", true)]);
        await expect(IssuerRegistry.fromManifest(two)).rejects.toThrow(/exactly one issuer "active": true \(found 2\)/);
        const dup = await layout(() => [entry("smime-r1", true), entry("smime-r1", false)]);
        await expect(IssuerRegistry.fromManifest(dup)).rejects.toThrow(/Duplicate issuer id/);
    });

    describe("openbao-transit keys", () => {
        /** A fake Transit engine for `h.issuerSigner`'s key, served through an injected fetch. */
        function fakeFetch(privateKey: crypto.KeyObject) {
            const calls: Array<{ url: string; init: RequestInit }> = [];
            const fetchFn = (async (url: string, init: RequestInit) => {
                calls.push({ url, init });
                const headers = init.headers as Record<string, string>;
                if (headers["X-Vault-Token"] !== "s.abc") {
                    return new Response(JSON.stringify({ errors: ["permission denied"] }), { status: 403 });
                }
                if (init.method === "GET") {
                    return new Response(
                        JSON.stringify({ data: { type: "ecdsa-p384", latest_version: 1, keys: { "1": { public_key: crypto.createPublicKey(privateKey).export({ type: "spki", format: "pem" }) } } } }),
                        { status: 200 }
                    );
                }
                const body = JSON.parse(String(init.body));
                const sig = crypto.sign("sha384", Buffer.from(body.input, "base64"), { key: privateKey, dsaEncoding: "der" });
                return new Response(JSON.stringify({ data: { signature: `vault:v1:${sig.toString("base64")}` } }), { status: 200 });
            }) as unknown as typeof fetch;
            return { calls, fetchFn };
        }

        const baoKey = (extra: Record<string, unknown>) => ({ type: "openbao-transit", url: "https://bao.test:8200", key_name: "ca-r1", ...extra });

        it("creates a remote signer from token_env, and certificates issued through it verify", async () => {
            const { calls, fetchFn } = fakeFetch(privateKeyOf(h.issuerSigner));
            const manifest = await layout(() => [entry("smime-r1", true, { key: baoKey({ token_env: "BAO_TOKEN" }) })]);
            const registry = await IssuerRegistry.fromManifest(manifest, { env: { BAO_TOKEN: "s.abc" }, fetch: fetchFn });
            expect(calls[0].url).toBe("https://bao.test:8200/v1/transit/keys/ca-r1");
            const subject = newSubjectKey("rsa");
            const leaf = await issueLeafCertificate(registry.active(), URLS, {
                spki: subject.spki,
                email: "remote@example.com",
                type: "signing",
                notBefore: new Date(Date.now() - HOUR),
                notAfter: new Date(Date.now() + DAY),
            });
            expect(new crypto.X509Certificate(Buffer.from(leaf.der)).verify(nodeKey(h.issuerSigner.spki))).toBe(true);
            expect(calls.some((c) => c.url.endsWith("/sign/ca-r1/sha2-384"))).toBe(true);
        });

        it("reads the token from token_file on every signature (rotation-friendly)", async () => {
            const { fetchFn, calls } = fakeFetch(privateKeyOf(h.issuerSigner));
            const manifest = await layout(() => [entry("smime-r1", true, { key: baoKey({ token_file: "token" }) })]);
            const tokenFile = put(dir, "token", "s.abc\n");
            // the file is read when the signer is created (to read the public key) and again for each signature
            const registry = await IssuerRegistry.fromManifest(manifest, { fetch: fetchFn });
            writeFileSync(tokenFile, "s.rotated\n");
            await expect(registry.active().signer.sign(new Uint8Array([1, 2, 3]))).rejects.toThrow(/HTTP 403: permission denied/);
            expect((calls[calls.length - 1].init.headers as Record<string, string>)["X-Vault-Token"]).toBe("s.rotated");
            writeFileSync(tokenFile, "s.abc\n");
            await expect(registry.active().signer.sign(new Uint8Array([1, 2, 3]))).resolves.toBeInstanceOf(Uint8Array);
        });

        it("needs a token source and reports an unset variable", async () => {
            const { fetchFn } = fakeFetch(privateKeyOf(h.issuerSigner));
            const none = await layout(() => [entry("smime-r1", true, { key: baoKey({}) })]);
            await expect(IssuerRegistry.fromManifest(none, { fetch: fetchFn })).rejects.toThrow(/token_env.*token_file/);
            const unset = await layout(() => [entry("smime-r1", true, { key: baoKey({ token_env: "BAO_TOKEN" }) })]);
            await expect(IssuerRegistry.fromManifest(unset, { env: {}, fetch: fetchFn })).rejects.toThrow(/BAO_TOKEN.*not set/);
        });

        it("rejects a remote key that is not the issuer certificate's key", async () => {
            const { fetchFn } = fakeFetch(privateKeyOf(newSigner("ecdsa-p384")));
            const manifest = await layout(() => [entry("smime-r1", true, { key: baoKey({ token_env: "BAO_TOKEN" }) })]);
            await expect(IssuerRegistry.fromManifest(manifest, { env: { BAO_TOKEN: "s.abc" }, fetch: fetchFn })).rejects.toThrow(/does not match/);
        });

        it("surfaces authorization failures from the key lookup", async () => {
            const { fetchFn } = fakeFetch(privateKeyOf(h.issuerSigner));
            const manifest = await layout(() => [entry("smime-r1", true, { key: baoKey({ token_env: "BAO_TOKEN" }) })]);
            await expect(IssuerRegistry.fromManifest(manifest, { env: { BAO_TOKEN: "s.bad" }, fetch: fetchFn })).rejects.toThrow(/HTTP 403/);
        });
    });
});

