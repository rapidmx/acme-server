///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import * as crypto from "node:crypto";
import {
    LocalKeySigner,
    OpenBaoTransitSigner,
    isRsaSignatureAlgorithm,
    pemToDer,
    signChecked,
    signatureAlgorithmIdentifier,
    signatureHash,
    verifySignature,
    type CaSigner,
    type OpenBaoHttpGet,
    type OpenBaoHttpPost,
    issueLeafCertificate,
} from "../../../src/lib/pki/index.js";
import { HOUR, URLS, makeHierarchy, newSubjectKey } from "./helpers.js";

const DATA = new TextEncoder().encode("to be signed");

describe("LocalKeySigner", () => {
    it.each([
        ["ecdsa-p256", "ecdsa-with-SHA256"],
        ["ecdsa-p384", "ecdsa-with-SHA384"],
    ] as const)("generates %s keys that sign X.509-style (DER) ECDSA signatures", async (kind, algorithm) => {
        const { signer } = await LocalKeySigner.generate(kind);
        expect(signer.algorithm).toBe(algorithm);
        const sig = await signer.sign(DATA);
        // DER SEQUENCE { INTEGER, INTEGER }, not IEEE P1363
        expect(sig[0]).toBe(0x30);
        expect(verifySignature(signer.algorithm, signer.spki, DATA, sig)).toBe(true);
        const pub = crypto.createPublicKey({ key: Buffer.from(signer.spki), format: "der", type: "spki" });
        expect(crypto.verify(signatureHash(algorithm), DATA, { key: pub, dsaEncoding: "der" }, sig)).toBe(true);
        expect(verifySignature(signer.algorithm, signer.spki, new TextEncoder().encode("other"), sig)).toBe(false);
    });

    it("signs ECDSA P-521 with SHA-512", () => {
        const signer = new LocalKeySigner(crypto.generateKeyPairSync("ec", { namedCurve: "P-521" }).privateKey);
        expect(signer.algorithm).toBe("ecdsa-with-SHA512");
    });

    it("signs RSA with PKCS #1 v1.5 and picks the digest by key size", async () => {
        const rsa2048 = new LocalKeySigner(crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey);
        expect(rsa2048.algorithm).toBe("sha256WithRSAEncryption");
        expect(isRsaSignatureAlgorithm(rsa2048.algorithm)).toBe(true);
        const sig = await rsa2048.sign(DATA);
        expect(sig.length).toBe(256);
        expect(verifySignature(rsa2048.algorithm, rsa2048.spki, DATA, sig)).toBe(true);
        // PKCS #1 v1.5 is deterministic (PSS would not be)
        expect(Buffer.from(await rsa2048.sign(DATA)).equals(Buffer.from(sig))).toBe(true);

        const { signer: rsa3072 } = await LocalKeySigner.generate("rsa-3072");
        expect(rsa3072.algorithm).toBe("sha384WithRSAEncryption");
        expect(verifySignature(rsa3072.algorithm, rsa3072.spki, DATA, await rsa3072.sign(DATA))).toBe(true);
    });

    it("lets the digest be overridden", () => {
        const key = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
        expect(new LocalKeySigner(key, "sha512").algorithm).toBe("ecdsa-with-SHA512");
    });

    it("refuses keys it will not sign certificates with", () => {
        expect(() => new LocalKeySigner(crypto.generateKeyPairSync("rsa", { modulusLength: 1024 }).privateKey)).toThrow(
            /RSA key size/
        );
        expect(() => new LocalKeySigner(crypto.generateKeyPairSync("ed25519").privateKey)).toThrow(/key type/);
        expect(() => new LocalKeySigner(crypto.generateKeyPairSync("ec", { namedCurve: "secp256k1" }).privateKey)).toThrow(
            /curve/
        );
        expect(() => new LocalKeySigner(crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey)).toThrow(
            /private key/
        );
    });

    it("exports and re-imports an unencrypted PKCS #8 PEM", async () => {
        const { signer, privateKeyPem } = await LocalKeySigner.generate("ecdsa-p256");
        const pem = privateKeyPem();
        expect(pem).toMatch(/^-----BEGIN PRIVATE KEY-----/);
        const again = LocalKeySigner.fromPem(pem);
        expect(Buffer.from(again.spki).equals(Buffer.from(signer.spki))).toBe(true);
        expect(verifySignature(signer.algorithm, signer.spki, DATA, await again.sign(DATA))).toBe(true);
    });

    it("encrypts with PBES2 / PBKDF2-HMAC-SHA-256 / 600 000 iterations / AES-256-CBC and decrypts with the passphrase", async () => {
        const { signer, privateKeyPem } = await LocalKeySigner.generate("ecdsa-p384");
        const pem = privateKeyPem("correct horse battery staple");
        expect(pem).toMatch(/^-----BEGIN ENCRYPTED PRIVATE KEY-----/);
        expect(pem).not.toContain("BEGIN PRIVATE KEY");
        const der = Buffer.from(pemToDer(pem));
        expect(der.includes(Buffer.from("02030927c0", "hex"))).toBe(true); // INTEGER 600000
        const loaded = LocalKeySigner.fromPem(pem, "correct horse battery staple");
        expect(Buffer.from(loaded.spki).equals(Buffer.from(signer.spki))).toBe(true);
        // Node itself agrees this is a well-formed, decryptable PKCS #8 (OpenSSL's decoder, not ours)
        expect(crypto.createPrivateKey({ key: pem, passphrase: "correct horse battery staple" }).type).toBe("private");
    });

    it("reports a missing or wrong passphrase clearly, without echoing the key", async () => {
        const { privateKeyPem } = await LocalKeySigner.generate("ecdsa-p256");
        const pem = privateKeyPem("secret-pass");
        expect(() => LocalKeySigner.fromPem(pem)).toThrow(/encrypted and no passphrase/);
        let message = "";
        try {
            LocalKeySigner.fromPem(pem, "wrong");
        } catch (err) {
            message = (err as Error).message;
        }
        expect(message).toMatch(/wrong passphrase/);
        expect(message).not.toContain(pem.slice(40, 80));
        expect(() => LocalKeySigner.fromPem("not a key")).toThrow(/not a valid PEM key/);
        expect(() => privateKeyPem("")).toThrow(/must not be empty/);
    });

    it("does not expose the private key through enumerable properties or JSON", async () => {
        const { signer } = await LocalKeySigner.generate("ecdsa-p256");
        expect(Object.keys(signer).sort()).toEqual(["algorithm", "spki"]);
        expect(JSON.stringify(signer)).not.toMatch(/PRIVATE/);
    });
});

describe("signatureAlgorithmIdentifier", () => {
    it("omits parameters for ECDSA and writes NULL for RSA (RFC 5758 / RFC 8017)", () => {
        expect(signatureAlgorithmIdentifier("ecdsa-with-SHA384").parameters).toBeUndefined();
        expect(signatureAlgorithmIdentifier("ecdsa-with-SHA384").algorithm).toBe("1.2.840.10045.4.3.3");
        const rsa = signatureAlgorithmIdentifier("sha256WithRSAEncryption");
        expect(rsa.algorithm).toBe("1.2.840.113549.1.1.11");
        expect(Array.from(new Uint8Array(rsa.parameters!))).toEqual([5, 0]);
        expect(() => signatureAlgorithmIdentifier("md5" as never)).toThrow();
    });
});

describe("signChecked", () => {
    it("refuses a signer that returns a signature that does not verify", async () => {
        const good = new LocalKeySigner(crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey);
        const other = new LocalKeySigner(crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey);
        const liar: CaSigner = { algorithm: good.algorithm, spki: good.spki, sign: (d) => other.sign(d) };
        await expect(signChecked(liar, DATA)).rejects.toThrow(/does not verify/);
        await expect(signChecked(good, DATA)).resolves.toBeInstanceOf(Uint8Array);
    });
});

// --- OpenBao / Vault Transit ------------------------------------------------------------------------------------------

interface FakeBao {
    httpGet: OpenBaoHttpGet;
    httpPost: OpenBaoHttpPost;
    gets: Array<{ url: string; headers: Record<string, string> }>;
    posts: Array<{ url: string; body: Record<string, unknown>; headers: Record<string, string> }>;
    privateKey: crypto.KeyObject;
    spki: Uint8Array;
}

/** A Transit engine with one key (two versions; the signing key is version 2) that really signs. */
function fakeBao(kind: "ecdsa-p384" | "rsa-2048", override?: { signature?: (input: Buffer, version: number) => string }): FakeBao {
    const pair =
        kind === "rsa-2048"
            ? crypto.generateKeyPairSync("rsa", { modulusLength: 2048 })
            : crypto.generateKeyPairSync("ec", { namedCurve: "P-384" });
    const old =
        kind === "rsa-2048"
            ? crypto.generateKeyPairSync("rsa", { modulusLength: 2048 })
            : crypto.generateKeyPairSync("ec", { namedCurve: "P-384" });
    const pem = (k: crypto.KeyObject) => k.export({ type: "spki", format: "pem" });
    const gets: FakeBao["gets"] = [];
    const posts: FakeBao["posts"] = [];
    return {
        gets,
        posts,
        privateKey: pair.privateKey,
        spki: new Uint8Array(pair.publicKey.export({ type: "spki", format: "der" })),
        httpGet: async (url, headers) => {
            gets.push({ url, headers });
            return {
                status: 200,
                body: {
                    data: {
                        type: kind,
                        supports_signing: true,
                        latest_version: 2,
                        keys: { "1": { public_key: pem(old.publicKey) }, "2": { public_key: pem(pair.publicKey) } },
                    },
                },
            };
        },
        httpPost: async (url, body, headers) => {
            posts.push({ url, body: body as Record<string, unknown>, headers });
            const b = body as Record<string, unknown>;
            const input = Buffer.from(String(b.input), "base64");
            const version = Number(b.key_version);
            if (override?.signature) {
                return { status: 200, body: { data: { signature: override.signature(input, version) } } };
            }
            const hash = url.split("/").pop()!.replace("sha2-", "sha");
            const sig =
                kind === "rsa-2048"
                    ? crypto.sign(hash, input, { key: pair.privateKey, padding: crypto.constants.RSA_PKCS1_PADDING })
                    : crypto.sign(hash, input, { key: pair.privateKey, dsaEncoding: "der" });
            return { status: 200, body: { data: { signature: `vault:v${version}:${sig.toString("base64")}` } } };
        },
    };
}

describe("OpenBaoTransitSigner", () => {
    it("reads the public key of the latest version and signs through the sign endpoint (ECDSA, asn1 marshaling)", async () => {
        const bao = fakeBao("ecdsa-p384");
        const signer = await OpenBaoTransitSigner.create({
            url: "https://bao.test:8200/",
            keyName: "ca-r1",
            token: "s.token",
            httpGet: bao.httpGet,
            httpPost: bao.httpPost,
        });
        expect(bao.gets).toHaveLength(1);
        expect(bao.gets[0].url).toBe("https://bao.test:8200/v1/transit/keys/ca-r1");
        expect(bao.gets[0].headers["X-Vault-Token"]).toBe("s.token");
        expect(Buffer.from(signer.spki).equals(Buffer.from(bao.spki))).toBe(true);
        expect(signer.algorithm).toBe("ecdsa-with-SHA384");

        const sig = await signer.sign(DATA);
        expect(verifySignature(signer.algorithm, signer.spki, DATA, sig)).toBe(true);
        expect(bao.posts).toHaveLength(1);
        const post = bao.posts[0];
        expect(post.url).toBe("https://bao.test:8200/v1/transit/sign/ca-r1/sha2-384");
        expect(post.headers["X-Vault-Token"]).toBe("s.token");
        expect(post.body.marshaling_algorithm).toBe("asn1");
        expect(post.body.key_version).toBe(2); // pinned to the version whose public key was read
        expect(Buffer.from(String(post.body.input), "base64").equals(Buffer.from(DATA))).toBe(true);
        expect(post.body.signature_algorithm).toBeUndefined();
    });

    it("asks for PKCS #1 v1.5 for RSA keys (Transit defaults to PSS)", async () => {
        const bao = fakeBao("rsa-2048");
        const signer = await OpenBaoTransitSigner.create({
            url: "http://bao.test",
            keyName: "ca",
            token: "t",
            httpGet: bao.httpGet,
            httpPost: bao.httpPost,
        });
        expect(signer.algorithm).toBe("sha256WithRSAEncryption");
        const sig = await signer.sign(DATA);
        expect(verifySignature(signer.algorithm, signer.spki, DATA, sig)).toBe(true);
        expect(bao.posts[0].body.signature_algorithm).toBe("pkcs1v15");
        expect(bao.posts[0].url).toMatch(/\/sign\/ca\/sha2-256$/);
    });

    it("supports a custom mount, a hash override, a pinned key version and a token function", async () => {
        const bao = fakeBao("ecdsa-p384");
        let calls = 0;
        const signer = await OpenBaoTransitSigner.create({
            url: "https://bao.test",
            mount: "/secret/transit/",
            keyName: "my key/1",
            hash: "sha2-512",
            keyVersion: 1,
            token: async () => `tok${++calls}`,
            httpGet: bao.httpGet,
            httpPost: bao.httpPost,
        });
        // version 1 is the "old" key in the fake, whose public key differs from the private key that signs: the
        // signer must still refuse to hand out a signature that does not verify when used through signChecked
        expect(signer.algorithm).toBe("ecdsa-with-SHA512");
        expect(bao.gets[0].url).toBe("https://bao.test/v1/secret/transit/keys/my%20key%2F1");
        await signer.sign(DATA);
        expect(bao.posts[0].url).toBe("https://bao.test/v1/secret/transit/sign/my%20key%2F1/sha2-512");
        expect(bao.posts[0].headers["X-Vault-Token"]).toBe("tok2");
        expect(bao.posts[0].body.key_version).toBe(1);
        await expect(signChecked(signer, DATA)).rejects.toThrow(/does not verify/);
    });

    it("works as the signer of a real issuer: certificates verify with Node's X509Certificate", async () => {
        const bao = fakeBao("ecdsa-p384");
        const signer = await OpenBaoTransitSigner.create({
            url: "https://bao.test",
            keyName: "ca",
            token: "t",
            httpGet: bao.httpGet,
            httpPost: bao.httpPost,
        });
        const h = await makeHierarchy("ecdsa-p384");
        const { Issuer, buildCaCertificate } = await import("../../../src/lib/pki/index.js");
        const cert = await buildCaCertificate({
            subject: "CN=Remote CA",
            subjectSpki: signer.spki,
            issuer: h.rootIssuer,
            signer: h.rootSigner,
            notBefore: new Date(Date.now() - HOUR),
            notAfter: new Date(Date.now() + 365 * 86_400_000),
            pathLen: 0,
        });
        const issuer = new Issuer({ id: "remote", name: "Remote", certificate: cert.pem, chain: [h.rootCert.pem], signer, active: true });
        const subject = newSubjectKey("ec");
        const leaf = await issueLeafCertificate(issuer, URLS, {
            spki: subject.spki,
            email: "user@example.com",
            type: "signing",
            notBefore: new Date(Date.now() - HOUR),
            notAfter: new Date(Date.now() + 30 * 86_400_000),
        });
        const x = new crypto.X509Certificate(Buffer.from(leaf.der));
        expect(x.verify(crypto.createPublicKey({ key: Buffer.from(signer.spki), format: "der", type: "spki" }))).toBe(true);
        expect(bao.posts.length).toBeGreaterThan(0);
    });

    it("reports HTTP failures with the server's error text but never the token", async () => {
        const httpGet: OpenBaoHttpGet = async () => ({ status: 403, body: { errors: ["permission denied"] } });
        await expect(
            OpenBaoTransitSigner.create({ url: "https://bao.test", keyName: "k", token: "SECRET-TOKEN", httpGet })
        ).rejects.toThrow(/HTTP 403: permission denied/);

        const bao = fakeBao("ecdsa-p384");
        const signer = await OpenBaoTransitSigner.create({
            url: "https://bao.test",
            keyName: "k",
            token: "SECRET-TOKEN",
            httpGet: bao.httpGet,
            httpPost: async () => ({ status: 500, body: { errors: ["boom"] } }),
        });
        const err = await signer.sign(DATA).catch((e: Error) => e);
        expect((err as Error).message).toMatch(/HTTP 500: boom/);
        expect((err as Error).message).not.toContain("SECRET-TOKEN");
    });

    it("rejects malformed or mismatched signature responses", async () => {
        for (const signature of ["garbage", "vault:v9:AAAA", "vault:v2:not base64!", undefined]) {
            const bao = fakeBao("ecdsa-p384", { signature: () => signature as string });
            const signer = await OpenBaoTransitSigner.create({
                url: "https://bao.test",
                keyName: "k",
                token: "t",
                httpGet: bao.httpGet,
                httpPost: bao.httpPost,
            });
            await expect(signer.sign(DATA)).rejects.toThrow(/unexpected signature/);
        }
    });

    it("refuses key types that cannot sign certificates and missing keys", async () => {
        const ed: OpenBaoHttpGet = async () => ({ status: 200, body: { data: { type: "ed25519", keys: {}, latest_version: 1 } } });
        await expect(OpenBaoTransitSigner.create({ url: "https://b", keyName: "k", token: "t", httpGet: ed })).rejects.toThrow(
            /cannot sign certificates/
        );
        const noKey: OpenBaoHttpGet = async () => ({ status: 200, body: { data: { type: "ecdsa-p256", keys: {}, latest_version: 3 } } });
        await expect(OpenBaoTransitSigner.create({ url: "https://b", keyName: "k", token: "t", httpGet: noKey })).rejects.toThrow(
            /no public key for version 3/
        );
        await expect(OpenBaoTransitSigner.create({ url: "https://b", keyName: "k", token: "" })).rejects.toThrow();
    });

    it("uses fetch by default, sends the token as a header, and never follows redirects", async () => {
        const bao = fakeBao("ecdsa-p384");
        const seen: Array<{ url: string; init: RequestInit }> = [];
        const fakeFetch = (async (url: string, init: RequestInit) => {
            seen.push({ url, init });
            const headers = init.headers as Record<string, string>;
            const res =
                init.method === "GET"
                    ? await bao.httpGet(url, headers)
                    : await bao.httpPost(url, JSON.parse(String(init.body)), headers);
            return new Response(JSON.stringify(res.body), { status: res.status });
        }) as unknown as typeof fetch;
        const signer = await OpenBaoTransitSigner.create({ url: "https://bao.test", keyName: "k", token: "t", fetch: fakeFetch });
        await signer.sign(DATA);
        expect(seen).toHaveLength(2);
        for (const s of seen) {
            expect(s.init.redirect).toBe("error");
            expect(s.init.signal).toBeDefined();
            expect((s.init.headers as Record<string, string>)["X-Vault-Token"]).toBe("t");
        }
        expect((seen[1].init.headers as Record<string, string>)["content-type"]).toBe("application/json");
    });
});
