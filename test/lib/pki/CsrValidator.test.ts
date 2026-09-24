///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import "reflect-metadata";
import * as x509 from "@peculiar/x509";
import * as crypto from "node:crypto";
import {
    PkiPolicyError,
    checkPublicKey,
    derToPem,
    resolveCertificateType,
    sha256Hex,
    validateCsr,
    type CertificateType,
} from "../../../src/lib/pki/index.js";
import { derOctetString, derOid, derSequence, derTlv } from "../../../src/lib/pki/der.js";
import {
    basicConstraintsExtension,
    buildCsr,
    csrPem,
    ekuExtension,
    keyUsageExtension,
    newSubjectKey,
    rsaSpkiFrom,
    sanExtension,
    spkiOf,
} from "./helpers.js";

x509.cryptoProvider.set(globalThis.crypto);

const DS = 0x01; // digitalSignature
const NR = 0x02; // nonRepudiation
const KE = 0x04; // keyEncipherment
const DE = 0x08; // dataEncipherment
const KA = 0x10; // keyAgreement
const KCS = 0x20; // keyCertSign
const CRLS = 0x40; // cRLSign
const EO = 0x80; // encipherOnly
const DO = 0x100; // decipherOnly

/** Asserts that a promise rejects with a PkiPolicyError of the given code. */
async function expectPolicy(promise: Promise<unknown>, code: "badCSR" | "badPublicKey", message?: RegExp): Promise<void> {
    const err = await promise.then(
        () => undefined,
        (e) => e
    );
    expect(err).toBeInstanceOf(PkiPolicyError);
    expect((err as PkiPolicyError).code).toBe(code);
    if (message) {
        expect((err as Error).message).toMatch(message);
    }
}

function expectPolicySync(fn: () => unknown, code: "badCSR" | "badPublicKey", message?: RegExp): void {
    let err: unknown;
    try {
        fn();
    } catch (e) {
        err = e;
    }
    expect(err).toBeInstanceOf(PkiPolicyError);
    expect((err as PkiPolicyError).code).toBe(code);
    if (message) {
        expect((err as Error).message).toMatch(message);
    }
}

// --- big number helpers for crafting RSA moduli ------------------------------------------------------------------------

const bitLength = (n: bigint) => n.toString(2).length;
const smallPrimes: bigint[] = [];
for (let i = 2; i < 752; i++) {
    if (smallPrimes.every((p) => BigInt(i) % p !== 0n)) smallPrimes.push(BigInt(i));
}
const hasSmallFactor = (n: bigint) => smallPrimes.some((p) => n % p === 0n);

/** A random integer of exactly `bits` bits (top bit set). */
function randomBits(bits: number): bigint {
    const bytes = crypto.randomBytes(Math.ceil(bits / 8));
    let n = BigInt("0x" + bytes.toString("hex")) & ((1n << BigInt(bits)) - 1n);
    n |= 1n << BigInt(bits - 1);
    return n;
}

/** A random odd `bits`-bit integer with no prime factor below 752 (not necessarily prime). */
function randomCleanOdd(bits: number): bigint {
    for (;;) {
        const n = randomBits(bits) | 1n;
        if (!hasSmallFactor(n)) return n;
    }
}

const E = 65537n;

describe("PkiPolicyError", () => {
    it("is an Error carrying the ACME problem code", () => {
        const e = new PkiPolicyError("badCSR", "nope");
        expect(e).toBeInstanceOf(Error);
        expect(e.name).toBe("PkiPolicyError");
        expect(e.code).toBe("badCSR");
        expect(e.message).toBe("nope");
    });
});

describe("checkPublicKey", () => {
    describe("accepted keys", () => {
        it.each([
            ["ec", "ECDSA P-256"],
            ["ec-p384", "ECDSA P-384"],
            ["ec-p521", "ECDSA P-521"],
        ] as const)("accepts %s", (kind, description) => {
            expect(checkPublicKey(newSubjectKey(kind).spki)).toEqual({ keyKind: "ec", description });
        });

        it.each([2048, 3072, 4096])("accepts a real RSA %i key", (bits) => {
            const { publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: bits });
            expect(checkPublicKey(spkiOf(publicKey))).toEqual({ keyKind: "rsa", description: `RSA ${bits}` });
        });

        it("accepts moduli whose length is any multiple of 8 bits within range, and 8192 bits", () => {
            expect(checkPublicKey(rsaSpkiFrom(randomCleanOdd(2056), E)).description).toBe("RSA 2056");
            expect(checkPublicKey(rsaSpkiFrom(randomCleanOdd(8192), E)).description).toBe("RSA 8192");
        }, 30_000);

        it("accepts a modulus divisible by 757, the first prime above the 752 bound", () => {
            for (;;) {
                const n = 757n * randomBits(2038) * 1n;
                if (bitLength(n) === 2048 && (n & 1n) === 1n && !smallPrimes.filter((p) => p !== 757n).some((p) => n % p === 0n) && n % 757n === 0n) {
                    // 757 is above the bound, so only the *other* small primes matter; the modulus is not a perfect power
                    expect(checkPublicKey(rsaSpkiFrom(n, E)).keyKind).toBe("rsa");
                    return;
                }
            }
        }, 30_000);

        it("accepts a public exponent of 65537 and larger odd exponents", () => {
            const n = randomCleanOdd(2048);
            expect(checkPublicKey(rsaSpkiFrom(n, 65537n)).keyKind).toBe("rsa");
            expect(checkPublicKey(rsaSpkiFrom(n, 65539n)).keyKind).toBe("rsa");
        });
    });

    describe("RSA modulus and exponent rules (CA/B Forum BR 6.1.1.3)", () => {
        it("rejects keys shorter than 2048 bits and longer than 8192 bits", () => {
            const weak = crypto.generateKeyPairSync("rsa", { modulusLength: 1024 }).publicKey;
            expectPolicySync(() => checkPublicKey(spkiOf(weak)), "badPublicKey", /2048 to 8192/);
            expectPolicySync(() => checkPublicKey(rsaSpkiFrom(randomCleanOdd(2040), E)), "badPublicKey", /2048 to 8192/);
            expectPolicySync(() => checkPublicKey(rsaSpkiFrom(randomCleanOdd(8200), E)), "badPublicKey", /2048 to 8192/);
        });

        it("rejects a modulus whose bit length is not a multiple of 8", () => {
            expectPolicySync(() => checkPublicKey(rsaSpkiFrom(randomCleanOdd(2049), E)), "badPublicKey", /multiple of 8/);
            expectPolicySync(() => checkPublicKey(rsaSpkiFrom(randomCleanOdd(3071), E)), "badPublicKey", /multiple of 8/);
        });

        it("rejects an even modulus", () => {
            expectPolicySync(() => checkPublicKey(rsaSpkiFrom(randomBits(2048) & ~1n, E)), "badPublicKey", /odd/);
        });

        it.each([3n, 751n, 5n * 7n])("rejects a modulus with a small prime factor (multiple of %s)", (factor) => {
            for (;;) {
                const n = randomBits(2048) | 1n;
                // force divisibility by `factor` while keeping 2048 bits and oddness
                const adjusted = n - (n % factor);
                if (bitLength(adjusted) === 2048 && (adjusted & 1n) === 1n) {
                    expectPolicySync(() => checkPublicKey(rsaSpkiFrom(adjusted, E)), "badPublicKey", /small prime factor/);
                    return;
                }
            }
        });

        it("rejects a perfect square and a perfect cube (prime powers)", () => {
            for (;;) {
                const p = randomCleanOdd(1024) | (3n << 1022n);
                if (hasSmallFactor(p)) continue;
                expectPolicySync(() => checkPublicKey(rsaSpkiFrom(p * p, E)), "badPublicKey", /perfect power/);
                break;
            }
            for (;;) {
                const p = randomCleanOdd(683);
                const n = p * p * p;
                if (bitLength(n) !== 2048) continue;
                expectPolicySync(() => checkPublicKey(rsaSpkiFrom(n, E)), "badPublicKey", /perfect power/);
                break;
            }
        });

        it.each([
            ["3", 3n],
            ["an even exponent (65536)", 65536n],
            ["65535", 65535n],
            ["2^256 + 1", (1n << 256n) + 1n],
        ])("rejects the public exponent %s", (_name, e) => {
            expectPolicySync(() => checkPublicKey(rsaSpkiFrom(randomCleanOdd(2048), e)), "badPublicKey");
        });

        it("rejects a modulus with the ROCA (CVE-2017-15361) structure but accepts ordinary keys", () => {
            // Infineon's flawed generator makes primes p = k*M + (65537^a mod M) with M a primorial.
            const primes = smallPrimes.filter((p) => p <= 353n);
            const M = primes.reduce((a, b) => a * b, 1n);
            const modPow = (b: bigint, e: bigint, m: bigint) => {
                let r = 1n;
                b %= m;
                while (e > 0n) {
                    if (e & 1n) r = (r * b) % m;
                    b = (b * b) % m;
                    e >>= 1n;
                }
                return r;
            };
            const rocaPrime = () => {
                const r = modPow(65537n, randomBits(64), M);
                const kMin = (3n << 1022n) / M + 1n;
                const kMax = ((1n << 1024n) - 1n - r) / M;
                let k = kMin + (randomBits(500) % (kMax - kMin));
                for (;;) {
                    const p = k * M + r;
                    if (bitLength(p) === 1024 && crypto.checkPrimeSync(p, { checks: 8 })) return p;
                    k++;
                }
            };
            const n = rocaPrime() * rocaPrime();
            expect(bitLength(n)).toBe(2048);
            expectPolicySync(() => checkPublicKey(rsaSpkiFrom(n, E)), "badPublicKey", /ROCA/);
        }, 60_000);
    });

    describe("elliptic curves", () => {
        it.each(["prime192v1", "secp256k1", "brainpoolP256r1", "secp224r1"])("rejects curve %s", (namedCurve) => {
            const { publicKey } = crypto.generateKeyPairSync("ec", { namedCurve });
            expectPolicySync(() => checkPublicKey(spkiOf(publicKey)), "badPublicKey", /curve/);
        });

        it("rejects explicit curve parameters and compressed points (non-canonical encodings)", () => {
            const explicit = crypto.generateKeyPairSync("ec", { namedCurve: "P-256", paramEncoding: "explicit" }).publicKey;
            expectPolicySync(() => checkPublicKey(spkiOf(explicit)), "badPublicKey");

            const { publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
            const jwk = publicKey.export({ format: "jwk" });
            const y = Buffer.from(jwk.y!, "base64url");
            const x = Buffer.from(jwk.x!, "base64url");
            const compressed = Buffer.concat([Buffer.from([0x00, y[y.length - 1] & 1 ? 0x03 : 0x02]), x]);
            const spki = derSequence(
                derSequence(derOid("1.2.840.10045.2.1"), derOid("1.2.840.10045.3.1.7")),
                derTlv(0x03, compressed)
            );
            // the compressed encoding is a valid key...
            expect(crypto.createPublicKey({ key: Buffer.from(spki), format: "der", type: "spki" }).asymmetricKeyType).toBe("ec");
            // ...but is not what will be copied into a certificate
            expectPolicySync(() => checkPublicKey(spki), "badPublicKey", /canonical/);
        });

        it("rejects a point that is not on the curve", () => {
            const { publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
            const spki = spkiOf(publicKey);
            spki[spki.length - 1] ^= 0x01; // move y: no longer on the curve
            expectPolicySync(() => checkPublicKey(spki), "badPublicKey");
        });
    });

    describe("other key types and encodings", () => {
        it.each([
            ["Ed25519", () => crypto.generateKeyPairSync("ed25519").publicKey],
            ["X25519", () => crypto.generateKeyPairSync("x25519").publicKey],
            ["RSA-PSS", () => crypto.generateKeyPairSync("rsa-pss", { modulusLength: 2048 }).publicKey],
            ["DSA", () => crypto.generateKeyPairSync("dsa", { modulusLength: 2048, divisorLength: 256 }).publicKey],
        ])("rejects %s", (_name, make) => {
            expectPolicySync(() => checkPublicKey(spkiOf(make())), "badPublicKey");
        });

        it("rejects garbage, empty input and trailing data", () => {
            expectPolicySync(() => checkPublicKey(new Uint8Array()), "badPublicKey");
            expectPolicySync(() => checkPublicKey(new Uint8Array(64).fill(7)), "badPublicKey");
            expectPolicySync(() => checkPublicKey(new Uint8Array(4096)), "badPublicKey");
            const spki = newSubjectKey("ec").spki;
            expectPolicySync(() => checkPublicKey(Buffer.concat([spki, Buffer.from([0])])), "badPublicKey");
            expectPolicySync(() => checkPublicKey("nope" as unknown as Uint8Array), "badPublicKey");
        });
    });
});

describe("resolveCertificateType", () => {
    const S: CertificateType = "signing";
    const ENC: CertificateType = "encryption";
    const B: CertificateType = "signing-encryption";

    it.each<[CertificateType | undefined, CertificateType | undefined, CertificateType | "badCSR"]>([
        // CSR without a KeyUsage request: the profile decides, else both
        [undefined, undefined, B],
        [undefined, S, S],
        [undefined, ENC, ENC],
        [undefined, B, B],
        // no profile: the CSR decides
        [S, undefined, S],
        [ENC, undefined, ENC],
        [B, undefined, B],
        // profile is a ceiling: equal is fine, narrower CSR under the broad profile is fine
        [S, S, S],
        [ENC, ENC, ENC],
        [B, B, B],
        [S, B, S],
        [ENC, B, ENC],
        // contradictions
        [S, ENC, "badCSR"],
        [ENC, S, "badCSR"],
        [B, S, "badCSR"],
        [B, ENC, "badCSR"],
    ])("requested=%s profile=%s -> %s", (requested, profile, expected) => {
        if (expected === "badCSR") {
            expectPolicySync(() => resolveCertificateType(requested, profile), "badCSR", /contradicts/);
        } else {
            expect(resolveCertificateType(requested, profile)).toBe(expected);
        }
    });

    it("rejects values that are not certificate types", () => {
        expectPolicySync(() => resolveCertificateType("server" as CertificateType, undefined), "badCSR");
        expectPolicySync(() => resolveCertificateType(undefined, "server" as CertificateType), "badCSR");
    });
});

describe("validateCsr", () => {
    const rsa = newSubjectKey("rsa");
    const ec = newSubjectKey("ec");
    const email = (address: string) => sanExtension([{ email: address }]);
    const build = (o: Partial<Parameters<typeof buildCsr>[0]> & { key?: ReturnType<typeof newSubjectKey> } = {}) => {
        const key = o.key ?? ec;
        return buildCsr({ privateKey: key.privateKey, extensions: [email("alice@example.com")], ...o });
    };

    describe("valid requests", () => {
        it.each([
            ["RSA 2048", rsa, "rsa", "RSA 2048"],
            ["ECDSA P-256", ec, "ec", "ECDSA P-256"],
            ["ECDSA P-384", newSubjectKey("ec-p384"), "ec", "ECDSA P-384"],
            ["ECDSA P-521", newSubjectKey("ec-p521"), "ec", "ECDSA P-521"],
        ] as const)("accepts a %s request and returns only the validated facts", async (_name, key, kind, description) => {
            const der = build({ key });
            const v = await validateCsr(der);
            expect(v.keyKind).toBe(kind);
            expect(v.keyDescription).toBe(description);
            expect(v.emails).toEqual(["alice@example.com"]);
            expect(v.requestedType).toBeUndefined();
            expect(Buffer.from(v.spki).equals(Buffer.from(key.spki))).toBe(true);
            expect(v.spkiSha256).toBe(sha256Hex(key.spki));
        });

        it.each(["sha256", "sha384", "sha512"] as const)("accepts %s signatures", async (hash) => {
            await expect(validateCsr(build({ hash }))).resolves.toBeDefined();
            await expect(validateCsr(build({ key: rsa, hash }))).resolves.toBeDefined();
        });

        it("accepts a request generated by @peculiar/x509 (RSA and ECDSA), as a real client would send it", async () => {
            for (const alg of [
                { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 },
                { name: "ECDSA", hash: "SHA-256", namedCurve: "P-256" },
            ] as const) {
                const keys = (await globalThis.crypto.subtle.generateKey(alg as never, true, ["sign", "verify"]));
                const csr = await x509.Pkcs10CertificateRequestGenerator.create({
                    name: "CN=whatever",
                    keys,
                    signingAlgorithm: alg,
                    extensions: [
                        new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.nonRepudiation),
                        new x509.SubjectAlternativeNameExtension([{ type: "email", value: "Peculiar@Example.ORG" }]),
                    ],
                });
                const v = await validateCsr(csr.toString("pem"));
                expect(v.emails).toEqual(["Peculiar@example.org"]);
                expect(v.requestedType).toBe("signing");
                expect(v.keyKind).toBe(alg.name === "ECDSA" ? "ec" : "rsa");
            }
        });

        it("ignores the subject, an EKU request and unknown extensions: none of it can reach the certificate", async () => {
            const der = buildCsr({
                privateKey: ec.privateKey,
                subjectCn: "CN=admin, O=Evil",
                extensions: [
                    email("alice@example.com"),
                    ekuExtension(["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.4"]),
                    basicConstraintsExtension(false),
                    derSequence(derOid("1.2.3.4.5"), derOctetString(Uint8Array.of(5, 0))), // unknown extension
                ],
            });
            const v = await validateCsr(der);
            expect(v.emails).toEqual(["alice@example.com"]);
            expect(Object.keys(v).sort()).toEqual(["emails", "keyDescription", "keyKind", "requestedType", "spki", "spkiSha256"]);
        });

        it("lower-cases only the domain, keeps order and removes duplicates", async () => {
            const der = buildCsr({
                privateKey: ec.privateKey,
                extensions: [sanExtension([{ email: "B@Example.COM" }, { email: "a@example.com" }, { email: "B@example.com" }, { email: "b@example.com" }])],
            });
            expect((await validateCsr(der)).emails).toEqual(["B@example.com", "a@example.com", "b@example.com"]);
        });
    });

    describe("input encodings", () => {
        const der = build();

        it("accepts DER bytes (Uint8Array and Buffer)", async () => {
            expect((await validateCsr(der)).emails).toEqual(["alice@example.com"]);
            expect((await validateCsr(Buffer.from(der))).emails).toEqual(["alice@example.com"]);
        });

        it("accepts PEM (also NEW CERTIFICATE REQUEST, CRLF and surrounding whitespace)", async () => {
            expect((await validateCsr(csrPem(der))).emails).toHaveLength(1);
            expect((await validateCsr(`\n  ${csrPem(der).replace(/\n/g, "\r\n")}  \n`)).emails).toHaveLength(1);
            expect((await validateCsr(derToPem(der, "NEW CERTIFICATE REQUEST"))).emails).toHaveLength(1);
        });

        it("accepts unpadded base64url DER (the ACME finalize encoding)", async () => {
            expect((await validateCsr(Buffer.from(der).toString("base64url"))).emails).toEqual(["alice@example.com"]);
        });

        it.each([
            ["padded base64url", () => Buffer.from(der).toString("base64") + "="],
            ["standard base64 alphabet", () => Buffer.from(build({ key: rsa })).toString("base64")],
            ["a PEM with the wrong label", () => derToPem(der, "CERTIFICATE")],
            ["two PEM blocks", () => csrPem(der) + csrPem(der)],
            ["an empty string", () => ""],
            ["garbage", () => "definitely not a CSR"],
            ["valid base64url that is not a CSR", () => Buffer.from("hello world, this is not DER").toString("base64url")],
        ])("rejects %s", async (_n, make) => {
            await expectPolicy(validateCsr(make()), "badCSR");
        });

        it("rejects empty, truncated, oversized, trailing-data and non-byte input", async () => {
            await expectPolicy(validateCsr(new Uint8Array()), "badCSR");
            await expectPolicy(validateCsr(der.slice(0, der.length - 5)), "badCSR");
            await expectPolicy(validateCsr(Buffer.concat([der, Buffer.from([0x00])])), "badCSR", /trailing/);
            await expectPolicy(validateCsr(new Uint8Array(40_000).fill(0x30)), "badCSR", /size/);
            await expectPolicy(validateCsr(123 as unknown as string), "badCSR");
        });
    });

    describe("proof of possession and signature algorithm", () => {
        it("rejects a corrupted signature (RSA and ECDSA)", async () => {
            await expectPolicy(validateCsr(build({ corruptSignature: true })), "badCSR", /signature/);
            await expectPolicy(validateCsr(build({ key: rsa, corruptSignature: true })), "badCSR", /signature/);
        });

        it("rejects a request whose public key was swapped after signing", async () => {
            const other = newSubjectKey("ec");
            // sign with `ec` but announce `other`'s public key: the signature cannot verify with it
            await expectPolicy(validateCsr(build({ spki: other.spki })), "badCSR", /signature/);
        });

        it("rejects SHA-1 signatures", async () => {
            await expectPolicy(validateCsr(build({ hash: "sha1" })), "badCSR", /algorithm/);
            await expectPolicy(validateCsr(build({ key: rsa, hash: "sha1" })), "badCSR", /algorithm/);
        });

        it("reports weak keys as badPublicKey even when the request itself is well signed", async () => {
            const weak = crypto.generateKeyPairSync("rsa", { modulusLength: 1024 });
            await expectPolicy(validateCsr(buildCsr({ privateKey: weak.privateKey, extensions: [email("a@example.com")] })), "badPublicKey", /2048/);
            for (const namedCurve of ["prime192v1", "secp256k1"]) {
                const { privateKey } = crypto.generateKeyPairSync("ec", { namedCurve });
                await expectPolicy(validateCsr(buildCsr({ privateKey, extensions: [email("a@example.com")] })), "badPublicKey", /curve/);
            }
        });
    });

    describe("subjectAltName", () => {
        it.each([
            ["no extensions at all", undefined],
            ["extensions but no SAN", [keyUsageExtension(DS)]],
            ["an empty SAN", [sanExtension([])]],
        ])("rejects a request with %s", async (_n, extensions) => {
            await expectPolicy(validateCsr(buildCsr({ privateKey: ec.privateKey, extensions })), "badCSR");
        });

        it.each([
            ["only a dNSName", [{ dns: "example.com" }], /only rfc822Name and SmtpUTF8Mailbox/],
            ["an e-mail plus a dNSName", [{ email: "a@example.com" }, { dns: "example.com" }], /only rfc822Name/],
            ["an e-mail plus a URI", [{ email: "a@example.com" }, { uri: "https://example.com/" }], /only rfc822Name/],
            ["an e-mail plus an IP address", [{ email: "a@example.com" }, { ip: Uint8Array.of(127, 0, 0, 1) }], /only rfc822Name/],
            ["an otherName (UPN)", [{ email: "a@example.com" }, { raw: derTlv(0xa0, Buffer.concat([derOid("1.3.6.1.4.1.311.20.2.3"), derTlv(0xa0, derTlv(0x0c, Buffer.from("a@example.com")))])) }], /only rfc822Name/],
        ] as const)("rejects %s", async (_n, names, message) => {
            await expectPolicy(validateCsr(buildCsr({ privateKey: ec.privateKey, extensions: [sanExtension([...names] as never)] })), "badCSR", message);
        });

        it.each([
            "not an address",
            "alice@localhost",
            "\"quoted\"@example.com",
            "a@example.com, b@example.com",
            "alice@[127.0.0.1]",
        ])("rejects the address %s", async (address) => {
            await expectPolicy(validateCsr(buildCsr({ privateKey: ec.privateKey, extensions: [email(address)] })), "badCSR", /e-mail address/);
        });

        describe("internationalized addresses (RFC 8398 / 8399)", () => {
            /** An SmtpUTF8Mailbox otherName: [0] { OID 1.3.6.1.5.5.7.8.9, [0] UTF8String }. */
            const utf8Mailbox = (address: string) =>
                ({ raw: derTlv(0xa0, Buffer.concat([derOid("1.3.6.1.5.5.7.8.9"), derTlv(0xa0, derTlv(0x0c, Buffer.from(address, "utf8")))])) }) as const;

            it("accepts an SmtpUTF8Mailbox and reports it as local@A-label-domain", async () => {
                const result = await validateCsr(buildCsr({ privateKey: ec.privateKey, extensions: [sanExtension([utf8Mailbox("用户@bücher.example.com")] as never)] }));
                expect(result.emails).toEqual(["用户@xn--bcher-kva.example.com"]);
            });

            it("accepts an rfc822Name whose domain is an IDN in either spelling, canonicalized to A-labels", async () => {
                const a = await validateCsr(buildCsr({ privateKey: ec.privateKey, extensions: [email("alice@xn--bcher-kva.example.com")] }));
                expect(a.emails).toEqual(["alice@xn--bcher-kva.example.com"]);
            });

            it("treats the same mailbox given as rfc822Name and as SmtpUTF8Mailbox as one", async () => {
                const result = await validateCsr(
                    buildCsr({ privateKey: ec.privateKey, extensions: [sanExtension([utf8Mailbox("ålice@example.com"), utf8Mailbox("ålice@EXAMPLE.com")] as never)] }),
                );
                expect(result.emails).toEqual(["ålice@example.com"]);
            });

            it.each([
                ["a decomposed (non-NFC) local part", "ålice@example.com"],
                ["a control character", "alice@example.com"],
                ["a zero-width character", "al​ice@example.com"],
                ["a right-to-left override", "al‮ice@example.com"],
                ["a space", "al ice@example.com"],
                ["a compatibility-mapped (full-width) domain", "ålice@ｅxample.com"],
                ["an invalid Punycode label", "ålice@xn--a.example.com"],
                ["a local part over 64 octets", `${"é".repeat(33)}@example.com`],
            ])("rejects an SmtpUTF8Mailbox with %s", async (_name, address) => {
                await expectPolicy(validateCsr(buildCsr({ privateKey: ec.privateKey, extensions: [sanExtension([utf8Mailbox(address)] as never)] })), "badCSR", /e-mail address/);
            });

            it("rejects an SmtpUTF8Mailbox whose value is not a UTF8String", async () => {
                const bad = { raw: derTlv(0xa0, Buffer.concat([derOid("1.3.6.1.5.5.7.8.9"), derTlv(0xa0, derTlv(0x16, Buffer.from("ålice@example.com", "latin1")))])) } as const;
                await expectPolicy(validateCsr(buildCsr({ privateKey: ec.privateKey, extensions: [sanExtension([bad] as never)] })), "badCSR", /e-mail address/);
            });
        });

        it("rejects two SAN extensions and two extensionRequest attributes", async () => {
            await expectPolicy(
                validateCsr(buildCsr({ privateKey: ec.privateKey, extensions: [email("a@example.com"), email("b@example.com")] })),
                "badCSR"
            );
            await expectPolicy(validateCsr(build({ attributeCopies: 2 })), "badCSR", /more than one/);
        });

        it("rejects an absurd number of addresses", async () => {
            const many = Array.from({ length: 101 }, (_v, i) => ({ email: `u${i}@example.com` }));
            await expectPolicy(validateCsr(buildCsr({ privateKey: ec.privateKey, extensions: [sanExtension(many)] })), "badCSR", /too many/);
            const fine = Array.from({ length: 100 }, (_v, i) => ({ email: `u${i}@example.com` }));
            expect((await validateCsr(buildCsr({ privateKey: ec.privateKey, extensions: [sanExtension(fine)] }))).emails).toHaveLength(100);
        });
    });

    describe("basicConstraints", () => {
        it("rejects a request for a CA certificate and accepts an explicit CA:FALSE", async () => {
            await expectPolicy(validateCsr(build({ extensions: [email("a@example.com"), basicConstraintsExtension(true)] })), "badCSR", /CA/);
            await expect(validateCsr(build({ extensions: [email("a@example.com"), basicConstraintsExtension(false)] }))).resolves.toBeDefined();
        });
    });

    describe("KeyUsage -> certificate type (RFC 8823 s3.3)", () => {
        const withKu = (key: ReturnType<typeof newSubjectKey>, mask: number) =>
            buildCsr({ privateKey: key.privateKey, extensions: [email("a@example.com"), keyUsageExtension(mask)] });

        it.each<[string, number, CertificateType | "badCSR"]>([
            ["digitalSignature", DS, "signing"],
            ["nonRepudiation", NR, "signing"],
            ["digitalSignature+nonRepudiation", DS | NR, "signing"],
            ["keyEncipherment", KE, "encryption"],
            ["digitalSignature+keyEncipherment", DS | KE, "signing-encryption"],
            ["nonRepudiation+keyEncipherment", NR | KE, "signing-encryption"],
            ["all three", DS | NR | KE, "signing-encryption"],
            ["keyAgreement (RSA cannot agree)", KA, "badCSR"],
            ["keyEncipherment+keyAgreement", KE | KA, "badCSR"],
            ["dataEncipherment", DE, "badCSR"],
            ["digitalSignature+dataEncipherment", DS | DE, "badCSR"],
            ["keyCertSign", KCS, "badCSR"],
            ["digitalSignature+cRLSign", DS | CRLS, "badCSR"],
            ["encipherOnly", EO, "badCSR"],
            ["decipherOnly", DO, "badCSR"],
            ["digitalSignature+keyCertSign+cRLSign", DS | KCS | CRLS, "badCSR"],
        ])("RSA %s -> %s", async (_name, mask, expected) => {
            if (expected === "badCSR") {
                await expectPolicy(validateCsr(withKu(rsa, mask)), "badCSR", /keyUsage/);
            } else {
                expect((await validateCsr(withKu(rsa, mask))).requestedType).toBe(expected);
            }
        });

        it.each<[string, number, CertificateType | "badCSR"]>([
            ["digitalSignature", DS, "signing"],
            ["digitalSignature+nonRepudiation", DS | NR, "signing"],
            ["keyAgreement", KA, "encryption"],
            ["digitalSignature+keyAgreement", DS | KA, "signing-encryption"],
            ["all three", DS | NR | KA, "signing-encryption"],
            ["keyEncipherment (EC cannot encipher)", KE, "badCSR"],
            ["digitalSignature+keyEncipherment", DS | KE, "badCSR"],
            ["keyCertSign", KCS, "badCSR"],
            ["encipherOnly", EO, "badCSR"],
        ])("EC %s -> %s", async (_name, mask, expected) => {
            if (expected === "badCSR") {
                await expectPolicy(validateCsr(withKu(ec, mask)), "badCSR", /keyUsage/);
            } else {
                expect((await validateCsr(withKu(ec, mask))).requestedType).toBe(expected);
            }
        });

        it("rejects an empty KeyUsage and a repeated KeyUsage extension; accepts a non-critical one", async () => {
            await expectPolicy(validateCsr(withKu(ec, 0)), "badCSR");
            await expectPolicy(
                validateCsr(buildCsr({ privateKey: ec.privateKey, extensions: [email("a@example.com"), keyUsageExtension(DS), keyUsageExtension(KA)] })),
                "badCSR",
                /more than one keyUsage/
            );
            const lenient = buildCsr({ privateKey: ec.privateKey, extensions: [email("a@example.com"), keyUsageExtension(DS, false)] });
            expect((await validateCsr(lenient)).requestedType).toBe("signing");
        });

        it("feeds resolveCertificateType: a signing CSR under the encryption profile is a badCSR", async () => {
            const v = await validateCsr(withKu(ec, DS));
            expectPolicySync(() => resolveCertificateType(v.requestedType, "encryption"), "badCSR");
            expect(resolveCertificateType(v.requestedType, "signing-encryption")).toBe("signing");
        });
    });

    describe("forbiddenSpkiSha256", () => {
        it("refuses a key on the list (account key, revoked-for-keyCompromise key) with badPublicKey", async () => {
            const der = build();
            const digest = sha256Hex(ec.spki);
            await expectPolicy(validateCsr(der, { forbiddenSpkiSha256: [digest] }), "badPublicKey", /may not be used/);
            await expectPolicy(validateCsr(der, { forbiddenSpkiSha256: new Set(["00", digest.toUpperCase()]) }), "badPublicKey");
            await expectPolicy(
                validateCsr(der, {
                    forbiddenSpkiSha256: (function* () {
                        yield "ff".repeat(32);
                        yield digest;
                    })(),
                }),
                "badPublicKey"
            );
        });

        it("accepts a key that is not on the list", async () => {
            await expect(validateCsr(build(), { forbiddenSpkiSha256: [sha256Hex(rsa.spki), "zz"] })).resolves.toBeDefined();
            await expect(validateCsr(build(), { forbiddenSpkiSha256: [] })).resolves.toBeDefined();
            await expect(validateCsr(build(), {})).resolves.toBeDefined();
        });
    });
});
