///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import * as crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { derInteger, derOctetString, derOid, derSequence, derTlv } from "../../../src/lib/pki/der.js";
import {
    buildCaCertificate,
    Issuer,
    IssuerRegistry,
    LocalKeySigner,
    type IssuedCertificate,
    type IssuerUrls,
} from "../../../src/lib/pki/index.js";
import { concatBytes } from "../../../src/lib/pki/util.js";

export const HOUR = 3_600_000;
export const DAY = 24 * HOUR;

/** URLs written into leaf certificates in the tests. */
export const URLS: IssuerUrls = {
    crl: "https://acme.test/crl/smime-r1.crl",
    caIssuers: "https://acme.test/ca/smime-r1.crt",
    ocsp: "https://acme.test/ocsp",
};

export type Kind = "ecdsa-p256" | "ecdsa-p384" | "rsa-2048";

const SIGNER_KEYS = new WeakMap<object, crypto.KeyObject>();

/** A new local signer of the given kind (RSA 2048 for speed; production uses 3072+). */
export function newSigner(kind: Kind): LocalKeySigner {
    const privateKey =
        kind === "rsa-2048"
            ? crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey
            : crypto.generateKeyPairSync("ec", { namedCurve: kind === "ecdsa-p256" ? "P-256" : "P-384" }).privateKey;
    const signer = new LocalKeySigner(privateKey);
    SIGNER_KEYS.set(signer, privateKey);
    return signer;
}

/** The Node private key behind a signer made by {@link newSigner} (the production class deliberately has no getter). */
export function privateKeyOf(signer: object): crypto.KeyObject {
    const key = SIGNER_KEYS.get(signer);
    if (!key) throw new Error("test bug: signer was not made by newSigner()");
    return key;
}

/** PKCS #8 PEM of a {@link newSigner} key, optionally encrypted (Node's own PBES2, which is fine for tests). */
export function exportKey(signer: object, passphrase?: string): string {
    const key = privateKeyOf(signer);
    return (passphrase
        ? key.export({ type: "pkcs8", format: "pem", cipher: "aes-256-cbc", passphrase })
        : key.export({ type: "pkcs8", format: "pem" }));
}

/** DER SPKI of a Node public key. */
export function spkiOf(key: crypto.KeyObject): Uint8Array {
    return new Uint8Array(key.export({ type: "spki", format: "der" }));
}

/** A fresh subscriber key pair and its SPKI. */
export function newSubjectKey(kind: "rsa" | "ec" | "ec-p384" | "ec-p521"): {
    privateKey: crypto.KeyObject;
    spki: Uint8Array;
} {
    const pair =
        kind === "rsa"
            ? crypto.generateKeyPairSync("rsa", { modulusLength: 2048 })
            : crypto.generateKeyPairSync("ec", {
                  namedCurve: kind === "ec" ? "P-256" : kind === "ec-p384" ? "P-384" : "P-521",
              });
    return { privateKey: pair.privateKey, spki: spkiOf(pair.publicKey) };
}

export interface Hierarchy {
    rootCert: IssuedCertificate;
    rootSigner: LocalKeySigner;
    rootIssuer: Issuer;
    issuerCert: IssuedCertificate;
    issuerSigner: LocalKeySigner;
    issuer: Issuer;
    registry: IssuerRegistry;
}

/** A root and an issuing CA (pathLen 0, emailProtection), like ca-init makes. */
export async function makeHierarchy(kind: Kind = "ecdsa-p384", id = "smime-r1"): Promise<Hierarchy> {
    const now = Date.now();
    const rootSigner = newSigner(kind);
    const rootCert = await buildCaCertificate({
        subject: "CN=Test Root CA",
        subjectSpki: rootSigner.spki,
        signer: rootSigner,
        notBefore: new Date(now - HOUR),
        notAfter: new Date(now + 20 * 365 * DAY),
    });
    const rootIssuer = new Issuer({ id: "root", name: "Test Root", certificate: rootCert.pem, signer: rootSigner });
    const issuerSigner = newSigner(kind);
    const issuerCert = await buildCaCertificate({
        subject: "CN=Test S/MIME CA",
        subjectSpki: issuerSigner.spki,
        issuer: rootIssuer,
        signer: rootSigner,
        notBefore: new Date(now - HOUR),
        notAfter: new Date(now + 10 * 365 * DAY),
        pathLen: 0,
        ekuEmailProtection: true,
    });
    const issuer = new Issuer({
        id,
        name: "Test S/MIME CA",
        certificate: issuerCert.pem,
        chain: [rootCert.pem],
        signer: issuerSigner,
        active: true,
    });
    return {
        rootCert,
        rootSigner,
        rootIssuer,
        issuerCert,
        issuerSigner,
        issuer,
        registry: IssuerRegistry.fromIssuers([issuer]),
    };
}

// --- Hand-built CSRs ----------------------------------------------------------------------------------------------
// The tests build PKCS #10 requests byte by byte so that every malformed / unusual case (unsupported curves, odd
// extension combinations, non-email SAN types, ...) can be produced; WebCrypto-based generators cannot do that.

const OID_EXT_REQ = "1.2.840.113549.1.9.14";

function ext(oid: string, critical: boolean, value: Uint8Array): Uint8Array {
    return derSequence(derOid(oid), ...(critical ? [derTlv(0x01, Uint8Array.of(0xff))] : []), derOctetString(value));
}

/** A SAN general name. */
export type SanName = { email: string } | { dns: string } | { uri: string } | { ip: Uint8Array } | { raw: Uint8Array };

function generalName(n: SanName): Uint8Array {
    if ("email" in n) return derTlv(0x81, new Uint8Array(Buffer.from(n.email, "latin1")));
    if ("dns" in n) return derTlv(0x82, new Uint8Array(Buffer.from(n.dns, "latin1")));
    if ("uri" in n) return derTlv(0x86, new Uint8Array(Buffer.from(n.uri, "latin1")));
    if ("ip" in n) return derTlv(0x87, n.ip);
    return n.raw;
}

export function sanExtension(names: SanName[]): Uint8Array {
    return ext("2.5.29.17", false, derSequence(...names.map(generalName)));
}

/** A KeyUsage extension value from a bit mask using RFC 5280 numbering (digitalSignature = bit 0 = 0x01 here). */
export function keyUsageExtension(mask: number, critical = true): Uint8Array {
    // Bit i of the mask (LSB first) is named bit i; DER puts bit 0 in the MSB of the first octet.
    const bits = new Uint8Array(2);
    for (let i = 0; i < 9; i++) {
        if (mask & (1 << i)) bits[i >> 3] |= 0x80 >> (i & 7);
    }
    let len = 2;
    while (len > 0 && bits[len - 1] === 0) len--;
    let unused = 0;
    if (len > 0) {
        while (((bits[len - 1] >> unused) & 1) === 0) unused++;
    }
    return ext("2.5.29.15", critical, derTlv(0x03, concatBytes(Uint8Array.of(unused), bits.subarray(0, len))));
}

export function basicConstraintsExtension(ca: boolean): Uint8Array {
    return ext("2.5.29.19", true, derSequence(...(ca ? [derTlv(0x01, Uint8Array.of(0xff))] : [])));
}

export function ekuExtension(oids: string[]): Uint8Array {
    return ext("2.5.29.37", false, derSequence(...oids.map(derOid)));
}

export interface CsrOptions {
    /** Private key that signs the request (and whose public key is requested, unless `spki` is given). */
    privateKey: crypto.KeyObject;
    /** Overrides the SPKI placed in the request (e.g. a key that cannot sign). */
    spki?: Uint8Array;
    /** Extensions to request, already encoded. Omit for a request without an extensionRequest attribute. */
    extensions?: Uint8Array[];
    /** Number of extensionRequest attributes to emit (default 1 when there are extensions). */
    attributeCopies?: number;
    /** Digest for the signature (default sha256). */
    hash?: "sha1" | "sha256" | "sha384" | "sha512";
    /** Flip a bit in the signature. */
    corruptSignature?: boolean;
    /** Subject CN (ignored by the CA; default "ignored"). */
    subjectCn?: string;
}

const SIG_OIDS: Record<string, { ec: string; rsa: string }> = {
    sha1: { ec: "1.2.840.10045.4.1", rsa: "1.2.840.113549.1.1.5" },
    sha256: { ec: "1.2.840.10045.4.3.2", rsa: "1.2.840.113549.1.1.11" },
    sha384: { ec: "1.2.840.10045.4.3.3", rsa: "1.2.840.113549.1.1.12" },
    sha512: { ec: "1.2.840.10045.4.3.4", rsa: "1.2.840.113549.1.1.13" },
};

/** Builds a signed PKCS #10 CertificationRequest (DER). */
export function buildCsr(o: CsrOptions): Uint8Array {
    const spki = o.spki ?? new Uint8Array(crypto.createPublicKey(o.privateKey).export({ type: "spki", format: "der" }));
    const attribute = derSequence(derOid(OID_EXT_REQ), derTlv(0x31, derSequence(...(o.extensions ?? []))));
    const copies = o.extensions ? (o.attributeCopies ?? 1) : 0;
    const attributes = derTlv(0xa0, concatBytes(...Array.from({ length: copies }, () => attribute)));
    const cn = derSequence(
        derTlv(0x31, derSequence(derOid("2.5.4.3"), derTlv(0x0c, new Uint8Array(Buffer.from(o.subjectCn ?? "ignored")))))
    );
    const info = derSequence(derInteger(0n), cn, spki, attributes);
    const hash = o.hash ?? "sha256";
    const isRsa = o.privateKey.asymmetricKeyType === "rsa";
    const signature = new Uint8Array(
        crypto.sign(hash, info, isRsa ? o.privateKey : { key: o.privateKey, dsaEncoding: "der" })
    );
    if (o.corruptSignature) {
        signature[signature.length - 1] ^= 0x01;
    }
    const sigAlg = derSequence(
        derOid(isRsa ? SIG_OIDS[hash].rsa : SIG_OIDS[hash].ec),
        ...(isRsa ? [Uint8Array.of(0x05, 0x00)] : [])
    );
    return derSequence(info, sigAlg, derTlv(0x03, concatBytes(Uint8Array.of(0), signature)));
}

/** PEM form of a DER CSR. */
export function csrPem(der: Uint8Array): string {
    const b64 = Buffer.from(der).toString("base64").match(/.{1,64}/g)!.join("\n");
    return `-----BEGIN CERTIFICATE REQUEST-----\n${b64}\n-----END CERTIFICATE REQUEST-----\n`;
}

/** SPKI DER of an RSA public key given as modulus and exponent (no key validity checks are made by Node). */
export function rsaSpkiFrom(n: bigint, e: bigint): Uint8Array {
    const b64u = (v: bigint) => {
        let hex = v.toString(16);
        if (hex.length % 2) hex = "0" + hex;
        return Buffer.from(hex, "hex").toString("base64url");
    };
    const key = crypto.createPublicKey({ key: { kty: "RSA", n: b64u(n), e: b64u(e) }, format: "jwk" });
    return spkiOf(key);
}

// --- openssl (optional interop checks) -------------------------------------------------------------------------------

/** Runs `openssl`; returns `undefined` when the binary is not on PATH. */
export function openssl(args: string[], input?: Buffer): { status: number; stdout: string; stderr: string } | undefined {
    const r = spawnSync("openssl", args, { input, encoding: "utf8" });
    if (r.error) {
        return undefined;
    }
    return { status: r.status ?? -1, stdout: r.stdout, stderr: r.stderr };
}

/** True when an openssl binary is available. */
export const hasOpenssl = openssl(["version"]) !== undefined;

/** Creates a temp directory that the caller removes. */
export function tempDir(prefix = "pki-test-"): string {
    return mkdtempSync(join(tmpdir(), prefix));
}

/** Writes a file into a directory and returns its path. */
export function put(dir: string, name: string, data: string | Uint8Array): string {
    const file = join(dir, name);
    writeFileSync(file, data);
    return file;
}

export { rmSync };
