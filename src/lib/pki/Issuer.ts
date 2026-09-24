///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { x509 } from "./runtime.js";
import * as crypto from "node:crypto";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { certificateParts, keyIdentifierOf, spkiKeyBits } from "./certutil.js";
import { LocalKeySigner, OpenBaoTransitSigner, type CaSigner, type SignatureAlgorithm } from "./Signer.js";
import { OID } from "./oids.js";
import { bytesEqual, bytesToHex, derToPem, digest, pemBlocks, serialBytesToHex, sha256Hex, toArrayBuffer, toBytes } from "./util.js";

/** Public description of an issuer (`GET /ca`). */
export interface IssuerInfo {
    id: string;
    name: string;
    role: "root" | "intermediate";
    subject: string;
    /** Canonical lower-case hex serial. */
    serialNumber: string;
    /** ISO 8601. */
    notBefore: string;
    /** ISO 8601. */
    notAfter: string;
    /** Lower-case hex SHA-256 of the certificate DER. */
    sha256Fingerprint: string;
    /** Lower-case hex SHA-256 of the SubjectPublicKeyInfo DER. */
    spkiSha256: string;
    pem: string;
    /** Public key as a JWK (with `kid` = the issuer id, `use` = `sig` and the signature `alg`). */
    jwk: JsonWebKey & { kid: string; use: "sig"; alg: string };
}

/** Anything that can be turned into a certificate: an object, DER, or PEM text. */
export type CertificateInput = x509.X509Certificate | Uint8Array | string;

/** Constructor options of {@link Issuer}. */
export interface IssuerOptions {
    /** URL-safe identifier (`[a-z0-9][a-z0-9_-]{0,62}`); appears in `/crl/<id>.crl` and `/ca/<id>.crt`. */
    id: string;
    /** Display name. */
    name: string;
    /** The issuing CA certificate. */
    certificate: CertificateInput;
    /** The CAs above `certificate`, nearest first, root last. */
    chain?: CertificateInput[];
    /** Signs with the key that belongs to `certificate`. */
    signer: CaSigner;
    /** Whether this issuer signs new certificates (default false). */
    active?: boolean;
}

const ID_PATTERN = /^[a-z0-9][a-z0-9_-]{0,62}$/;

function toCertificate(input: CertificateInput): x509.X509Certificate {
    if (input instanceof x509.X509Certificate) {
        return input;
    }
    const der = typeof input === "string" ? pemBlocks(input).find((b) => b.label === "CERTIFICATE")?.der : input;
    if (!der) {
        throw new Error("No CERTIFICATE PEM block found");
    }
    return new x509.X509Certificate(toArrayBuffer(der));
}

function nodeCert(cert: x509.X509Certificate): crypto.X509Certificate {
    return new crypto.X509Certificate(Buffer.from(cert.rawData));
}

/** True when `child` verifiably names and is signed by `parent`. */
function isIssuedBy(child: x509.X509Certificate, parent: x509.X509Certificate): boolean {
    const c = nodeCert(child);
    const p = nodeCert(parent);
    return bytesEqual(certificateParts(toBytes(child.rawData)).issuer, certificateParts(toBytes(parent.rawData)).subject) && c.verify(p.publicKey);
}

/**
 * An issuing CA: its certificate, the chain above it and the signer that holds its key.
 *
 * Construction checks that everything fits together (the certificate is a CA that may sign certificates and CRLs, the
 * signer's public key is the certificate's, and each chain link really is signed by the next), so a wrong key file or a
 * mixed-up manifest is a start-up error and never a batch of unverifiable certificates.
 *
 * @author Jean-Philippe Steinmetz
 */
export class Issuer {
    public readonly id: string;
    public readonly name: string;
    public readonly certificate: x509.X509Certificate;
    /** CAs above `certificate`, nearest first, root last. */
    public readonly chain: x509.X509Certificate[];
    public readonly signer: CaSigner;
    public readonly active: boolean;
    /** The subjectKeyIdentifier of `certificate` (computed per RFC 5280 method 1 when the certificate has none). */
    public readonly keyId: Uint8Array;
    readonly #der: Uint8Array;
    readonly #parts: ReturnType<typeof certificateParts>;
    readonly #role: "root" | "intermediate";

    /**
     * @param o The issuer definition.
     * @throws Error when the parts are inconsistent.
     */
    public constructor(o: IssuerOptions) {
        if (!ID_PATTERN.test(o.id)) {
            throw new Error(`Invalid issuer id ${JSON.stringify(o.id)} (use lower-case letters, digits, '-' and '_')`);
        }
        if (typeof o.name !== "string" || o.name.length === 0 || o.name.length > 200) {
            throw new Error(`Issuer ${o.id}: a name is required`);
        }
        this.id = o.id;
        this.name = o.name;
        this.certificate = toCertificate(o.certificate);
        this.chain = (o.chain ?? []).map(toCertificate);
        this.signer = o.signer;
        this.active = o.active === true;
        this.#der = toBytes(this.certificate.rawData);
        this.#parts = certificateParts(this.#der);

        const bc = this.certificate.getExtension<x509.BasicConstraintsExtension>(OID.basicConstraints);
        if (!bc || !bc.ca) {
            throw new Error(`Issuer ${o.id}: the certificate is not a CA certificate (basicConstraints CA:TRUE)`);
        }
        const ku = this.certificate.getExtension<x509.KeyUsagesExtension>(OID.keyUsage);
        const required = x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign;
        if (ku && (ku.usages & required) !== required) {
            throw new Error(`Issuer ${o.id}: the certificate's keyUsage lacks keyCertSign and/or cRLSign`);
        }
        if (!bytesEqual(this.signer.spki, this.#parts.spki)) {
            throw new Error(`Issuer ${o.id}: the signing key does not match the issuer certificate's public key`);
        }
        const ski = this.certificate.getExtension<x509.SubjectKeyIdentifierExtension>(OID.subjectKeyIdentifier);
        this.keyId = ski ? new Uint8Array(Buffer.from(ski.keyId, "hex")) : keyIdentifierOf(this.#parts.spki);

        let child = this.certificate;
        for (const parent of this.chain) {
            if (!isIssuedBy(child, parent)) {
                throw new Error(`Issuer ${o.id}: the certificate chain is broken (${child.subject} is not issued by ${parent.subject})`);
            }
            child = parent;
        }
        this.#role = isIssuedBy(this.certificate, this.certificate) ? "root" : "intermediate";
    }

    /**
     * The SHA-1/SHA-2 hash of the issuer certificate's public key bits, as used in an OCSP CertID `issuerKeyHash`.
     *
     * @param algorithm The digest.
     */
    public keyHash(algorithm: "sha1" | "sha256" | "sha384" | "sha512" = "sha1"): Uint8Array {
        return digest(algorithm, spkiKeyBits(this.#parts.spki));
    }

    /**
     * The hash of the issuer certificate's subject Name (DER, as encoded in the certificate), as used in an OCSP CertID
     * `issuerNameHash`.
     *
     * @param algorithm The digest.
     */
    public nameHash(algorithm: "sha1" | "sha256" | "sha384" | "sha512" = "sha1"): Uint8Array {
        return digest(algorithm, this.#parts.subject);
    }

    /** DER of the subject Name exactly as it appears in the certificate (what leaf certificates must carry as issuer). */
    public get subjectDer(): Uint8Array {
        return this.#parts.subject.slice();
    }

    /** DER of the issuer certificate. */
    public get der(): Uint8Array {
        return this.#der.slice();
    }

    /** Describes the issuer for the public trust endpoints. */
    public info(): IssuerInfo {
        const jwk = crypto.createPublicKey({ key: Buffer.from(this.#parts.spki), format: "der", type: "spki" }).export({
            format: "jwk",
        });
        const algs: Record<SignatureAlgorithm, string> = {
            "ecdsa-with-SHA256": "ES256",
            "ecdsa-with-SHA384": "ES384",
            "ecdsa-with-SHA512": "ES512",
            sha256WithRSAEncryption: "RS256",
            sha384WithRSAEncryption: "RS384",
            sha512WithRSAEncryption: "RS512",
        };
        return {
            id: this.id,
            name: this.name,
            role: this.#role,
            subject: this.certificate.subject,
            serialNumber: serialBytesToHex(this.#parts.serial) ?? bytesToHex(this.#parts.serial),
            notBefore: this.certificate.notBefore.toISOString(),
            notAfter: this.certificate.notAfter.toISOString(),
            sha256Fingerprint: sha256Hex(this.#der),
            spkiSha256: sha256Hex(this.#parts.spki),
            pem: derToPem(this.#der, "CERTIFICATE"),
            jwk: { ...jwk, kid: this.id, use: "sig", alg: algs[this.signer.algorithm] },
        };
    }
}

/** How an issuer's key is reached, from the manifest. */
interface FileKeyEntry {
    type: "file";
    path: string;
    passphrase_env?: string;
}

interface OpenBaoKeyEntry {
    type: "openbao-transit";
    url: string;
    mount?: string;
    key_name: string;
    token_env?: string;
    token_file?: string;
    hash?: "sha2-256" | "sha2-384" | "sha2-512";
    key_version?: number;
}

interface ManifestEntry {
    id: string;
    name: string;
    certificate: string;
    chain?: string[];
    key: FileKeyEntry | OpenBaoKeyEntry;
    active?: boolean;
}

function isRecord(v: unknown): v is Record<string, unknown> {
    return v !== null && typeof v === "object" && !Array.isArray(v);
}

function requireString(v: unknown, what: string): string {
    if (typeof v !== "string" || v.length === 0) {
        throw new Error(`${what} must be a non-empty string`);
    }
    return v;
}

async function readFileClearly(file: string, what: string): Promise<Buffer> {
    try {
        return await fs.readFile(file);
    } catch (err) {
        const code = (err as NodeJS.ErrnoException).code;
        throw new Error(`Cannot read ${what} ${file}: ${code === "ENOENT" ? "file not found" : (err as Error).message}`);
    }
}

async function readCertificates(file: string, what: string): Promise<x509.X509Certificate[]> {
    const text = (await readFileClearly(file, what)).toString("utf8");
    const certs = pemBlocks(text).filter((b) => b.label === "CERTIFICATE");
    if (certs.length === 0) {
        throw new Error(`${what} ${file} contains no PEM certificate`);
    }
    return certs.map((b) => new x509.X509Certificate(toArrayBuffer(b.der)));
}

/**
 * The set of issuing CAs the service knows, exactly one of which is active.
 *
 * @author Jean-Philippe Steinmetz
 */
export class IssuerRegistry {
    readonly #issuers: Issuer[];

    private constructor(issuers: Issuer[]) {
        const seen = new Set<string>();
        for (const issuer of issuers) {
            if (seen.has(issuer.id)) {
                throw new Error(`Duplicate issuer id ${issuer.id}`);
            }
            seen.add(issuer.id);
        }
        this.#issuers = issuers.slice();
    }

    /**
     * Builds a registry from already-constructed issuers (tests, embedding).
     *
     * @param issuers The issuers; ids must be unique.
     */
    public static fromIssuers(issuers: Issuer[]): IssuerRegistry {
        return new IssuerRegistry(issuers);
    }

    /**
     * Loads `issuers.json` (see the architecture document). Relative paths resolve against the manifest's directory.
     * Fails with a message naming the offending issuer and file for: unreadable or malformed JSON, missing certificate or
     * key files, a wrong passphrase or a missing `passphrase_env` variable, a key that does not match its certificate, and
     * anything other than exactly one `"active": true` issuer.
     *
     * @param manifestPath The manifest file.
     * @param opts `env` for `passphrase_env`/`token_env` lookups (default `process.env`); `fetch` for OpenBao calls.
     */
    public static async fromManifest(
        manifestPath: string,
        opts?: { env?: NodeJS.ProcessEnv; fetch?: typeof fetch }
    ): Promise<IssuerRegistry> {
        const env = opts?.env ?? process.env;
        const dir = path.dirname(path.resolve(manifestPath));
        const resolve = (p: string) => path.resolve(dir, p);
        let raw: unknown;
        try {
            raw = JSON.parse((await readFileClearly(path.resolve(manifestPath), "issuer manifest")).toString("utf8"));
        } catch (err) {
            if ((err as Error).message.startsWith("Cannot read")) {
                throw err;
            }
            throw new Error(`Issuer manifest ${manifestPath} is not valid JSON: ${(err as Error).message}`);
        }
        if (!Array.isArray(raw) || raw.length === 0) {
            throw new Error(`Issuer manifest ${manifestPath} must be a non-empty JSON array`);
        }

        const issuers: Issuer[] = [];
        for (const item of raw) {
            const id = isRecord(item) && typeof item.id === "string" ? item.id : "?";
            try {
                if (!isRecord(item) || !isRecord(item.key)) {
                    throw new Error("each entry must be an object with a 'key' object");
                }
                const entry = item as unknown as ManifestEntry;
                if (entry.active !== undefined && typeof entry.active !== "boolean") {
                    throw new Error("'active' must be true or false");
                }
                if (entry.chain !== undefined && !Array.isArray(entry.chain)) {
                    throw new Error("'chain' must be an array of certificate paths");
                }
                const certificate = (await readCertificates(resolve(requireString(entry.certificate, "'certificate'")), "certificate"))[0];
                const chain: x509.X509Certificate[] = [];
                for (const p of entry.chain ?? []) {
                    chain.push(...(await readCertificates(resolve(requireString(p, "'chain' entries")), "chain certificate")));
                }
                let signer: CaSigner;
                if (entry.key.type === "file") {
                    const key = entry.key;
                    let passphrase: string | undefined;
                    if (key.passphrase_env !== undefined) {
                        passphrase = env[requireString(key.passphrase_env, "'passphrase_env'")];
                        if (!passphrase) {
                            throw new Error(`environment variable ${key.passphrase_env} (key passphrase) is not set`);
                        }
                    }
                    const pem = (await readFileClearly(resolve(requireString(key.path, "'key.path'")), "private key")).toString("utf8");
                    signer = LocalKeySigner.fromPem(pem, passphrase);
                } else if (entry.key.type === "openbao-transit") {
                    const key = entry.key;
                    let token: string | (() => Promise<string>);
                    if (key.token_env !== undefined) {
                        const value = env[requireString(key.token_env, "'token_env'")];
                        if (!value) {
                            throw new Error(`environment variable ${key.token_env} (OpenBao token) is not set`);
                        }
                        token = value;
                    } else if (key.token_file !== undefined) {
                        const file = resolve(requireString(key.token_file, "'token_file'"));
                        token = async () => (await readFileClearly(file, "OpenBao token file")).toString("utf8").trim();
                    } else {
                        throw new Error("an openbao-transit key needs 'token_env' or 'token_file'");
                    }
                    signer = await OpenBaoTransitSigner.create({
                        url: requireString(key.url, "'key.url'"),
                        mount: key.mount,
                        keyName: requireString(key.key_name, "'key.key_name'"),
                        token,
                        hash: key.hash,
                        keyVersion: key.key_version,
                        fetch: opts?.fetch,
                    });
                } else {
                    throw new Error(`unknown key type ${JSON.stringify((entry.key as { type?: unknown }).type)}`);
                }
                issuers.push(
                    new Issuer({
                        id: requireString(entry.id, "'id'"),
                        name: requireString(entry.name, "'name'"),
                        certificate,
                        chain,
                        signer,
                        active: entry.active === true,
                    })
                );
            } catch (err) {
                throw new Error(`Issuer manifest ${manifestPath}: issuer '${id}': ${(err as Error).message}`);
            }
        }
        const registry = new IssuerRegistry(issuers);
        const active = issuers.filter((i) => i.active).length;
        if (active !== 1) {
            throw new Error(`Issuer manifest ${manifestPath} must mark exactly one issuer "active": true (found ${active})`);
        }
        return registry;
    }

    /** Every issuer, in manifest order. */
    public all(): Issuer[] {
        return this.#issuers.slice();
    }

    /**
     * Looks an issuer up by id.
     *
     * @param id The issuer id.
     */
    public get(id: string): Issuer | undefined {
        return this.#issuers.find((i) => i.id === id);
    }

    /**
     * The issuer that signs new certificates.
     *
     * @throws Error unless exactly one issuer is active.
     */
    public active(): Issuer {
        const active = this.#issuers.filter((i) => i.active);
        if (active.length !== 1) {
            throw new Error(`Exactly one issuer must be active (found ${active.length})`);
        }
        return active[0];
    }

    /** The trust anchors: the top of every issuer's chain (the issuer itself when it has none), de-duplicated. */
    public roots(): x509.X509Certificate[] {
        const seen = new Set<string>();
        const roots: x509.X509Certificate[] = [];
        for (const issuer of this.#issuers) {
            const top = issuer.chain.length > 0 ? issuer.chain[issuer.chain.length - 1] : issuer.certificate;
            const fingerprint = sha256Hex(toBytes(top.rawData));
            if (!seen.has(fingerprint)) {
                seen.add(fingerprint);
                roots.push(top);
            }
        }
        return roots;
    }

    /**
     * Finds the issuer whose public key hashes to `issuerKeyHash` (OCSP CertID).
     *
     * @param algorithm The digest the hash was computed with.
     * @param issuerKeyHash The hash from the request.
     */
    public findByIssuerKeyHash(
        algorithm: "sha1" | "sha256" | "sha384" | "sha512",
        issuerKeyHash: Uint8Array
    ): Issuer | undefined {
        return this.#issuers.find((i) => bytesEqual(i.keyHash(algorithm), issuerKeyHash));
    }

    /**
     * Finds the issuer that a full OCSP CertID names: both the name hash and the key hash must match.
     *
     * @param algorithm The digest the hashes were computed with.
     * @param issuerNameHash The name hash from the request.
     * @param issuerKeyHash The key hash from the request.
     */
    public findByCertId(
        algorithm: "sha1" | "sha256" | "sha384" | "sha512",
        issuerNameHash: Uint8Array,
        issuerKeyHash: Uint8Array
    ): Issuer | undefined {
        return this.#issuers.find(
            (i) => bytesEqual(i.keyHash(algorithm), issuerKeyHash) && bytesEqual(i.nameHash(algorithm), issuerNameHash)
        );
    }
}

