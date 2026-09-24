///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import "./runtime.js";
import * as crypto from "node:crypto";
import { AlgorithmIdentifier } from "@peculiar/asn1-x509";
import { derInteger, derNull, derOctetString, derOid, derSequence } from "./der.js";
import { OID } from "./oids.js";
import { concatBytes, derToPem, toArrayBuffer } from "./util.js";

/** Signature algorithms a CA key may use (X.509 `signatureAlgorithm` names). */
export type SignatureAlgorithm =
    | "ecdsa-with-SHA256"
    | "ecdsa-with-SHA384"
    | "ecdsa-with-SHA512"
    | "sha256WithRSAEncryption"
    | "sha384WithRSAEncryption"
    | "sha512WithRSAEncryption";

/**
 * The single seam through which a CA private key is used. Certificates, CRLs and OCSP responses are all assembled as
 * DER `TBS` structures and handed to `sign()`, so the key may live in this process ({@link LocalKeySigner}) or in an
 * HSM-like remote service ({@link OpenBaoTransitSigner}) without any other code caring.
 */
export interface CaSigner {
    /** The signature algorithm written into every artefact this signer signs. */
    readonly algorithm: SignatureAlgorithm;
    /** DER SubjectPublicKeyInfo of the signing key. */
    readonly spki: Uint8Array;
    /**
     * Signs data.
     *
     * @param data The DER-encoded to-be-signed structure.
     * @returns An X.509-style signature: ECDSA as a DER `SEQUENCE { r, s }`, RSA as PKCS #1 v1.5.
     */
    sign(data: Uint8Array): Promise<Uint8Array>;
}

/** The kinds of key {@link LocalKeySigner.generate} can create. */
export type GeneratedKeyKind = "ecdsa-p256" | "ecdsa-p384" | "rsa-3072" | "rsa-4096";

type Digest = "sha256" | "sha384" | "sha512";

const ALGORITHMS: Record<SignatureAlgorithm, { oid: string; hash: Digest; rsa: boolean }> = {
    "ecdsa-with-SHA256": { oid: OID.ecdsaWithSHA256, hash: "sha256", rsa: false },
    "ecdsa-with-SHA384": { oid: OID.ecdsaWithSHA384, hash: "sha384", rsa: false },
    "ecdsa-with-SHA512": { oid: OID.ecdsaWithSHA512, hash: "sha512", rsa: false },
    sha256WithRSAEncryption: { oid: OID.sha256WithRSAEncryption, hash: "sha256", rsa: true },
    sha384WithRSAEncryption: { oid: OID.sha384WithRSAEncryption, hash: "sha384", rsa: true },
    sha512WithRSAEncryption: { oid: OID.sha512WithRSAEncryption, hash: "sha512", rsa: true },
};

/**
 * The `AlgorithmIdentifier` for a signature algorithm, encoded as RFC 5758 (ECDSA: parameters absent) and RFC 8017
 * (RSA: explicit NULL) require. Clients that compare the outer and inner identifiers byte for byte depend on this.
 *
 * @param algorithm The algorithm.
 */
export function signatureAlgorithmIdentifier(algorithm: SignatureAlgorithm): AlgorithmIdentifier {
    const info = ALGORITHMS[algorithm];
    if (!info) {
        throw new Error(`Unsupported signature algorithm ${String(algorithm)}`);
    }
    return new AlgorithmIdentifier({
        algorithm: info.oid,
        parameters: info.rsa ? toArrayBuffer(derNull()) : undefined,
    });
}

/**
 * The digest a signature algorithm hashes with.
 *
 * @param algorithm The algorithm.
 */
export function signatureHash(algorithm: SignatureAlgorithm): Digest {
    return ALGORITHMS[algorithm].hash;
}

/**
 * True when the algorithm is an RSA (PKCS #1 v1.5) one.
 *
 * @param algorithm The algorithm.
 */
export function isRsaSignatureAlgorithm(algorithm: SignatureAlgorithm): boolean {
    return ALGORITHMS[algorithm].rsa;
}

const CURVE_DIGEST: Record<string, Digest> = { prime256v1: "sha256", secp384r1: "sha384", secp521r1: "sha512" };

/**
 * Chooses the signature algorithm for a CA key: ECDSA uses the digest matching the curve size (P-384 -> SHA-384, the
 * default hierarchy), RSA uses SHA-256 below 3072 bits and SHA-384 from there on. Also the place where keys this
 * library refuses to sign with (small RSA, other curves, EdDSA, RSA-PSS-restricted keys) are turned away.
 *
 * @param publicKey The CA's public key.
 * @param digest Overrides the digest; must be a SHA-2 hash.
 */
function chooseAlgorithm(publicKey: crypto.KeyObject, digest?: Digest): SignatureAlgorithm {
    const details = publicKey.asymmetricKeyDetails;
    if (publicKey.asymmetricKeyType === "ec") {
        const auto = CURVE_DIGEST[details?.namedCurve ?? ""];
        if (!auto) {
            throw new Error(`Unsupported CA key curve ${details?.namedCurve}`);
        }
        const d = digest ?? auto;
        return `ecdsa-with-SHA${d.slice(3)}` as SignatureAlgorithm;
    }
    if (publicKey.asymmetricKeyType === "rsa") {
        const bits = details?.modulusLength ?? 0;
        if (bits < 2048 || bits > 8192) {
            throw new Error(`Unsupported CA RSA key size ${bits}`);
        }
        const d = digest ?? (bits < 3072 ? "sha256" : "sha384");
        return `sha${d.slice(3)}WithRSAEncryption` as SignatureAlgorithm;
    }
    throw new Error(`Unsupported CA key type ${publicKey.asymmetricKeyType}`);
}

/**
 * Verifies an X.509-style signature with a DER SubjectPublicKeyInfo.
 *
 * @param algorithm The signature algorithm.
 * @param spki The signer's public key.
 * @param data The signed bytes.
 * @param signature The signature.
 * @returns True only when the signature is valid.
 */
export function verifySignature(
    algorithm: SignatureAlgorithm,
    spki: Uint8Array,
    data: Uint8Array,
    signature: Uint8Array
): boolean {
    const info = ALGORITHMS[algorithm];
    const key = crypto.createPublicKey({ key: Buffer.from(spki), format: "der", type: "spki" });
    if (info.rsa) {
        return crypto.verify(info.hash, data, { key, padding: crypto.constants.RSA_PKCS1_PADDING }, signature);
    }
    return crypto.verify(info.hash, data, { key, dsaEncoding: "der" }, signature);
}

/**
 * Signs through a {@link CaSigner} and immediately verifies the result with the signer's own public key. A CA that
 * emitted a certificate, CRL or OCSP response with a bad signature (misconfigured remote key, a hash mismatch, a
 * faulty computation) would only find out when a relying party rejects it; this makes the failure happen at issuance.
 *
 * @param signer The signer.
 * @param data The DER TBS structure.
 * @throws Error when the signer returns a signature that does not verify.
 */
export async function signChecked(signer: CaSigner, data: Uint8Array): Promise<Uint8Array> {
    const signature = await signer.sign(data);
    if (!verifySignature(signer.algorithm, signer.spki, data, signature)) {
        throw new Error("The CA signer returned a signature that does not verify against its own public key");
    }
    return signature;
}

/**
 * Encrypts a PKCS #8 private key with a passphrase as PKCS #8 EncryptedPrivateKeyInfo using PBES2 with
 * PBKDF2-HMAC-SHA-256 (600 000 iterations, the OWASP guidance) and AES-256-CBC. Node's own `export({cipher})` writes
 * the same structure with 2 048 iterations, which is far too cheap to brute force for a CA key at rest.
 *
 * @param pkcs8 The unencrypted PKCS #8 DER.
 * @param passphrase A non-empty passphrase.
 */
function encryptPkcs8(pkcs8: Uint8Array, passphrase: string): Uint8Array {
    if (typeof passphrase !== "string" || passphrase.length === 0) {
        throw new Error("The key passphrase must not be empty");
    }
    const iterations = 600_000;
    const salt = crypto.randomBytes(16);
    const iv = crypto.randomBytes(16);
    const key = crypto.pbkdf2Sync(passphrase, salt, iterations, 32, "sha256");
    const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
    const encrypted = concatBytes(new Uint8Array(cipher.update(pkcs8)), new Uint8Array(cipher.final()));
    const kdf = derSequence(
        derOid(OID.pbkdf2),
        derSequence(
            derOctetString(new Uint8Array(salt)),
            derInteger(BigInt(iterations)),
            derSequence(derOid(OID.hmacWithSHA256), derNull())
        )
    );
    const scheme = derSequence(derOid(OID.aes256Cbc), derOctetString(new Uint8Array(iv)));
    return derSequence(derSequence(derOid(OID.pbes2), derSequence(kdf, scheme)), derOctetString(encrypted));
}

/**
 * A CA key held in this process as a Node `KeyObject`. Used for development, tests and file-based deployments; a
 * production root must never live on the same host (see the offline-root guidance in the architecture document).
 *
 * @author Jean-Philippe Steinmetz
 */
export class LocalKeySigner implements CaSigner {
    public readonly algorithm: SignatureAlgorithm;
    public readonly spki: Uint8Array;
    readonly #privateKey: crypto.KeyObject;

    /**
     * @param privateKey The private key. RSA 2048-8192 bits or ECDSA P-256/P-384/P-521.
     * @param digest Overrides the default digest for the key.
     */
    public constructor(privateKey: crypto.KeyObject, digest?: Digest) {
        if (privateKey.type !== "private") {
            throw new Error("LocalKeySigner needs a private key");
        }
        const publicKey = crypto.createPublicKey(privateKey);
        this.algorithm = chooseAlgorithm(publicKey, digest);
        this.spki = new Uint8Array(publicKey.export({ type: "spki", format: "der" }));
        this.#privateKey = privateKey;
    }

    /**
     * Loads a PKCS #8 (or traditional) PEM private key.
     *
     * @param pem The PEM text.
     * @param passphrase Required when the key is encrypted.
     * @throws Error with a readable message when the key cannot be loaded; the key material is never echoed.
     */
    public static fromPem(pem: string, passphrase?: string): LocalKeySigner {
        if (passphrase === undefined && /ENCRYPTED/.test(pem.slice(0, 200))) {
            throw new Error("The private key is encrypted and no passphrase was supplied");
        }
        let key: crypto.KeyObject;
        try {
            key = crypto.createPrivateKey(
                passphrase === undefined ? { key: pem, format: "pem" } : { key: pem, format: "pem", passphrase }
            );
        } catch (err) {
            const code = (err as { code?: string }).code;
            if (code === "ERR_MISSING_PASSPHRASE") {
                throw new Error("The private key is encrypted and no passphrase was supplied");
            }
            if (passphrase !== undefined) {
                throw new Error("The private key could not be decrypted (wrong passphrase?) or is not a valid PEM key");
            }
            throw new Error("The private key is not a valid PEM key");
        }
        return new LocalKeySigner(key);
    }

    /**
     * Generates a new key.
     *
     * @param kind The key type and size.
     * @returns The signer plus a function that exports the private key as PKCS #8 PEM (encrypted when a passphrase is supplied).
     */
    public static async generate(
        kind: GeneratedKeyKind
    ): Promise<{ signer: LocalKeySigner; privateKeyPem: (passphrase?: string) => string }> {
        let privateKey: crypto.KeyObject;
        if (kind === "ecdsa-p256" || kind === "ecdsa-p384") {
            const namedCurve = kind === "ecdsa-p256" ? "P-256" : "P-384";
            privateKey = await new Promise<crypto.KeyObject>((resolve, reject) =>
                crypto.generateKeyPair("ec", { namedCurve }, (err, _pub, priv) => (err ? reject(err) : resolve(priv)))
            );
        } else if (kind === "rsa-3072" || kind === "rsa-4096") {
            const modulusLength = kind === "rsa-3072" ? 3072 : 4096;
            privateKey = await new Promise<crypto.KeyObject>((resolve, reject) =>
                crypto.generateKeyPair("rsa", { modulusLength, publicExponent: 65537 }, (err, _pub, priv) =>
                    err ? reject(err) : resolve(priv)
                )
            );
        } else {
            throw new Error(`Unsupported key kind ${String(kind)}`);
        }
        return {
            signer: new LocalKeySigner(privateKey),
            privateKeyPem: (passphrase?: string) => {
                const pkcs8 = new Uint8Array(privateKey.export({ type: "pkcs8", format: "der" }));
                return passphrase === undefined
                    ? derToPem(pkcs8, "PRIVATE KEY")
                    : derToPem(encryptPkcs8(pkcs8, passphrase), "ENCRYPTED PRIVATE KEY");
            },
        };
    }

    /** @inheritdoc */
    public sign(data: Uint8Array): Promise<Uint8Array> {
        const info = ALGORITHMS[this.algorithm];
        const options: crypto.SignKeyObjectInput = info.rsa
            ? { key: this.#privateKey, padding: crypto.constants.RSA_PKCS1_PADDING }
            : { key: this.#privateKey, dsaEncoding: "der" };
        return new Promise((resolve, reject) =>
            crypto.sign(info.hash, data, options, (err, signature) =>
                err ? reject(err) : resolve(new Uint8Array(signature))
            )
        );
    }
}

/** A response from an injected HTTP function. */
export interface OpenBaoHttpResponse {
    /** The HTTP status code. */
    status: number;
    /** The parsed JSON body, or `undefined` when there was none / it was not JSON. */
    body: unknown;
}

/** POSTs JSON. Injected for tests; the default uses `fetch`. */
export type OpenBaoHttpPost = (
    url: string,
    body: unknown,
    headers: Record<string, string>
) => Promise<OpenBaoHttpResponse>;

/** GETs JSON. Injected for tests; the default uses `fetch`. */
export type OpenBaoHttpGet = (url: string, headers: Record<string, string>) => Promise<OpenBaoHttpResponse>;

/** Options of {@link OpenBaoTransitSigner}. */
export interface OpenBaoTransitOptions {
    /** Base URL of the OpenBao/Vault server, e.g. `https://bao.internal:8200`. */
    url: string;
    /** Mount path of the Transit engine (default `transit`). */
    mount?: string;
    /** Name of the Transit key. */
    keyName: string;
    /** A token, or a function returning the current one (for short-lived tokens/rotation). Sent as `X-Vault-Token`. */
    token: string | (() => Promise<string>);
    /** Digest; defaults from the key (P-256 -> sha2-256, P-384 -> sha2-384, RSA < 3072 -> sha2-256, else sha2-384). */
    hash?: "sha2-256" | "sha2-384" | "sha2-512";
    /** Pins a key version (default: the latest at creation time). Signatures always name it explicitly. */
    keyVersion?: number;
    /** Injected POST (tests). */
    httpPost?: OpenBaoHttpPost;
    /** Injected GET (tests). */
    httpGet?: OpenBaoHttpGet;
    /** `fetch` used by the default HTTP functions. */
    fetch?: typeof fetch;
    /** Per-request timeout of the default HTTP functions, in milliseconds (default 10 000). */
    timeoutMs?: number;
}

const BAO_HASH: Record<"sha2-256" | "sha2-384" | "sha2-512", Digest> = {
    "sha2-256": "sha256",
    "sha2-384": "sha384",
    "sha2-512": "sha512",
};

function defaultHttp(o: OpenBaoTransitOptions): { post: OpenBaoHttpPost; get: OpenBaoHttpGet } {
    const doFetch = o.fetch ?? globalThis.fetch;
    const timeout = o.timeoutMs ?? 10_000;
    const run = async (url: string, init: RequestInit): Promise<OpenBaoHttpResponse> => {
        // A redirect would re-send the X-Vault-Token header to wherever the response points; never follow one.
        const res = await doFetch(url, { ...init, redirect: "error", signal: AbortSignal.timeout(timeout) });
        let body: unknown;
        try {
            body = await res.json();
        } catch {
            body = undefined;
        }
        return { status: res.status, body };
    };
    return {
        post: (url, body, headers) =>
            run(url, {
                method: "POST",
                headers: { ...headers, "content-type": "application/json" },
                body: JSON.stringify(body),
            }),
        get: (url, headers) => run(url, { method: "GET", headers }),
    };
}

function record(value: unknown): Record<string, unknown> | undefined {
    return value !== null && typeof value === "object" ? (value as Record<string, unknown>) : undefined;
}

function baoError(what: string, res: OpenBaoHttpResponse): Error {
    const errors = record(res.body)?.errors;
    const detail = Array.isArray(errors) ? errors.map((e) => String(e)).join("; ").slice(0, 200) : "";
    return new Error(`OpenBao ${what} failed with HTTP ${res.status}${detail ? `: ${detail}` : ""}`);
}

/**
 * A CA key that never leaves an OpenBao / HashiCorp Vault Transit engine: every `sign()` is a
 * `POST /v1/<mount>/sign/<key>/<hash>` with `marshaling_algorithm=asn1` (so ECDSA comes back as a DER SEQUENCE, the
 * X.509 form) and, for RSA, `signature_algorithm=pkcs1v15` (Transit defaults to PSS, which no certificate here
 * uses). Signatures pin the key version whose public key was read at creation, so a later Transit key rotation cannot
 * make this issuer sign with a key that does not match its certificate.
 *
 * @author Jean-Philippe Steinmetz
 */
export class OpenBaoTransitSigner implements CaSigner {
    public readonly algorithm: SignatureAlgorithm;
    public readonly spki: Uint8Array;
    readonly #base: string;
    readonly #mount: string;
    readonly #keyName: string;
    readonly #token: string | (() => Promise<string>);
    readonly #hash: "sha2-256" | "sha2-384" | "sha2-512";
    readonly #keyVersion: number;
    readonly #rsa: boolean;
    readonly #post: OpenBaoHttpPost;

    /**
     * Prefer {@link OpenBaoTransitSigner.create}, which discovers the public key and version. The constructor is for
     * callers that already know them.
     *
     * @param o The options plus the key's DER SubjectPublicKeyInfo and the key version it belongs to.
     */
    public constructor(o: OpenBaoTransitOptions & { spki: Uint8Array; keyVersion: number }) {
        if (!o.url || !o.keyName || !o.token) {
            throw new Error("OpenBao transit signer needs url, keyName and token");
        }
        const publicKey = crypto.createPublicKey({ key: Buffer.from(o.spki), format: "der", type: "spki" });
        const digest = o.hash ? BAO_HASH[o.hash] : undefined;
        if (o.hash && !digest) {
            throw new Error(`Unsupported OpenBao hash ${String(o.hash)}`);
        }
        this.algorithm = chooseAlgorithm(publicKey, digest);
        this.#rsa = publicKey.asymmetricKeyType === "rsa";
        this.#hash = (Object.keys(BAO_HASH) as Array<keyof typeof BAO_HASH>).find(
            (k) => BAO_HASH[k] === ALGORITHMS[this.algorithm].hash
        )!;
        this.spki = new Uint8Array(o.spki);
        this.#base = o.url.replace(/\/+$/, "");
        this.#mount = (o.mount ?? "transit")
            .split("/")
            .filter((s) => s.length > 0)
            .map(encodeURIComponent)
            .join("/");
        this.#keyName = encodeURIComponent(o.keyName);
        this.#token = o.token;
        this.#keyVersion = o.keyVersion;
        this.#post = o.httpPost ?? defaultHttp(o).post;
    }

    /**
     * Reads the Transit key's public key (`GET /v1/<mount>/keys/<name>`) and creates the signer.
     *
     * @param o The options.
     * @throws Error when the key cannot be read, cannot sign, or is not an ECDSA/RSA key.
     */
    public static async create(o: OpenBaoTransitOptions): Promise<OpenBaoTransitSigner> {
        const get = o.httpGet ?? defaultHttp(o).get;
        const mount = (o.mount ?? "transit")
            .split("/")
            .filter((s) => s.length > 0)
            .map(encodeURIComponent)
            .join("/");
        const url = `${o.url.replace(/\/+$/, "")}/v1/${mount}/keys/${encodeURIComponent(o.keyName)}`;
        const token = typeof o.token === "function" ? await o.token() : o.token;
        if (!token) {
            throw new Error("OpenBao token is empty");
        }
        const res = await get(url, { "X-Vault-Token": token });
        if (res.status !== 200) {
            throw baoError("key lookup", res);
        }
        const data = record(record(res.body)?.data);
        const type = String(data?.type ?? "");
        if (!/^(ecdsa-p(256|384|521)|rsa-(2048|3072|4096))$/.test(type)) {
            throw new Error(`OpenBao transit key type '${type}' cannot sign certificates (need ecdsa-* or rsa-*)`);
        }
        if (data?.supports_signing === false) {
            throw new Error("The OpenBao transit key does not support signing");
        }
        const latest = Number(data?.latest_version);
        const version = o.keyVersion ?? latest;
        const keys = record(data?.keys);
        const entry = record(keys?.[String(version)]);
        if (!Number.isInteger(version) || version < 1 || typeof entry?.public_key !== "string") {
            throw new Error(`OpenBao transit key has no public key for version ${String(version)}`);
        }
        const publicKey = crypto.createPublicKey(entry.public_key);
        const spki = new Uint8Array(publicKey.export({ type: "spki", format: "der" }));
        return new OpenBaoTransitSigner({ ...o, spki, keyVersion: version });
    }

    /** @inheritdoc */
    public async sign(data: Uint8Array): Promise<Uint8Array> {
        const token = typeof this.#token === "function" ? await this.#token() : this.#token;
        if (!token) {
            throw new Error("OpenBao token is empty");
        }
        const body: Record<string, unknown> = {
            input: Buffer.from(data).toString("base64"),
            marshaling_algorithm: "asn1",
            key_version: this.#keyVersion,
        };
        if (this.#rsa) {
            body.signature_algorithm = "pkcs1v15";
        }
        const url = `${this.#base}/v1/${this.#mount}/sign/${this.#keyName}/${this.#hash}`;
        const res = await this.#post(url, body, { "X-Vault-Token": token });
        if (res.status !== 200) {
            throw baoError("sign request", res);
        }
        const signature = record(record(res.body)?.data)?.signature;
        const m = typeof signature === "string" ? /^vault:v(\d+):([A-Za-z0-9+/]+={0,2})$/.exec(signature) : null;
        if (!m || Number(m[1]) !== this.#keyVersion) {
            throw new Error("OpenBao returned an unexpected signature (wrong format or key version)");
        }
        return new Uint8Array(Buffer.from(m[2], "base64"));
    }
}
