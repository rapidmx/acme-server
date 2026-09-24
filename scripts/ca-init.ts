///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import {
    buildCaCertificate,
    Issuer,
    LocalKeySigner,
    pemBlocks,
    sha256Hex,
    type GeneratedKeyKind,
    type IssuedCertificate,
} from "../src/lib/pki/index.js";

/**
 * `yarn ca:init`: creates the RapidMX S/MIME CA hierarchy (an offline root and an issuing CA) and the `issuers.json`
 * manifest the service loads (see docs/ARCHITECTURE.md, "Issuers"). Everything is built with the same library code the
 * service uses (`buildCaCertificate`, `LocalKeySigner`).
 *
 * Typical production use:
 *
 * 1. on an offline machine, create the root: `ca:init --root-only --dir ./root --passphrase-env ROOT_PASS`
 * 2. on the same machine, sign an issuer: `ca:init --issuer-only --root-cert ./root/root-r1/cert.pem
 * --root-key ./root/root-r1/key.pem --dir ./server-ca --passphrase-env ACME_CA_KEY_PASSPHRASE`
 * 3. copy `./server-ca` (issuer cert + key, root CERTIFICATE only, issuers.json) to the server.
 *
 * For development, running it with no mode flag creates both and keeps the root key next to them.
 */
const USAGE = `Usage: tsx scripts/ca-init.ts [options]

  --dir <dir>                 output directory (default ./data/ca)
  --root-cn <name>            root subject CN (default "RapidMX Root CA <R>")
  --issuer-cn <name>          issuing CA subject CN and display name (default "RapidMX S/MIME CA <R>")
  --issuer-id <id>            issuer id, used in URLs and as directory name (default smime-r1)
  --root-id <id>              root directory suffix (default: the issuer id after its first '-', e.g. r1)
  --key-alg <alg>             ecdsa-p384 (default) | ecdsa-p256 | rsa-3072 | rsa-4096
  --base-url <url>            public base URL of this service (default https://acme.rapidmx.io); the certificate URLs
                              will be <base>/crl/<id>.crl, <base>/ca/<id>.crt and <base>/ocsp
  --root-only                 create only the root (writes root-<r>/cert.pem and key.pem)
  --issuer-only               create only an issuer with an existing root; needs --root-cert and --root-key
  --root-cert <file>          existing root certificate (PEM) for --issuer-only
  --root-key <file>           existing root private key (PEM) for --issuer-only
  --root-key-passphrase-env <VAR>  env var holding the passphrase of --root-key (default: the --passphrase-env var)
  --passphrase-env <VAR>      encrypt the written private keys with the passphrase in this env var, and record
                              passphrase_env in the manifest
  --root-years <n>            root validity (default 20)
  --issuer-years <n>          issuer validity (default 10; clamped to the root's)
  --no-root-key               do not write the root private key (development convenience: the root can then never
                              sign another issuer)
  --root-urls                 put CRL/caIssuers URLs for the root (<base>/crl/root-<r>.crl, <base>/ca/root-<r>.crt)
                              into the issuer certificate. Off by default: this service cannot serve a root CRL, and a
                              dead CRL link makes some mail clients report the chain as unverifiable
  --activate                  when adding to an existing issuers.json, make the new issuer the active one
  --force                     overwrite existing files
  --help                      show this text
`;

const KEY_ALGS = ["ecdsa-p384", "ecdsa-p256", "rsa-3072", "rsa-4096"] as const;
const ID_PATTERN = /^[a-z0-9][a-z0-9_-]{0,62}$/;

/** Where main() writes its messages; overridable so tests stay quiet. */
export interface CaInitIo {
    log: (message: string) => void;
    warn: (message: string) => void;
    env: NodeJS.ProcessEnv;
}

/** What {@link main} produced. */
export interface CaInitResult {
    /** The output directory (absolute). */
    dir: string;
    /** The root certificate file in the output directory. */
    rootCertPath?: string;
    /** The root key file, when written. */
    rootKeyPath?: string;
    /** The issuer certificate file. */
    issuerCertPath?: string;
    /** The issuer key file. */
    issuerKeyPath?: string;
    /** The manifest, when written. */
    manifestPath?: string;
    /** Lower-case hex SHA-256 of the root certificate (for pinning). */
    rootFingerprint: string;
}

function fail(message: string): never {
    throw new Error(message);
}

function parseYears(value: string | undefined, name: string, fallback: number): number {
    const text = value ?? String(fallback);
    if (!/^[0-9]{1,2}$/.test(text) || Number(text) < 1 || Number(text) > 50) {
        fail(`--${name} must be a whole number of years between 1 and 50`);
    }
    return Number(text);
}

function addYears(date: Date, years: number): Date {
    const d = new Date(date);
    d.setUTCFullYear(d.getUTCFullYear() + years);
    return d;
}

async function exists(file: string): Promise<boolean> {
    try {
        await fs.access(file);
        return true;
    } catch {
        return false;
    }
}

function passphraseFrom(env: NodeJS.ProcessEnv, variable: string | undefined, flag: string): string | undefined {
    if (variable === undefined) {
        return undefined;
    }
    const value = env[variable];
    if (!value) {
        fail(`--${flag} names ${variable}, but that environment variable is not set or is empty`);
    }
    return value;
}

async function writeFileSafely(file: string, data: string, mode: number, force: boolean): Promise<void> {
    await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
    try {
        await fs.writeFile(file, data, { mode, flag: force ? "w" : "wx" });
    } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "EEXIST") {
            fail(`Refusing to overwrite ${file} (use --force)`);
        }
        throw err;
    }
    if (mode !== 0o644) {
        await fs.chmod(file, mode);
    }
}

const rel = (from: string, to: string) => path.relative(from, to).split(path.sep).join("/");

/**
 * Runs `ca:init`.
 *
 * @param argv The arguments after the script name.
 * @param io Output and environment (defaults: console and `process.env`).
 * @returns The files that were written.
 * @throws Error with a readable message for invalid arguments or unusable inputs.
 */
export async function main(argv: string[], io?: Partial<CaInitIo>): Promise<CaInitResult> {
    const log = io?.log ?? ((m: string) => console.log(m));
    const warn = io?.warn ?? ((m: string) => console.warn(m));
    const env = io?.env ?? process.env;

    let values;
    try {
        ({ values } = parseArgs({
            args: argv,
            strict: true,
            allowPositionals: false,
            options: {
                dir: { type: "string" },
                "root-cn": { type: "string" },
                "issuer-cn": { type: "string" },
                "issuer-id": { type: "string" },
                "root-id": { type: "string" },
                "key-alg": { type: "string" },
                "base-url": { type: "string" },
                "root-only": { type: "boolean" },
                "issuer-only": { type: "boolean" },
                "root-cert": { type: "string" },
                "root-key": { type: "string" },
                "root-key-passphrase-env": { type: "string" },
                "passphrase-env": { type: "string" },
                "root-years": { type: "string" },
                "issuer-years": { type: "string" },
                "no-root-key": { type: "boolean" },
                "root-urls": { type: "boolean" },
                activate: { type: "boolean" },
                force: { type: "boolean" },
                help: { type: "boolean" },
            },
        }));
    } catch (err) {
        fail(`${(err as Error).message}\n\n${USAGE}`);
    }
    if (values.help) {
        log(USAGE);
        return { dir: "", rootFingerprint: "" };
    }

    const outDir = path.resolve(values.dir ?? "./data/ca");
    const issuerId = values["issuer-id"] ?? "smime-r1";
    if (!ID_PATTERN.test(issuerId)) {
        fail("--issuer-id must be lower-case letters, digits, '-' and '_' (it appears in URLs)");
    }
    const rootId = values["root-id"] ?? (issuerId.includes("-") ? issuerId.slice(issuerId.indexOf("-") + 1) : issuerId);
    if (!ID_PATTERN.test(rootId)) {
        fail("--root-id must be lower-case letters, digits, '-' and '_'");
    }
    const suffix = rootId.toUpperCase();
    const rootCn = values["root-cn"] ?? `RapidMX Root CA ${suffix}`;
    const issuerCn = values["issuer-cn"] ?? `RapidMX S/MIME CA ${suffix}`;
    const keyAlg = (values["key-alg"] ?? "ecdsa-p384") as GeneratedKeyKind;
    if (!KEY_ALGS.includes(keyAlg)) {
        fail(`--key-alg must be one of ${KEY_ALGS.join(", ")}`);
    }
    let baseUrl = values["base-url"] ?? "https://acme.rapidmx.io";
    try {
        const u = new URL(baseUrl);
        if (u.protocol !== "https:" && u.protocol !== "http:") {
            throw new Error("protocol");
        }
    } catch {
        fail("--base-url must be an http(s) URL");
    }
    baseUrl = baseUrl.replace(/\/+$/, "");
    const rootYears = parseYears(values["root-years"], "root-years", 20);
    const issuerYears = parseYears(values["issuer-years"], "issuer-years", 10);

    const rootOnly = values["root-only"] === true;
    const issuerOnly = values["issuer-only"] === true;
    if (rootOnly && issuerOnly) {
        fail("--root-only and --issuer-only are mutually exclusive");
    }
    if (issuerOnly && (!values["root-cert"] || !values["root-key"])) {
        fail("--issuer-only needs --root-cert and --root-key");
    }
    if (!issuerOnly && (values["root-cert"] || values["root-key"])) {
        fail("--root-cert/--root-key are only meaningful with --issuer-only");
    }
    if (rootOnly && values["no-root-key"]) {
        fail("--root-only with --no-root-key would create a root nobody can use");
    }
    const force = values.force === true;
    const passphrase = passphraseFrom(env, values["passphrase-env"], "passphrase-env");
    const rootKeyPassphrase = values["root-key-passphrase-env"]
        ? passphraseFrom(env, values["root-key-passphrase-env"], "root-key-passphrase-env")
        : passphrase;

    const rootDir = path.join(outDir, `root-${rootId}`);
    const issuerDir = path.join(outDir, issuerId);
    const rootCertPath = path.join(rootDir, "cert.pem");
    const rootKeyPath = path.join(rootDir, "key.pem");
    const issuerCertPath = path.join(issuerDir, "cert.pem");
    const issuerKeyPath = path.join(issuerDir, "key.pem");
    const manifestPath = path.join(outDir, "issuers.json");
    const writeRootKey = !issuerOnly && !values["no-root-key"];

    // Refuse before generating anything if a target exists, so a failed run leaves no half-written hierarchy.
    const targets: string[] = [rootCertPath];
    if (writeRootKey) {
        targets.push(rootKeyPath);
    }
    if (!rootOnly) {
        targets.push(issuerCertPath, issuerKeyPath);
    }
    if (issuerOnly && path.resolve(values["root-cert"]!) === rootCertPath) {
        targets.shift();
    }
    if (!force) {
        for (const target of targets) {
            if (await exists(target)) {
                fail(`Refusing to overwrite ${target} (use --force)`);
            }
        }
        if (!rootOnly && !issuerOnly && (await exists(manifestPath))) {
            fail(`Refusing to overwrite ${manifestPath} (use --force, or --issuer-only to add an issuer to it)`);
        }
    }

    const now = new Date();
    const notBefore = new Date(now.getTime() - 3_600_000);

    // --- The root ----------------------------------------------------------------------------------------------
    let rootIssuer: Issuer;
    let rootCert: IssuedCertificate | undefined;
    let rootPem: string;
    let rootKeyPem: string | undefined;
    if (issuerOnly) {
        let certText: string;
        let keyText: string;
        try {
            certText = await fs.readFile(path.resolve(values["root-cert"]!), "utf8");
            keyText = await fs.readFile(path.resolve(values["root-key"]!), "utf8");
        } catch (err) {
            fail(`Cannot read the root certificate/key: ${(err as Error).message}`);
        }
        const der = pemBlocks(certText).find((b) => b.label === "CERTIFICATE");
        if (!der) {
            fail("--root-cert contains no PEM certificate");
        }
        rootPem = certText;
        rootIssuer = new Issuer({
            id: "root",
            name: "root",
            certificate: certText,
            signer: LocalKeySigner.fromPem(keyText, rootKeyPassphrase),
        });
    } else {
        const { signer, privateKeyPem } = await LocalKeySigner.generate(keyAlg);
        rootCert = await buildCaCertificate({
            subject: `CN=${escapeDnValue(rootCn)}`,
            subjectSpki: signer.spki,
            signer,
            notBefore,
            notAfter: addYears(now, rootYears),
        });
        rootPem = rootCert.pem;
        rootIssuer = new Issuer({ id: "root", name: rootCn, certificate: rootCert.pem, signer });
        if (writeRootKey) {
            rootKeyPem = privateKeyPem(passphrase);
        }
    }
    const rootFingerprint = sha256Hex(rootIssuer.der);

    // --- The issuing CA ----------------------------------------------------------------------------------------
    let issuerCert: IssuedCertificate | undefined;
    let issuerKeyPem: string | undefined;
    if (!rootOnly) {
        const rootNotAfter = rootIssuer.certificate.notAfter;
        let issuerNotAfter = addYears(now, issuerYears);
        if (issuerNotAfter.getTime() > rootNotAfter.getTime()) {
            issuerNotAfter = new Date(rootNotAfter.getTime());
            warn(`The issuer's validity was clamped to the root's end of validity (${rootNotAfter.toISOString()}).`);
        }
        if (issuerNotAfter.getTime() - now.getTime() < 86_400_000) {
            fail("The root certificate expires in less than a day; it cannot issue a useful CA certificate");
        }
        const { signer, privateKeyPem } = await LocalKeySigner.generate(keyAlg);
        issuerCert = await buildCaCertificate({
            subject: `CN=${escapeDnValue(issuerCn)}`,
            subjectSpki: signer.spki,
            issuer: rootIssuer,
            signer: rootIssuer.signer,
            notBefore,
            notAfter: issuerNotAfter,
            pathLen: 0,
            ekuEmailProtection: true,
            urls: values["root-urls"]
                ? { crl: `${baseUrl}/crl/root-${rootId}.crl`, caIssuers: `${baseUrl}/ca/root-${rootId}.crt` }
                : undefined,
        });
        issuerKeyPem = privateKeyPem(passphrase);
        // Prove the pieces fit before anything is written.
        new Issuer({
            id: issuerId,
            name: issuerCn,
            certificate: issuerCert.pem,
            chain: [rootPem],
            signer,
            active: true,
        });
    }

    // --- Write -------------------------------------------------------------------------------------------------
    const result: CaInitResult = { dir: outDir, rootFingerprint };
    if (!issuerOnly || path.resolve(values["root-cert"]!) !== rootCertPath) {
        await writeFileSafely(rootCertPath, rootPem.endsWith("\n") ? rootPem : rootPem + "\n", 0o644, force);
    }
    result.rootCertPath = rootCertPath;
    if (rootKeyPem) {
        await writeFileSafely(rootKeyPath, rootKeyPem, 0o600, force);
        result.rootKeyPath = rootKeyPath;
    }
    if (issuerCert && issuerKeyPem) {
        await writeFileSafely(issuerCertPath, issuerCert.pem, 0o644, force);
        await writeFileSafely(issuerKeyPath, issuerKeyPem, 0o600, force);
        result.issuerCertPath = issuerCertPath;
        result.issuerKeyPath = issuerKeyPath;

        const entry: Record<string, unknown> = {
            id: issuerId,
            name: issuerCn,
            certificate: rel(outDir, issuerCertPath),
            chain: [rel(outDir, rootCertPath)],
            key: {
                type: "file",
                path: rel(outDir, issuerKeyPath),
                ...(values["passphrase-env"] ? { passphrase_env: values["passphrase-env"] } : {}),
            },
            active: true,
        };
        let manifest: Array<Record<string, unknown>> = [];
        if (issuerOnly && (await exists(manifestPath))) {
            try {
                manifest = JSON.parse(await fs.readFile(manifestPath, "utf8"));
                if (!Array.isArray(manifest)) {
                    throw new Error("not an array");
                }
            } catch (err) {
                fail(`Cannot extend ${manifestPath}: ${(err as Error).message}`);
            }
            if (manifest.some((m) => m.id === issuerId) && !force) {
                fail(`${manifestPath} already has an issuer '${issuerId}' (use --force to replace it)`);
            }
            manifest = manifest.filter((m) => m.id !== issuerId);
            if (values.activate) {
                manifest = manifest.map((m) => ({ ...m, active: false }));
            } else {
                entry.active = false;
            }
        }
        manifest.push(entry);
        await writeFileSafely(manifestPath, JSON.stringify(manifest, null, 2) + "\n", 0o644, true);
        result.manifestPath = manifestPath;
    }

    // --- Report ------------------------------------------------------------------------------------------------
    log(`Root CA:    ${rootCertPath}`);
    log(`            SHA-256 ${rootFingerprint}`);
    if (rootKeyPem) {
        log(`Root key:   ${rootKeyPath}`);
    }
    if (result.issuerCertPath) {
        log(`Issuer CA:  ${result.issuerCertPath} (id ${issuerId})`);
        log(`Issuer key: ${result.issuerKeyPath}`);
        log(`Manifest:   ${result.manifestPath}`);
        log(`Certificates will carry CRL ${baseUrl}/crl/${issuerId}.crl, caIssuers ${baseUrl}/ca/${issuerId}.crt, OCSP ${baseUrl}/ocsp`);
        if (!passphrase) {
            warn("The issuer private key was written UNENCRYPTED. Use --passphrase-env to encrypt it, or keep it in OpenBao.");
        }
    }
    if (rootKeyPem) {
        const bar = "!".repeat(78);
        warn(
            [
                bar,
                "!! THE ROOT PRIVATE KEY BELONGS OFFLINE.",
                "!! A root key that sits on the same host as the service (or in a backup, image or repository) can",
                "!! mint certificates for anyone. Move root-<id>/key.pem to offline media NOW and delete it from this",
                "!! machine; the server only ever needs the root CERTIFICATE. This mode is for development only.",
                bar,
            ].join("\n")
        );
    } else if (rootCert && !issuerOnly) {
        warn("The root private key was NOT written (--no-root-key): it existed only in this process and is gone.");
    }
    return result;
}

/** Escapes the characters that are special in an RFC 4514 distinguished-name value. */
function escapeDnValue(value: string): string {
    return value.replace(/[\\,+"<>;=#]/g, (c) => `\\${c}`);
}

// Run when executed as a script (not when imported by tests).
const invoked = process.argv[1] ? path.resolve(process.argv[1]) : "";
const self = path.resolve(fileURLToPath(import.meta.url));
if (invoked && (process.platform === "win32" ? invoked.toLowerCase() === self.toLowerCase() : invoked === self)) {
    main(process.argv.slice(2)).catch((err) => {
        console.error(`ca-init: ${(err as Error).message}`);
        process.exitCode = 1;
    });
}
