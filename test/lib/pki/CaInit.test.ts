///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import "reflect-metadata";
import * as x509 from "@peculiar/x509";
import * as crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { main } from "../../../scripts/ca-init.js";
import { IssuerRegistry, issueLeafCertificate, sha256Hex } from "../../../src/lib/pki/index.js";
import { DAY, HOUR, URLS, hasOpenssl, newSubjectKey, openssl, put, rmSync, tempDir } from "./helpers.js";

x509.cryptoProvider.set(globalThis.crypto);

const YEAR = 365.25 * DAY;

/** Runs main() quietly and returns what it printed. */
async function run(argv: string[], env: NodeJS.ProcessEnv = {}) {
    const logs: string[] = [];
    const warnings: string[] = [];
    const result = await main(argv, { log: (m) => logs.push(m), warn: (m) => warnings.push(m), env });
    return { result, logs: logs.join("\n"), warnings: warnings.join("\n") };
}

const cert = (file: string) => new x509.X509Certificate(readFileSync(file, "utf8"));
const node = (file: string) => new crypto.X509Certificate(readFileSync(file));
const json = (file: string) => JSON.parse(readFileSync(file, "utf8"));
const ext = (c: x509.X509Certificate, oid: string) => c.getExtension(oid) as x509.Extension;

describe("ca-init", () => {
    const dirs: string[] = [];
    const tmp = () => {
        const d = tempDir("ca-init-");
        dirs.push(d);
        return d;
    };
    afterAll(() => {
        for (const d of dirs) rmSync(d, { recursive: true, force: true });
    });

    describe("default (development) mode", () => {
        let dir: string;
        let out: Awaited<ReturnType<typeof run>>;

        beforeAll(async () => {
            dir = tmp();
            out = await run(["--dir", dir]);
        });

        it("writes root-<id>/cert.pem + key.pem, <issuer>/cert.pem + key.pem and issuers.json in the documented layout", () => {
            for (const f of ["root-r1/cert.pem", "root-r1/key.pem", "smime-r1/cert.pem", "smime-r1/key.pem", "issuers.json"]) {
                expect(existsSync(join(dir, f))).toBe(true);
            }
            expect(out.result.dir).toBe(resolve(dir));
            expect(out.result.rootCertPath).toBe(join(dir, "root-r1", "cert.pem"));
            expect(out.result.issuerKeyPath).toBe(join(dir, "smime-r1", "key.pem"));
            expect(out.result.manifestPath).toBe(join(dir, "issuers.json"));
        });

        it("writes the manifest exactly in the architecture document's format", () => {
            expect(json(join(dir, "issuers.json"))).toEqual([
                {
                    id: "smime-r1",
                    name: "RapidMX S/MIME CA R1",
                    certificate: "smime-r1/cert.pem",
                    chain: ["root-r1/cert.pem"],
                    key: { type: "file", path: "smime-r1/key.pem" },
                    active: true,
                },
            ]);
            expect(Object.keys(json(join(dir, "issuers.json"))[0])).toEqual(["id", "name", "certificate", "chain", "key", "active"]);
        });

        it.skipIf(process.platform === "win32")("creates private keys with mode 0600 and directories that are not world-readable", () => {
            expect(statSync(join(dir, "smime-r1", "key.pem")).mode & 0o777).toBe(0o600);
            expect(statSync(join(dir, "root-r1", "key.pem")).mode & 0o777).toBe(0o600);
            expect(statSync(join(dir, "smime-r1")).mode & 0o077).toBe(0);
        });

        it("builds a P-384 hierarchy: self-signed root (20 years), pathLen 0 issuer with emailProtection (10 years)", () => {
            const root = cert(join(dir, "root-r1", "cert.pem"));
            const issuer = cert(join(dir, "smime-r1", "cert.pem"));
            expect(root.subject).toBe("CN=RapidMX Root CA R1");
            expect(issuer.subject).toBe("CN=RapidMX S/MIME CA R1");
            expect(issuer.issuer).toBe(root.subject);
            expect(node(join(dir, "root-r1", "cert.pem")).verify(node(join(dir, "root-r1", "cert.pem")).publicKey)).toBe(true);
            expect(node(join(dir, "smime-r1", "cert.pem")).verify(node(join(dir, "root-r1", "cert.pem")).publicKey)).toBe(true);
            expect(node(join(dir, "smime-r1", "cert.pem")).publicKey.asymmetricKeyDetails?.namedCurve).toBe("secp384r1");
            expect(root.signatureAlgorithm.hash.name).toBe("SHA-384");
            const rootYears = (root.notAfter.getTime() - root.notBefore.getTime()) / YEAR;
            const issuerYears = (issuer.notAfter.getTime() - issuer.notBefore.getTime()) / YEAR;
            expect(rootYears).toBeGreaterThan(19.9);
            expect(rootYears).toBeLessThan(20.1);
            expect(issuerYears).toBeGreaterThan(9.9);
            expect(issuerYears).toBeLessThan(10.1);
            expect(Date.now() - root.notBefore.getTime()).toBeGreaterThan(0.9 * HOUR); // back-dated for clock skew
            expect((ext(issuer, "2.5.29.19") as x509.BasicConstraintsExtension).pathLength).toBe(0);
            expect((ext(issuer, "2.5.29.37") as x509.ExtendedKeyUsageExtension).usages).toEqual(["1.3.6.1.5.5.7.3.4"]);
            // no dead CRL/AIA links by default
            expect(issuer.getExtension("2.5.29.31")).toBeNull();
            expect(issuer.getExtension("1.3.6.1.5.5.7.1.1")).toBeNull();
        });

        it("warns loudly that the root key belongs offline and prints the root fingerprint", () => {
            expect(out.warnings).toMatch(/ROOT PRIVATE KEY BELONGS OFFLINE/);
            expect(out.warnings).toMatch(/!{20}/);
            expect(out.warnings).toMatch(/UNENCRYPTED/); // no --passphrase-env
            const fingerprint = sha256Hex(new Uint8Array(cert(join(dir, "root-r1", "cert.pem")).rawData));
            expect(out.result.rootFingerprint).toBe(fingerprint);
            expect(out.logs).toContain(fingerprint);
            expect(out.logs).toMatch(/\/crl\/smime-r1\.crl/);
            expect(out.logs).toMatch(/\/ocsp/);
        });

        it("produces a result that IssuerRegistry.fromManifest loads and that can issue verifiable certificates", async () => {
            const registry = await IssuerRegistry.fromManifest(join(dir, "issuers.json"));
            const issuer = registry.active();
            expect(issuer.id).toBe("smime-r1");
            expect(issuer.info().role).toBe("intermediate");
            expect(registry.roots()).toHaveLength(1);
            expect(sha256Hex(new Uint8Array(registry.roots()[0].rawData))).toBe(out.result.rootFingerprint);

            for (const [kind, type] of [["rsa", "signing-encryption"], ["ec", "signing"]] as const) {
                const subject = newSubjectKey(kind);
                const leaf = await issueLeafCertificate(issuer, URLS, {
                    spki: subject.spki,
                    email: "user@example.com",
                    type,
                    notBefore: new Date(Date.now() - HOUR),
                    notAfter: new Date(Date.now() + 90 * DAY),
                });
                const leafNode = new crypto.X509Certificate(Buffer.from(leaf.der));
                expect(leafNode.verify(node(join(dir, "smime-r1", "cert.pem")).publicKey)).toBe(true);
                expect(leafNode.checkIssued(node(join(dir, "smime-r1", "cert.pem")))).toBe(true);
                expect(leafNode.checkEmail("user@example.com")).toBe("user@example.com");
            }
        });

        it.skipIf(!hasOpenssl)("yields a chain OpenSSL accepts for S/MIME", async () => {
            const registry = await IssuerRegistry.fromManifest(join(dir, "issuers.json"));
            const subject = newSubjectKey("ec");
            const leaf = await issueLeafCertificate(registry.active(), URLS, {
                spki: subject.spki,
                email: "user@example.com",
                type: "signing",
                notBefore: new Date(Date.now() - HOUR),
                notAfter: new Date(Date.now() + 90 * DAY),
            });
            const work = tmp();
            const r = openssl([
                "verify",
                "-CAfile",
                join(dir, "root-r1", "cert.pem"),
                "-untrusted",
                join(dir, "smime-r1", "cert.pem"),
                "-purpose",
                "smimesign",
                put(work, "leaf.pem", leaf.pem),
            ])!;
            expect(r.status).toBe(0);
        });
    });

    describe("options", () => {
        it("honours ids, names, algorithm, base URL and lifetimes; escapes special characters in names", async () => {
            const dir = tmp();
            const { result, logs } = await run([
                "--dir", dir,
                "--issuer-id", "mail-2027",
                "--root-cn", "Acme, Inc. Root",
                "--issuer-cn", "Acme S/MIME=CA #1",
                "--key-alg", "ecdsa-p256",
                "--base-url", "https://ca.example.org/",
                "--root-years", "5",
                "--issuer-years", "2",
            ]);
            expect(existsSync(join(dir, "root-2027", "cert.pem"))).toBe(true);
            expect(existsSync(join(dir, "mail-2027", "cert.pem"))).toBe(true);
            const manifest = json(join(dir, "issuers.json"))[0];
            expect(manifest).toMatchObject({ id: "mail-2027", name: "Acme S/MIME=CA #1", certificate: "mail-2027/cert.pem", chain: ["root-2027/cert.pem"] });
            const root = cert(join(dir, "root-2027", "cert.pem"));
            const issuer = cert(join(dir, "mail-2027", "cert.pem"));
            expect(root.subject).toMatch(/Acme.*Inc\. Root/);
            expect(node(join(dir, "root-2027", "cert.pem")).subject).toBe("CN=Acme\\, Inc. Root"); // Node escapes the comma in its own rendering
            expect(node(join(dir, "mail-2027", "cert.pem")).subject).toBe("CN=Acme S/MIME=CA #1");
            expect(node(join(dir, "mail-2027", "cert.pem")).publicKey.asymmetricKeyDetails?.namedCurve).toBe("prime256v1");
            expect(root.signatureAlgorithm.hash.name).toBe("SHA-256");
            expect((root.notAfter.getTime() - root.notBefore.getTime()) / YEAR).toBeCloseTo(5, 0);
            expect((issuer.notAfter.getTime() - issuer.notBefore.getTime()) / YEAR).toBeCloseTo(2, 0);
            expect(logs).toContain("https://ca.example.org/crl/mail-2027.crl");
            expect(logs).toContain("https://ca.example.org/ca/mail-2027.crt");
            expect(logs).toContain("https://ca.example.org/ocsp");
            expect(result.issuerCertPath).toBe(join(dir, "mail-2027", "cert.pem"));
            await expect(IssuerRegistry.fromManifest(join(dir, "issuers.json"))).resolves.toBeDefined();
        });

        it("clamps the issuer's validity to the root's and says so", async () => {
            const dir = tmp();
            const { warnings } = await run(["--dir", dir, "--root-years", "1", "--issuer-years", "10"]);
            expect(warnings).toMatch(/clamped/);
            const root = cert(join(dir, "root-r1", "cert.pem"));
            const issuer = cert(join(dir, "smime-r1", "cert.pem"));
            expect(issuer.notAfter.getTime()).toBeLessThanOrEqual(root.notAfter.getTime());
        });

        it("puts root CRL/AIA URLs into the issuer certificate only with --root-urls", async () => {
            const dir = tmp();
            await run(["--dir", dir, "--root-urls", "--base-url", "https://ca.example.org"]);
            const issuer = cert(join(dir, "smime-r1", "cert.pem"));
            const crldp = ext(issuer, "2.5.29.31") as x509.CRLDistributionPointsExtension;
            expect(crldp.distributionPoints[0].distributionPoint?.fullName?.map((n) => n.uniformResourceIdentifier)).toEqual(["https://ca.example.org/crl/root-r1.crl"]);
            const aia = ext(issuer, "1.3.6.1.5.5.7.1.1") as x509.AuthorityInfoAccessExtension;
            expect(aia.caIssuers.map((n) => n.value)).toEqual(["https://ca.example.org/ca/root-r1.crt"]);
            expect(aia.ocsp).toHaveLength(0);
        });

        it("supports RSA 3072 hierarchies (sha384WithRSAEncryption)", async () => {
            const dir = tmp();
            await run(["--dir", dir, "--key-alg", "rsa-3072"]);
            const issuer = cert(join(dir, "smime-r1", "cert.pem"));
            expect(node(join(dir, "smime-r1", "cert.pem")).publicKey.asymmetricKeyDetails?.modulusLength).toBe(3072);
            expect(issuer.signatureAlgorithm.name).toBe("RSASSA-PKCS1-v1_5");
            const registry = await IssuerRegistry.fromManifest(join(dir, "issuers.json"));
            const subject = newSubjectKey("ec");
            const leaf = await issueLeafCertificate(registry.active(), URLS, {
                spki: subject.spki,
                email: "rsa@example.com",
                type: "signing",
                notBefore: new Date(Date.now() - HOUR),
                notAfter: new Date(Date.now() + DAY),
            });
            expect(new crypto.X509Certificate(Buffer.from(leaf.der)).verify(node(join(dir, "smime-r1", "cert.pem")).publicKey)).toBe(true);
        }, 120_000);
    });

    describe("--passphrase-env", () => {
        it("encrypts every written private key and records passphrase_env in the manifest", async () => {
            const dir = tmp();
            const env = { CA_PASS: "correct horse battery staple" };
            await run(["--dir", dir, "--passphrase-env", "CA_PASS"], env);
            for (const f of ["root-r1/key.pem", "smime-r1/key.pem"]) {
                expect(readFileSync(join(dir, f), "utf8")).toMatch(/^-----BEGIN ENCRYPTED PRIVATE KEY-----/);
            }
            expect(json(join(dir, "issuers.json"))[0].key).toEqual({ type: "file", path: "smime-r1/key.pem", passphrase_env: "CA_PASS" });
            // it loads with the passphrase, and fails without it
            const registry = await IssuerRegistry.fromManifest(join(dir, "issuers.json"), { env });
            expect(registry.active().id).toBe("smime-r1");
            await expect(IssuerRegistry.fromManifest(join(dir, "issuers.json"), { env: {} })).rejects.toThrow(/CA_PASS/);
            await expect(IssuerRegistry.fromManifest(join(dir, "issuers.json"), { env: { CA_PASS: "nope" } })).rejects.toThrow(/wrong passphrase/);
            // the root key decrypts with the same passphrase
            expect(crypto.createPrivateKey({ key: readFileSync(join(dir, "root-r1", "key.pem"), "utf8"), passphrase: env.CA_PASS }).type).toBe("private");
        });

        it("does not warn about unencrypted keys when a passphrase is used", async () => {
            const { warnings } = await run(["--dir", tmp(), "--passphrase-env", "CA_PASS"], { CA_PASS: "pass-pass-pass" });
            expect(warnings).not.toMatch(/UNENCRYPTED/);
        });

        it("fails clearly when the variable is unset or empty", async () => {
            await expect(run(["--dir", tmp(), "--passphrase-env", "NOPE"], {})).rejects.toThrow(/NOPE.*not set or is empty/);
            await expect(run(["--dir", tmp(), "--passphrase-env", "NOPE"], { NOPE: "" })).rejects.toThrow(/NOPE.*not set or is empty/);
        });
    });

    describe("offline root workflow: --root-only then --issuer-only", () => {
        it("creates the root alone, then signs an issuer with it and hands over only the root certificate", async () => {
            const rootDir = tmp();
            const serverDir = tmp();
            const env = { ROOT_PASS: "root-passphrase", ACME_CA_KEY_PASSPHRASE: "issuer-passphrase" };

            const rootRun = await run(["--root-only", "--dir", rootDir, "--passphrase-env", "ROOT_PASS", "--root-cn", "Offline Root"], env);
            expect(existsSync(join(rootDir, "root-r1", "cert.pem"))).toBe(true);
            expect(existsSync(join(rootDir, "root-r1", "key.pem"))).toBe(true);
            expect(existsSync(join(rootDir, "issuers.json"))).toBe(false);
            expect(existsSync(join(rootDir, "smime-r1"))).toBe(false);
            expect(rootRun.warnings).toMatch(/OFFLINE/);

            const issuerRun = await run(
                [
                    "--issuer-only",
                    "--dir", serverDir,
                    "--root-cert", join(rootDir, "root-r1", "cert.pem"),
                    "--root-key", join(rootDir, "root-r1", "key.pem"),
                    "--root-key-passphrase-env", "ROOT_PASS",
                    "--passphrase-env", "ACME_CA_KEY_PASSPHRASE",
                ],
                env
            );
            // the server directory has the issuer and the root CERTIFICATE only
            expect(existsSync(join(serverDir, "smime-r1", "cert.pem"))).toBe(true);
            expect(existsSync(join(serverDir, "smime-r1", "key.pem"))).toBe(true);
            expect(existsSync(join(serverDir, "root-r1", "cert.pem"))).toBe(true);
            expect(existsSync(join(serverDir, "root-r1", "key.pem"))).toBe(false);
            expect(readFileSync(join(serverDir, "root-r1", "cert.pem"), "utf8").trim()).toBe(readFileSync(join(rootDir, "root-r1", "cert.pem"), "utf8").trim());
            expect(issuerRun.warnings).not.toMatch(/OFFLINE/);
            expect(issuerRun.result.rootKeyPath).toBeUndefined();
            expect(issuerRun.result.rootFingerprint).toBe(rootRun.result.rootFingerprint);

            const registry = await IssuerRegistry.fromManifest(join(serverDir, "issuers.json"), { env });
            expect(registry.active().chain.map((c) => c.subject)).toEqual(["CN=Offline Root"]);
            expect(node(join(serverDir, "smime-r1", "cert.pem")).verify(node(join(rootDir, "root-r1", "cert.pem")).publicKey)).toBe(true);
        });

        it("rejects a root key that does not match the root certificate and a missing root-key passphrase", async () => {
            const a = tmp();
            const b = tmp();
            await run(["--root-only", "--dir", a]);
            await run(["--root-only", "--dir", b]);
            await expect(
                run(["--issuer-only", "--dir", tmp(), "--root-cert", join(a, "root-r1", "cert.pem"), "--root-key", join(b, "root-r1", "key.pem")])
            ).rejects.toThrow(/does not match/);
            const c = tmp();
            await run(["--root-only", "--dir", c, "--passphrase-env", "P"], { P: "secret-secret" });
            await expect(
                run(["--issuer-only", "--dir", tmp(), "--root-cert", join(c, "root-r1", "cert.pem"), "--root-key", join(c, "root-r1", "key.pem")])
            ).rejects.toThrow(/encrypted and no passphrase/);
        });

        it("adds to an existing manifest: inactive by default, active (and the old one demoted) with --activate", async () => {
            const dir = tmp();
            await run(["--dir", dir]);
            const rootArgs = ["--root-cert", join(dir, "root-r1", "cert.pem"), "--root-key", join(dir, "root-r1", "key.pem"), "--dir", dir, "--issuer-only"];

            await run([...rootArgs, "--issuer-id", "smime-r2"]);
            let manifest = json(join(dir, "issuers.json"));
            expect(manifest.map((m: { id: string; active: boolean }) => [m.id, m.active])).toEqual([["smime-r1", true], ["smime-r2", false]]);
            expect((await IssuerRegistry.fromManifest(join(dir, "issuers.json"))).active().id).toBe("smime-r1");

            await run([...rootArgs, "--issuer-id", "smime-r3", "--activate"]);
            manifest = json(join(dir, "issuers.json"));
            expect(manifest.map((m: { id: string; active: boolean }) => [m.id, m.active])).toEqual([["smime-r1", false], ["smime-r2", false], ["smime-r3", true]]);
            const registry = await IssuerRegistry.fromManifest(join(dir, "issuers.json"));
            expect(registry.all().map((i) => i.id)).toEqual(["smime-r1", "smime-r2", "smime-r3"]);
            expect(registry.active().id).toBe("smime-r3");
            expect(registry.roots()).toHaveLength(1);
        });
    });

    describe("--no-root-key", () => {
        it("does not write the root key and says the root can never sign again", async () => {
            const dir = tmp();
            const { warnings, result } = await run(["--dir", dir, "--no-root-key"]);
            expect(existsSync(join(dir, "root-r1", "key.pem"))).toBe(false);
            expect(existsSync(join(dir, "root-r1", "cert.pem"))).toBe(true);
            expect(result.rootKeyPath).toBeUndefined();
            expect(warnings).toMatch(/NOT written/);
            expect(warnings).not.toMatch(/BELONGS OFFLINE/);
            await expect(IssuerRegistry.fromManifest(join(dir, "issuers.json"))).resolves.toBeDefined();
        });
    });

    describe("safety", () => {
        it("refuses to overwrite existing files unless --force is given, and writes nothing in that case", async () => {
            const dir = tmp();
            await run(["--dir", dir]);
            const before = readFileSync(join(dir, "smime-r1", "key.pem"), "utf8");
            await expect(run(["--dir", dir])).rejects.toThrow(/Refusing to overwrite .*(cert|key)\.pem.*--force/);
            expect(readFileSync(join(dir, "smime-r1", "key.pem"), "utf8")).toBe(before);
            await run(["--dir", dir, "--force"]);
            expect(readFileSync(join(dir, "smime-r1", "key.pem"), "utf8")).not.toBe(before);
            await expect(IssuerRegistry.fromManifest(join(dir, "issuers.json"))).resolves.toBeDefined();
        });

        it("refuses to overwrite an existing manifest in default mode", async () => {
            const dir = tmp();
            put(dir, "issuers.json", "[]");
            await expect(run(["--dir", dir])).rejects.toThrow(/Refusing to overwrite .*issuers\.json/);
            expect(existsSync(join(dir, "root-r1"))).toBe(false);
        });
    });

    describe("argument validation", () => {
        it.each([
            [["--root-only", "--issuer-only"], /mutually exclusive/],
            [["--issuer-only"], /needs --root-cert and --root-key/],
            [["--issuer-only", "--root-cert", "x.pem"], /needs --root-cert and --root-key/],
            [["--root-cert", "x.pem"], /only meaningful with --issuer-only/],
            [["--root-only", "--no-root-key"], /nobody can use/],
            [["--key-alg", "dsa"], /--key-alg must be one of/],
            [["--key-alg", "rsa-1024"], /--key-alg must be one of/],
            [["--issuer-id", "Bad Id"], /--issuer-id/],
            [["--issuer-id", "a/b"], /--issuer-id/],
            [["--root-id", "../x"], /--root-id/],
            [["--root-years", "0"], /--root-years/],
            [["--root-years", "abc"], /--root-years/],
            [["--issuer-years", "51"], /--issuer-years/],
            [["--base-url", "ftp://x.test"], /--base-url/],
            [["--base-url", "not a url"], /--base-url/],
            [["--bogus"], /Unknown option/],
            [["positional"], /Unexpected argument|positional/i],
        ])("rejects %j", async (argv, message) => {
            await expect(run([...argv, "--dir", tmp()])).rejects.toThrow(message);
        });

        it("rejects an unreadable root certificate for --issuer-only", async () => {
            await expect(
                run(["--issuer-only", "--dir", tmp(), "--root-cert", join(tmp(), "missing.pem"), "--root-key", join(tmp(), "missing-key.pem")])
            ).rejects.toThrow(/Cannot read the root certificate/);
        });

        it("prints usage for --help without writing anything", async () => {
            const dir = tmp();
            const { logs } = await run(["--help", "--dir", dir]);
            expect(logs).toMatch(/Usage: tsx scripts\/ca-init\.ts/);
            expect(logs).toMatch(/--passphrase-env/);
            expect(existsSync(join(dir, "issuers.json"))).toBe(false);
        });
    });

    describe("as a script", () => {
        const tsx = resolve("node_modules/tsx/dist/cli.mjs");

        it("runs as `tsx scripts/ca-init.ts`, exits 0 and produces a loadable CA", async () => {
            const dir = tmp();
            const r = spawnSync(process.execPath, [tsx, "scripts/ca-init.ts", "--dir", dir, "--key-alg", "ecdsa-p256"], { encoding: "utf8", env: { ...process.env } });
            expect(r.status).toBe(0);
            expect(r.stdout).toMatch(/Root CA:/);
            expect(r.stderr).toMatch(/BELONGS OFFLINE/);
            await expect(IssuerRegistry.fromManifest(join(dir, "issuers.json"))).resolves.toBeDefined();
        }, 60_000);

        it("prints a readable error and exits 1 on invalid arguments", () => {
            const r = spawnSync(process.execPath, [tsx, "scripts/ca-init.ts", "--key-alg", "nope", "--dir", tmp()], { encoding: "utf8" });
            expect(r.status).toBe(1);
            expect(r.stderr).toMatch(/ca-init: --key-alg must be one of/);
        }, 60_000);
    });
});
