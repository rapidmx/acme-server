///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { mkdirSync, writeFileSync } from "fs";
import { join } from "path";
import { buildCaCertificate, Issuer, LocalKeySigner } from "../../src/lib/pki/index.js";

/**
 * Creates a throw-away CA hierarchy in `dir` – a root and one issuing CA – and the `issuers.json` that points at it, the
 * same layout `yarn ca:init` produces. Returns the manifest path.
 */
export async function createTestCa(dir: string, baseUrl: string, issuerId: string = "test-ca", issuerDays: number = 5 * 365): Promise<string> {
    mkdirSync(join(dir, "root"), { recursive: true });
    mkdirSync(join(dir, issuerId), { recursive: true });
    const now: number = Date.now();
    const notBefore: Date = new Date(now - 24 * 3600_000);

    const root = await LocalKeySigner.generate("ecdsa-p384");
    const rootCert = await buildCaCertificate({
        subject: "CN=RapidMX Test Root,O=RapidMX Test",
        subjectSpki: root.signer.spki,
        signer: root.signer,
        notBefore,
        notAfter: new Date(now + 20 * 365 * 86400_000),
        pathLen: 0,
    });
    writeFileSync(join(dir, "root", "cert.pem"), rootCert.pem);
    const rootIssuer: Issuer = new Issuer({ id: "test-root", name: "Test Root", certificate: rootCert.pem, signer: root.signer });

    const issuing = await LocalKeySigner.generate("ecdsa-p384");
    const issuingCert = await buildCaCertificate({
        subject: "CN=RapidMX Test S/MIME CA,O=RapidMX Test",
        subjectSpki: issuing.signer.spki,
        issuer: rootIssuer,
        signer: root.signer,
        notBefore,
        notAfter: new Date(now + issuerDays * 86400_000),
        pathLen: 0,
        ekuEmailProtection: true,
        urls: { crl: `${baseUrl}/crl/test-root.crl`, caIssuers: `${baseUrl}/ca/test-root.crt` },
    });
    writeFileSync(join(dir, issuerId, "cert.pem"), issuingCert.pem);
    writeFileSync(join(dir, issuerId, "key.pem"), issuing.privateKeyPem(), { mode: 0o600 });

    const manifest: string = join(dir, "issuers.json");
    writeFileSync(
        manifest,
        JSON.stringify(
            [
                {
                    id: issuerId,
                    name: "RapidMX Test S/MIME CA",
                    certificate: `${issuerId}/cert.pem`,
                    chain: ["root/cert.pem"],
                    key: { type: "file", path: `${issuerId}/key.pem` },
                    active: true,
                },
            ],
            null,
            2,
        ),
    );
    return manifest;
}
