///////////////////////////////////////////////////////////////////////////////
// Security review: how much CPU does the key policy burn on a key that will never carry a valid signature?
//
// validateCsr() runs checkPublicKey() BEFORE it verifies the CSR's proof-of-possession signature, and checkPublicKey() does an
// integer k-th-root test for ~150 prime exponents on an up-to-8192-bit modulus. An applicant who owns one mailbox (so has a
// `ready` order) can send finalize requests carrying a garbage CSR whose modulus is a random odd 8192-bit number with no small
// factor: every one of them costs the full loop and fails at the signature check afterwards.
///////////////////////////////////////////////////////////////////////////////
import { createPublicKey, randomBytes } from "node:crypto";
import { checkPublicKey } from "../../src/lib/pki/CsrValidator.js";

/** A random odd 8192-bit modulus with no prime factor below 752 (so it passes every cheap check). */
function hardModulus(bits: number): Buffer {
    const small: number[] = [];
    for (let i = 3; i < 752; i += 2) {
        if (small.every((p) => i % p !== 0)) {
            small.push(i);
        }
    }
    for (;;) {
        const n = randomBytes(bits / 8);
        n[0] |= 0x80;
        n[n.length - 1] |= 1;
        const value = BigInt("0x" + n.toString("hex"));
        if (small.every((p) => value % BigInt(p) !== 0n)) {
            return n;
        }
    }
}

/** A syntactically valid CSR for an EC key whose public key has been swapped for `spki` and whose signature is garbage. */
async function garbageCsr(spki: Uint8Array): Promise<Uint8Array> {
    const { AsnConvert } = await import("@peculiar/asn1-schema");
    const { CertificationRequest } = await import("@peculiar/asn1-csr");
    const { SubjectPublicKeyInfo, AlgorithmIdentifier } = await import("@peculiar/asn1-x509");
    const keys = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]));
    const { x509 } = await import("../../src/lib/pki/runtime.js");
    const csr = await x509.Pkcs10CertificateRequestGenerator.create({
        name: "CN=a@example.com",
        keys,
        signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
        extensions: [new x509.SubjectAlternativeNameExtension([{ type: "email", value: "a@example.com" }])],
    });
    const parsed = AsnConvert.parse(csr.rawData, CertificationRequest);
    parsed.certificationRequestInfo.subjectPKInfo = AsnConvert.parse(spki, SubjectPublicKeyInfo);
    parsed.signatureAlgorithm = new AlgorithmIdentifier({ algorithm: "1.2.840.113549.1.1.11", parameters: null });
    parsed.signature = new Uint8Array(randomBytes(1024)).buffer;
    return new Uint8Array(AsnConvert.serialize(parsed));
}

describe("Review: cost of the RSA key policy on an unsigned, garbage key", () => {
    it("rejects a CSR with a bad signature without first doing the expensive key checks (validateCsr, RSA-8192 garbage key)", async () => {
        const { validateCsr } = await import("../../src/lib/pki/CsrValidator.js");
        const n = hardModulus(8192);
        const spki = new Uint8Array(createPublicKey({ key: { kty: "RSA", n: n.toString("base64url"), e: "AQAB" } as any, format: "jwk" }).export({ type: "spki", format: "der" }));
        const der = await garbageCsr(spki);
        const samples: number[] = [];
        let message = "";
        for (let i = 0; i < 3; i++) {
            const started = process.hrtime.bigint();
            await validateCsr(der).catch((err) => {
                message = String(err?.message);
            });
            samples.push(Number(process.hrtime.bigint() - started) / 1e6);
        }
        const median = samples.sort((a, b) => a - b)[1];
        console.log(`validateCsr(garbage RSA-8192 CSR): median ${median.toFixed(1)} ms, rejected with: ${message}`);
        expect(message).toContain("signature");
        expect(median).toBeLessThan(25);
    }, 60_000);
});
