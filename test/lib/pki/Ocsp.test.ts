///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import "reflect-metadata";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import {
    BasicOCSPResponse,
    CertID,
    id_pkix_ocsp_basic,
    id_pkix_ocsp_nonce,
    OCSPRequest,
    OCSPResponse,
    OCSPResponseStatus,
    Request,
    TBSRequest,
} from "@peculiar/asn1-ocsp";
import { AlgorithmIdentifier, Extension } from "@peculiar/asn1-x509";
import * as crypto from "node:crypto";
import {
    IssuerRegistry,
    OcspResponder,
    issueLeafCertificate,
    serialHexToDerContent,
    verifySignature,
    type CertStatusLookup,
    type Issuer,
    type IssuedCertificate,
} from "../../../src/lib/pki/index.js";
import { certificateParts } from "../../../src/lib/pki/certutil.js";
import {
    DAY,
    HOUR,
    URLS,
    hasOpenssl,
    makeHierarchy,
    newSubjectKey,
    openssl,
    put,
    rmSync,
    tempDir,
    type Hierarchy,
} from "./helpers.js";

const HASH_OIDS = {
    sha1: "1.3.14.3.2.26",
    sha256: "2.16.840.1.101.3.4.2.1",
    sha384: "2.16.840.1.101.3.4.2.2",
    sha512: "2.16.840.1.101.3.4.2.3",
} as const;

const NOW = new Date("2031-06-07T08:09:10.789Z");
const REVOKED_AT = new Date("2031-06-01T12:00:00Z");

/** A CertID computed independently of the library (straight from the certificate's DER). */
function certId(issuerCert: IssuedCertificate, serialHex: string, hash: keyof typeof HASH_OIDS = "sha1"): CertID {
    const parts = certificateParts(issuerCert.der);
    const keyBits = bitsOf(parts.spki);
    return new CertID({
        hashAlgorithm: new AlgorithmIdentifier({ algorithm: HASH_OIDS[hash], parameters: Uint8Array.of(5, 0).buffer }),
        issuerNameHash: new OctetString(crypto.createHash(hash).update(parts.subject).digest()),
        issuerKeyHash: new OctetString(crypto.createHash(hash).update(keyBits).digest()),
        serialNumber: serialHexToDerContent(serialHex).buffer.slice(0) as ArrayBuffer,
    });
}

/** Content of the subjectPublicKey BIT STRING of an SPKI, found by walking the DER by hand. */
function bitsOf(spki: Uint8Array): Uint8Array {
    const lenOf = (o: number) => (spki[o + 1] < 0x80 ? { hdr: 2, len: spki[o + 1] } : { hdr: 2 + (spki[o + 1] & 0x7f), len: parseInt(Buffer.from(spki.slice(o + 2, o + 2 + (spki[o + 1] & 0x7f))).toString("hex"), 16) });
    const outer = lenOf(0);
    const alg = lenOf(outer.hdr);
    const bitStringOffset = outer.hdr + alg.hdr + alg.len;
    const bs = lenOf(bitStringOffset);
    return spki.slice(bitStringOffset + bs.hdr + 1, bitStringOffset + bs.hdr + bs.len);
}

function request(ids: CertID[], extensions?: Extension[]): Uint8Array {
    return new Uint8Array(
        AsnConvert.serialize(
            new OCSPRequest({
                tbsRequest: new TBSRequest({ requestList: ids.map((reqCert) => new Request({ reqCert })), requestExtensions: extensions }),
            })
        )
    );
}

const nonceExtension = (nonce: Uint8Array, critical = false) =>
    new Extension({ extnID: id_pkix_ocsp_nonce, critical, extnValue: new OctetString(Buffer.concat([Buffer.from([0x04, nonce.length]), nonce])) });

interface Parsed {
    status: OCSPResponseStatus;
    basic?: BasicOCSPResponse;
}

function parse(der: Uint8Array): Parsed {
    const response = AsnConvert.parse(der, OCSPResponse);
    if (!response.responseBytes) {
        return { status: response.responseStatus };
    }
    expect(response.responseBytes.responseType).toBe(id_pkix_ocsp_basic);
    return { status: response.responseStatus, basic: AsnConvert.parse(response.responseBytes.response.buffer, BasicOCSPResponse) };
}

describe("OcspResponder", () => {
    let ec: Hierarchy;
    let rsa: Hierarchy;
    let leaf: IssuedCertificate;
    let registry: IssuerRegistry;
    let lookups: Array<[string, string]>;

    const lookup: CertStatusLookup = async (issuer: Issuer, serialHex: string) => {
        lookups.push([issuer.id, serialHex]);
        if (serialHex === leaf.serialHex) return { status: "good" };
        if (serialHex === "0123") return { status: "revoked", revokedAt: REVOKED_AT, reason: 4 };
        if (serialHex === "0456") return { status: "revoked", revokedAt: REVOKED_AT };
        return { status: "unknown" };
    };

    const responder = (o?: ConstructorParameters<typeof OcspResponder>[2]) =>
        new OcspResponder(registry, lookup, { now: () => NOW, ...o });

    beforeAll(async () => {
        ec = await makeHierarchy("ecdsa-p384", "smime-ec");
        rsa = await makeHierarchy("rsa-2048", "smime-rsa");
        registry = IssuerRegistry.fromIssuers([ec.issuer, rsa.issuer]);
        leaf = await issueLeafCertificate(ec.issuer, URLS, {
            spki: newSubjectKey("ec").spki,
            email: "ocsp@example.com",
            type: "signing",
            notBefore: new Date(Date.now() - HOUR),
            notAfter: new Date(Date.now() + DAY),
        });
    });

    beforeEach(() => {
        lookups = [];
    });

    /** Verifies the BasicOCSPResponse signature over the exact ResponseData bytes with the issuer's key. */
    function expectSignedBy(basic: BasicOCSPResponse, h: Hierarchy, algorithm: Parameters<typeof verifySignature>[0]) {
        expect(
            verifySignature(algorithm, h.issuerSigner.spki, new Uint8Array(basic.tbsResponseDataRaw!), new Uint8Array(basic.signature))
        ).toBe(true);
        expect(basic.signatureAlgorithm.algorithm).toBe(signatureAlgorithmOid(algorithm));
    }

    function signatureAlgorithmOid(algorithm: string) {
        return { "ecdsa-with-SHA384": "1.2.840.10045.4.3.3", sha256WithRSAEncryption: "1.2.840.113549.1.1.11" }[algorithm];
    }

    it("answers `good` with a response signed by the issuer key, valid for 24 hours, identified by key hash", async () => {
        const id = certId(ec.issuerCert, leaf.serialHex);
        const { status, basic } = parse(await responder().respond(request([id])));
        expect(status).toBe(OCSPResponseStatus.successful);
        expectSignedBy(basic!, ec, "ecdsa-with-SHA384");
        const data = basic!.tbsResponseData;
        expect(data.version).toBe(0);
        expect(data.responderID.byKey).toBeDefined();
        expect(Buffer.from(data.responderID.byKey!.buffer).equals(Buffer.from(id.issuerKeyHash.buffer))).toBe(true);
        expect(data.producedAt.toISOString()).toBe("2031-06-07T08:09:10.000Z");
        expect(data.responses).toHaveLength(1);
        const single = data.responses[0];
        expect(single.certStatus.good).not.toBeUndefined();
        expect(single.certStatus.revoked).toBeUndefined();
        expect(single.certStatus.unknown).toBeUndefined();
        expect(single.thisUpdate.toISOString()).toBe("2031-06-07T08:09:10.000Z");
        expect(single.nextUpdate!.toISOString()).toBe("2031-06-08T08:09:10.000Z");
        // the CertID is echoed exactly
        expect(Buffer.from(AsnConvert.serialize(single.certID)).equals(Buffer.from(AsnConvert.serialize(id)))).toBe(true);
        expect(basic!.certs).toBeUndefined(); // signed by the CA itself: no responder certificate
        expect(data.responseExtensions).toBeUndefined();
        expect(lookups).toEqual([["smime-ec", leaf.serialHex]]);
    });

    it("answers `revoked` with the revocation time and reason", async () => {
        const { basic } = parse(await responder().respond(request([certId(ec.issuerCert, "0123")])));
        const status = basic!.tbsResponseData.responses[0].certStatus;
        expect(status.revoked).toBeDefined();
        expect(status.revoked!.revocationTime.toISOString()).toBe("2031-06-01T12:00:00.000Z");
        expect(status.revoked!.revocationReason?.reason).toBe(4);
        expect(status.good).toBeUndefined();
        expect(lookups).toEqual([["smime-ec", "0123"]]);
    });

    it("answers `revoked` without a reason when none is recorded", async () => {
        const { basic } = parse(await responder().respond(request([certId(ec.issuerCert, "0456")])));
        const revoked = basic!.tbsResponseData.responses[0].certStatus.revoked!;
        expect(revoked.revocationTime.toISOString()).toBe("2031-06-01T12:00:00.000Z");
        expect(revoked.revocationReason).toBeUndefined();
    });

    it("answers `unknown` for a serial the lookup does not know (never `good`)", async () => {
        const { status, basic } = parse(await responder().respond(request([certId(ec.issuerCert, "deadbeef")])));
        expect(status).toBe(OCSPResponseStatus.successful);
        const single = basic!.tbsResponseData.responses[0];
        expect(single.certStatus.unknown).not.toBeUndefined();
        expect(single.certStatus.good).toBeUndefined();
        expect(lookups).toEqual([["smime-ec", "deadbeef"]]);
    });

    it("answers `unknown` without consulting the lookup for a serial that cannot be one of ours", async () => {
        const negative = certId(ec.issuerCert, "01");
        negative.serialNumber = Uint8Array.of(0xff, 0x01).buffer; // negative INTEGER: must not alias 00ff01
        const tooLong = certId(ec.issuerCert, "01");
        tooLong.serialNumber = new Uint8Array(30).fill(0x11).buffer;
        const zero = certId(ec.issuerCert, "01");
        zero.serialNumber = Uint8Array.of(0).buffer;
        for (const id of [negative, tooLong, zero]) {
            const { basic } = parse(await responder().respond(request([id])));
            expect(basic!.tbsResponseData.responses[0].certStatus.unknown).not.toBeUndefined();
        }
        expect(lookups).toEqual([]);
    });

    it("normalizes a leading-zero (sign octet) serial to the canonical hex form", async () => {
        const id = certId(ec.issuerCert, "0123");
        id.serialNumber = Uint8Array.of(0x00, 0x01, 0x23).buffer;
        await responder().respond(request([id]));
        expect(lookups).toEqual([["smime-ec", "0123"]]);
    });

    it("routes to the right issuer by key and name hash and signs with that issuer's key (RSA here)", async () => {
        const { basic } = parse(await responder().respond(request([certId(rsa.issuerCert, "0123")])));
        expectSignedBy(basic!, rsa, "sha256WithRSAEncryption");
        expect(lookups).toEqual([["smime-rsa", "0123"]]);
    });

    it.each(["sha1", "sha256", "sha384", "sha512"] as const)("understands %s CertIDs", async (hash) => {
        const id = certId(ec.issuerCert, leaf.serialHex, hash);
        const { status, basic } = parse(await responder().respond(request([id])));
        expect(status).toBe(OCSPResponseStatus.successful);
        expect(basic!.tbsResponseData.responses[0].certStatus.good).not.toBeUndefined();
        // the response echoes the hash algorithm the client used
        expect(basic!.tbsResponseData.responses[0].certID.hashAlgorithm.algorithm).toBe(HASH_OIDS[hash]);
    });

    it("answers several certificates of one issuer in one response", async () => {
        const { basic } = parse(await responder().respond(request([certId(ec.issuerCert, leaf.serialHex), certId(ec.issuerCert, "0123"), certId(ec.issuerCert, "99")])));
        const kinds = basic!.tbsResponseData.responses.map((r) => (r.certStatus.good !== undefined ? "good" : r.certStatus.revoked ? "revoked" : "unknown"));
        expect(kinds).toEqual(["good", "revoked", "unknown"]);
    });

    describe("nonce", () => {
        it("echoes the request nonce as a non-critical extension of the ResponseData (covered by the signature)", async () => {
            const nonce = new Uint8Array(crypto.randomBytes(16));
            const { basic } = parse(await responder().respond(request([certId(ec.issuerCert, leaf.serialHex)], [nonceExtension(nonce)])));
            const extensions = basic!.tbsResponseData.responseExtensions!;
            expect(extensions).toHaveLength(1);
            expect(extensions[0].extnID).toBe(id_pkix_ocsp_nonce);
            expect(extensions[0].critical).toBe(false);
            expect(Buffer.from(extensions[0].extnValue.buffer).equals(Buffer.concat([Buffer.from([4, 16]), nonce]))).toBe(true);
            expectSignedBy(basic!, ec, "ecdsa-with-SHA384");
        });

        it("adds no nonce when the request has none, and ignores unknown non-critical extensions", async () => {
            const other = new Extension({ extnID: "1.2.3.4", critical: false, extnValue: new OctetString(Uint8Array.of(5, 0)) });
            const { basic } = parse(await responder().respond(request([certId(ec.issuerCert, leaf.serialHex)], [other])));
            expect(basic!.tbsResponseData.responseExtensions).toBeUndefined();
        });

        it("refuses an oversized nonce, two nonces, and unknown critical extensions as malformed", async () => {
            const id = certId(ec.issuerCert, leaf.serialHex);
            const big = nonceExtension(new Uint8Array(200));
            const critical = new Extension({ extnID: "1.2.3.4", critical: true, extnValue: new OctetString(Uint8Array.of(5, 0)) });
            for (const extensions of [[big], [nonceExtension(Uint8Array.of(1)), nonceExtension(Uint8Array.of(2))], [critical]]) {
                expect(parse(await responder().respond(request([id], extensions))).status).toBe(OCSPResponseStatus.malformedRequest);
            }
            expect(lookups).toEqual([]);
        });
    });

    describe("error statuses", () => {
        it("answers `malformedRequest` for garbage, empty, truncated and oversized input", async () => {
            const valid = request([certId(ec.issuerCert, leaf.serialHex)]);
            for (const bad of [new Uint8Array(), Uint8Array.of(1, 2, 3), new TextEncoder().encode("GET / HTTP/1.1"), valid.slice(0, valid.length - 4), new Uint8Array(9000).fill(0x30)]) {
                const response = await responder().respond(bad);
                const { status, basic } = parse(response);
                expect(status).toBe(OCSPResponseStatus.malformedRequest);
                expect(basic).toBeUndefined();
            }
            expect(lookups).toEqual([]);
        });

        it("answers `malformedRequest` for an empty request list and for more than 8 certificates", async () => {
            expect(parse(await responder().respond(request([]))).status).toBe(OCSPResponseStatus.malformedRequest);
            const many = Array.from({ length: 9 }, () => certId(ec.issuerCert, leaf.serialHex));
            expect(parse(await responder().respond(request(many))).status).toBe(OCSPResponseStatus.malformedRequest);
            const eight = Array.from({ length: 8 }, () => certId(ec.issuerCert, leaf.serialHex));
            expect(parse(await responder().respond(request(eight))).status).toBe(OCSPResponseStatus.successful);
        });

        it("never throws, whatever it is given", async () => {
            for (const bad of [undefined, null, "string", 42, {}] as unknown[]) {
                const { status } = parse(await responder().respond(bad as Uint8Array));
                expect(status).toBe(OCSPResponseStatus.malformedRequest);
            }
        });

        it("answers `unauthorized` for an issuer this registry does not serve", async () => {
            const stranger = await makeHierarchy("ecdsa-p384", "someone-else");
            const { status, basic } = parse(await responder().respond(request([certId(stranger.issuerCert, "0123")])));
            expect(status).toBe(OCSPResponseStatus.unauthorized);
            expect(basic).toBeUndefined();
            expect(lookups).toEqual([]);
        });

        it("answers `unauthorized` when the name hash does not match even though the key hash does", async () => {
            const id = certId(ec.issuerCert, "0123");
            id.issuerNameHash = new OctetString(crypto.createHash("sha1").update("some other name").digest());
            expect(parse(await responder().respond(request([id]))).status).toBe(OCSPResponseStatus.unauthorized);
        });

        it("answers `unauthorized` for an unsupported hash algorithm or wrong-length hashes", async () => {
            const id = certId(ec.issuerCert, "0123");
            id.hashAlgorithm = new AlgorithmIdentifier({ algorithm: "1.2.840.113549.2.5" }); // MD5
            expect(parse(await responder().respond(request([id]))).status).toBe(OCSPResponseStatus.unauthorized);
            const short = certId(ec.issuerCert, "0123");
            short.issuerKeyHash = new OctetString(Uint8Array.of(1, 2, 3));
            expect(parse(await responder().respond(request([short]))).status).toBe(OCSPResponseStatus.unauthorized);
        });

        it("answers `unauthorized` when one request mixes issuers (one signature cannot cover both)", async () => {
            const { status } = parse(await responder().respond(request([certId(ec.issuerCert, "0123"), certId(rsa.issuerCert, "0123")])));
            expect(status).toBe(OCSPResponseStatus.unauthorized);
            expect(lookups).toEqual([]);
        });

        it("answers `internalError` when the lookup fails, and reports the error to the hook", async () => {
            const errors: unknown[] = [];
            const failing = new OcspResponder(registry, async () => { throw new Error("database is down"); }, { now: () => NOW, onError: (e) => errors.push(e) });
            const { status, basic } = parse(await failing.respond(request([certId(ec.issuerCert, "0123")])));
            expect(status).toBe(OCSPResponseStatus.internalError);
            expect(basic).toBeUndefined();
            expect((errors[0] as Error).message).toBe("database is down");
        });

        it("answers `internalError` for an invalid lookup result and survives a throwing error hook", async () => {
            const garbage = new OcspResponder(registry, (async () => ({ status: "maybe" })) as unknown as CertStatusLookup, { onError: () => { throw new Error("hook"); } });
            expect(parse(await garbage.respond(request([certId(ec.issuerCert, "0123")]))).status).toBe(OCSPResponseStatus.internalError);
            const noTime = new OcspResponder(registry, (async () => ({ status: "revoked" })) as unknown as CertStatusLookup);
            expect(parse(await noTime.respond(request([certId(ec.issuerCert, "0123")]))).status).toBe(OCSPResponseStatus.internalError);
        });

        it("answers `internalError` when the signer fails or produces a bad signature", async () => {
            const h = await makeHierarchy("ecdsa-p256", "broken");
            const failingSigner = { algorithm: h.issuer.signer.algorithm, spki: h.issuer.signer.spki, sign: async () => { throw new Error("HSM offline"); } };
            const registryWithBroken = {
                findByCertId: () => ({ id: "broken", signer: failingSigner, keyHash: () => new Uint8Array(20) }),
            } as unknown as IssuerRegistry;
            const errors: unknown[] = [];
            const r = new OcspResponder(registryWithBroken, lookup, { onError: (e) => errors.push(e) });
            expect(parse(await r.respond(request([certId(h.issuerCert, "0123")]))).status).toBe(OCSPResponseStatus.internalError);
            expect((errors[0] as Error).message).toBe("HSM offline");
        });
    });

    describe("configuration", () => {
        it("honours validityHours and the injected clock", async () => {
            const { basic } = parse(await responder({ validityHours: 8 }).respond(request([certId(ec.issuerCert, "0123")])));
            expect(basic!.tbsResponseData.responses[0].nextUpdate!.toISOString()).toBe("2031-06-07T16:09:10.000Z");
        });

        it("defaults to the real clock", async () => {
            const r = new OcspResponder(registry, lookup);
            const { basic } = parse(await r.respond(request([certId(ec.issuerCert, "0123")])));
            expect(Math.abs(basic!.tbsResponseData.producedAt.getTime() - Date.now())).toBeLessThan(5000);
        });

        it.each([0, -1, 241, NaN])("rejects validityHours=%s", (hours) => {
            expect(() => new OcspResponder(registry, lookup, { validityHours: hours })).toThrow(/validityHours/);
        });
    });

    it.skipIf(!hasOpenssl)("interoperates with `openssl ocsp`: OpenSSL-built request in, OpenSSL-verified response out", async () => {
        const dir = tempDir();
        try {
            const bundle = put(dir, "bundle.pem", ec.rootCert.pem + ec.issuerCert.pem);
            const issuerFile = put(dir, "issuer.pem", ec.issuerCert.pem);
            const leafFile = put(dir, "leaf.pem", leaf.pem);
            const reqFile = `${dir}/req.der`;
            const build = openssl(["ocsp", "-issuer", issuerFile, "-cert", leafFile, "-reqout", reqFile, "-no_nonce"])!;
            expect(build.status).toBe(0);
            const { readFileSync } = await import("node:fs");
            // real clock: OpenSSL checks thisUpdate/nextUpdate against the current time
            const resp = await new OcspResponder(registry, lookup).respond(new Uint8Array(readFileSync(reqFile)));
            const respFile = put(dir, "resp.der", resp);
            const check = openssl(["ocsp", "-respin", respFile, "-issuer", issuerFile, "-cert", leafFile, "-CAfile", bundle, "-no_nonce", "-VAfile", issuerFile])!;
            expect(check.stdout + check.stderr).toMatch(/Response verify OK/);
            expect(check.stdout).toMatch(/leaf\.pem: good/);
            expect(check.stdout).toMatch(/This Update: /);
            expect(check.stdout).toMatch(/Next Update: /);

            // a serial that is revoked, checked through OpenSSL's parser as well
            const revokedResp = await new OcspResponder(registry, async () => ({ status: "revoked", revokedAt: new Date(Date.now() - DAY), reason: 1 })).respond(new Uint8Array(readFileSync(reqFile)));
            const revokedFile = put(dir, "revoked.der", revokedResp);
            const revoked = openssl(["ocsp", "-respin", revokedFile, "-issuer", issuerFile, "-cert", leafFile, "-CAfile", bundle, "-no_nonce", "-VAfile", issuerFile])!;
            expect(revoked.stdout).toMatch(/leaf\.pem: revoked/);
            expect(revoked.stdout).toMatch(/Reason: keyCompromise/);
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });

});
