///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import "./runtime.js";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import {
    AccessDescription,
    AttributeTypeAndValue,
    AttributeValue,
    AuthorityInfoAccessSyntax,
    AuthorityKeyIdentifier,
    BasicConstraints,
    Certificate,
    CRLDistributionPoints,
    DistributionPoint,
    DistributionPointName,
    ExtendedKeyUsage,
    Extension,
    Extensions,
    GeneralName,
    KeyIdentifier,
    KeyUsage,
    KeyUsageFlags,
    Name,
    OtherName,
    RelativeDistinguishedName,
    SubjectAlternativeName,
    SubjectKeyIdentifier,
    SubjectPublicKeyInfo,
    TBSCertificate,
    Validity,
    Version,
} from "@peculiar/asn1-x509";
import { certificateParts, keyIdentifierOf } from "./certutil.js";
import { checkPublicKey } from "./CsrValidator.js";
import { canonicalMailbox, derUtf8String, SMTP_UTF8_MAILBOX_OID } from "./mailbox.js";
import type { Issuer } from "./Issuer.js";
import { OID } from "./oids.js";
import { signatureAlgorithmIdentifier, signChecked, type CaSigner } from "./Signer.js";
import {
    bytesEqual,
    bytesToHex,
    derToPem,
    floorToSecond,
    randomSerial,
    serialBytesToHex,
    serialHexToDerContent,
    sha256Hex,
    toArrayBuffer,
} from "./util.js";

/** What a certificate may be used for: signing mail, encrypting mail, or both (RFC 8823 s3.3, RFC 8551). */
export type CertificateType = "signing" | "encryption" | "signing-encryption";

/** A leaf certificate to issue. */
export interface LeafCertificateRequest {
    /** DER SubjectPublicKeyInfo (from a validated CSR). */
    spki: Uint8Array;
    /**
     * The mailbox (ASCII or internationalized, U-labels or A-labels in the domain). An ASCII local part becomes an `rfc822Name`
     * SAN with the domain as A-labels; a non-ASCII local part becomes an `SmtpUTF8Mailbox` otherName (RFC 8398/8399). Either
     * way it is also the subject CN.
     */
    email: string;
    /** Selects the KeyUsage. */
    type: CertificateType;
    /** Start of validity (already back-dated by the caller). */
    notBefore: Date;
    /** End of validity. */
    notAfter: Date;
    /** A pre-allocated serial (1-20 octets, first octet 0x01-0x7f); random when omitted. */
    serial?: Uint8Array;
}

/** A certificate that was issued. */
export interface IssuedCertificate {
    der: Uint8Array;
    pem: string;
    /** Lower-case hex, no leading `00`. */
    serialHex: string;
    notBefore: Date;
    notAfter: Date;
    /** Lower-case hex SHA-256 of the DER. */
    sha256Fingerprint: string;
}

/** Absolute URLs written into a certificate's CRLDP and AIA extensions. */
export interface IssuerUrls {
    crl: string;
    caIssuers: string;
    ocsp: string;
}

/** The longest validity this library will sign for a subscriber certificate (the S/MIME BR mailbox-validated bound). */
export const MAX_LEAF_VALIDITY_DAYS = 825;

const DAY_MS = 86_400_000;
const CERTIFICATE_TYPES: readonly CertificateType[] = ["signing", "encryption", "signing-encryption"];
/** Longest value the X.520 `ub-common-name` bound (RFC 5280 Appendix A) allows in a subject CN. */
const MAX_CN_OCTETS = 64;

/**
 * The KeyUsage bits of an S/MIME certificate (RFC 8551, the Baseline Requirements' S/MIME profile). RSA encrypts by
 * key transport (`keyEncipherment`), elliptic-curve keys by key agreement (`keyAgreement`); signing certificates
 * carry `digitalSignature` and `nonRepudiation` (contentCommitment).
 *
 * @param type The certificate type.
 * @param keyKind The subject key family.
 */
export function keyUsageFor(type: CertificateType, keyKind: "rsa" | "ec"): string[] {
    if (!CERTIFICATE_TYPES.includes(type)) {
        throw new Error(`Unknown certificate type ${String(type)}`);
    }
    if (keyKind !== "rsa" && keyKind !== "ec") {
        throw new Error(`Unknown key kind ${String(keyKind)}`);
    }
    const encryption = keyKind === "rsa" ? "keyEncipherment" : "keyAgreement";
    switch (type) {
        case "signing":
            return ["digitalSignature", "nonRepudiation"];
        case "encryption":
            return [encryption];
        default:
            return ["digitalSignature", "nonRepudiation", encryption];
    }
}

const KEY_USAGE_FLAGS: Record<string, number> = {
    digitalSignature: KeyUsageFlags.digitalSignature,
    nonRepudiation: KeyUsageFlags.nonRepudiation,
    keyEncipherment: KeyUsageFlags.keyEncipherment,
    keyAgreement: KeyUsageFlags.keyAgreement,
    keyCertSign: KeyUsageFlags.keyCertSign,
    cRLSign: KeyUsageFlags.cRLSign,
};

function ext(extnID: string, critical: boolean, value: unknown): Extension {
    return new Extension({ extnID, critical, extnValue: new OctetString(AsnConvert.serialize(value)) });
}

function checkUrl(url: string, what: string): string {
    if (typeof url !== "string" || url.length > 2048 || !/^https?:\/\/[\x21-\x7e]+$/.test(url)) {
        throw new Error(`Invalid ${what} URL ${JSON.stringify(String(url).slice(0, 100))}`);
    }
    try {
        new URL(url);
    } catch {
        throw new Error(`Invalid ${what} URL ${JSON.stringify(url.slice(0, 100))}`);
    }
    return url;
}

function uri(url: string): GeneralName {
    return new GeneralName({ uniformResourceIdentifier: url });
}

/** The CRLDP and AIA extensions for the given (possibly partial) URLs. */
function locationExtensions(urls: Partial<IssuerUrls> | undefined): Extension[] {
    const out: Extension[] = [];
    if (!urls) {
        return out;
    }
    if (urls.crl !== undefined) {
        out.push(
            ext(
                OID.cRLDistributionPoints,
                false,
                new CRLDistributionPoints([
                    new DistributionPoint({
                        distributionPoint: new DistributionPointName({ fullName: [uri(checkUrl(urls.crl, "CRL"))] }),
                    }),
                ])
            )
        );
    }
    const access: AccessDescription[] = [];
    if (urls.caIssuers !== undefined) {
        access.push(
            new AccessDescription({ accessMethod: OID.adCaIssuers, accessLocation: uri(checkUrl(urls.caIssuers, "caIssuers")) })
        );
    }
    if (urls.ocsp !== undefined) {
        access.push(new AccessDescription({ accessMethod: OID.adOcsp, accessLocation: uri(checkUrl(urls.ocsp, "OCSP")) }));
    }
    if (access.length > 0) {
        out.push(ext(OID.authorityInfoAccess, false, new AuthorityInfoAccessSyntax(access)));
    }
    return out;
}

/**
 * Parses an RFC 4514-style distinguished name into an ASN.1 `Name`. RDNs are written in the order they appear in the
 * certificate (most significant first: `C=US, O=RapidMX, CN=RapidMX Root`), separated by commas; `\` escapes `, + " \ < > ; = #`
 * and `\XX` is a hex octet. Multi-valued RDNs are not supported. Country and serialNumber are PrintableString,
 * domainComponent is IA5String, everything else is UTF8String, as the Baseline Requirements require.
 *
 * @param dn The distinguished name.
 * @throws Error on any syntax or value problem.
 */
export function parseDistinguishedName(dn: string): Name {
    if (typeof dn !== "string" || dn.trim().length === 0 || dn.length > 512) {
        throw new Error("Invalid distinguished name");
    }
    const parts: string[] = [];
    let current = "";
    for (let i = 0; i < dn.length; i++) {
        const c = dn[i];
        if (c === "\\") {
            if (i + 1 >= dn.length) {
                throw new Error("Invalid distinguished name: dangling escape");
            }
            current += c + dn[++i];
        } else if (c === ",") {
            parts.push(current);
            current = "";
        } else {
            current += c;
        }
    }
    parts.push(current);

    const types: Record<string, { oid: string; kind: "utf8" | "printable" | "ia5"; max: number }> = {
        CN: { oid: OID.commonName, kind: "utf8", max: 64 },
        O: { oid: OID.organizationName, kind: "utf8", max: 64 },
        OU: { oid: OID.organizationalUnitName, kind: "utf8", max: 64 },
        C: { oid: OID.countryName, kind: "printable", max: 2 },
        L: { oid: OID.localityName, kind: "utf8", max: 128 },
        ST: { oid: OID.stateOrProvinceName, kind: "utf8", max: 128 },
        SERIALNUMBER: { oid: OID.serialNumber, kind: "printable", max: 64 },
        DC: { oid: OID.domainComponent, kind: "ia5", max: 63 },
    };
    const rdns = parts.map((part) => {
        const eq = part.indexOf("=");
        if (eq < 1) {
            throw new Error(`Invalid distinguished name component ${JSON.stringify(part.trim())}`);
        }
        const spec = types[part.slice(0, eq).trim().toUpperCase()];
        if (!spec) {
            throw new Error(`Unsupported distinguished name attribute ${JSON.stringify(part.slice(0, eq).trim())}`);
        }
        const raw = part.slice(eq + 1).trim();
        if (/(^|[^\\])\+/.test(raw)) {
            throw new Error("Multi-valued RDNs are not supported");
        }
        const value = raw.replace(/\\([0-9a-fA-F]{2}|.)/g, (_m, g: string) =>
            g.length === 2 && /^[0-9a-fA-F]{2}$/.test(g) ? String.fromCharCode(parseInt(g, 16)) : g
        );
        // eslint-disable-next-line no-control-regex
        if (value.length === 0 || value.length > spec.max || /[\u0000-\u001f\u007f]/.test(value)) {
            throw new Error(`Invalid value for distinguished name attribute ${part.slice(0, eq).trim()}`);
        }
        const attrValue = new AttributeValue();
        if (spec.kind === "printable") {
            if (!/^[A-Za-z0-9 '()+,\-./:=?]+$/.test(value) || (spec.oid === OID.countryName && !/^[A-Z]{2}$/.test(value))) {
                throw new Error(`Invalid value for distinguished name attribute ${part.slice(0, eq).trim()}`);
            }
            attrValue.printableString = value;
        } else if (spec.kind === "ia5") {
            if (!/^[\x20-\x7e]+$/.test(value)) {
                throw new Error(`Invalid value for distinguished name attribute ${part.slice(0, eq).trim()}`);
            }
            attrValue.ia5String = value;
        } else {
            attrValue.utf8String = value;
        }
        return new RelativeDistinguishedName([new AttributeTypeAndValue({ type: spec.oid, value: attrValue })]);
    });
    return new Name(rdns);
}

function checkValidity(notBefore: Date, notAfter: Date, issuerNotAfter: Date, maxDays?: number): { nb: Date; na: Date } {
    if (!(notBefore instanceof Date) || !(notAfter instanceof Date) || isNaN(notBefore.getTime()) || isNaN(notAfter.getTime())) {
        throw new Error("Invalid validity dates");
    }
    const nb = floorToSecond(notBefore);
    const na = floorToSecond(notAfter);
    if (na.getTime() <= nb.getTime()) {
        throw new Error("notAfter must be after notBefore");
    }
    if (maxDays !== undefined && na.getTime() - nb.getTime() > maxDays * DAY_MS) {
        throw new Error(`Validity may not exceed ${maxDays} days`);
    }
    if (na.getTime() > issuerNotAfter.getTime()) {
        throw new Error("The certificate would outlive its issuer");
    }
    return { nb, na };
}

function issuerName(subjectDer: Uint8Array): Name {
    const name = AsnConvert.parse(subjectDer, Name);
    if (!bytesEqual(new Uint8Array(AsnConvert.serialize(name)), subjectDer)) {
        // The issuer field must repeat the issuer certificate's subject byte for byte (RFC 5280 s4.1.2.4).
        throw new Error("The issuer's subject name cannot be re-encoded identically");
    }
    return name;
}

function subjectPublicKeyInfo(spki: Uint8Array): SubjectPublicKeyInfo {
    const parsed = AsnConvert.parse(spki, SubjectPublicKeyInfo);
    if (!bytesEqual(new Uint8Array(AsnConvert.serialize(parsed)), spki)) {
        throw new Error("The SubjectPublicKeyInfo is not canonical DER");
    }
    return parsed;
}

async function signAndAssemble(signer: CaSigner, tbs: TBSCertificate): Promise<IssuedCertificate> {
    const tbsDer = new Uint8Array(AsnConvert.serialize(tbs));
    const signature = await signChecked(signer, tbsDer);
    const certificate = new Certificate({
        tbsCertificate: tbs,
        signatureAlgorithm: signatureAlgorithmIdentifier(signer.algorithm),
        signatureValue: toArrayBuffer(signature),
    });
    const der = new Uint8Array(AsnConvert.serialize(certificate));
    if (!bytesEqual(certificateParts(der).tbs, tbsDer)) {
        throw new Error("Internal error: the assembled certificate does not contain the signed TBS bytes");
    }
    const serial = serialBytesToHex(certificateParts(der).serial);
    if (serial === undefined) {
        throw new Error("Internal error: unusable serial number");
    }
    return {
        der,
        pem: derToPem(der, "CERTIFICATE"),
        serialHex: serial,
        notBefore: tbs.validity.notBefore.getTime(),
        notAfter: tbs.validity.notAfter.getTime(),
        sha256Fingerprint: sha256Hex(der),
    };
}

/**
 * Issues an S/MIME subscriber certificate signed by `issuer`.
 *
 * The certificate follows the CA/Browser Forum S/MIME mailbox-validated profile where practical: version 3; a random
 * 159-bit serial; subject `CN=<email>` and nothing else (or, when the address is longer than the 64-octet X.520 CN
 * bound, an empty subject and a *critical* SAN as RFC 5280 s4.1.2.6 demands); SAN with the single `rfc822Name`; critical
 * KeyUsage from {@link keyUsageFor}; EKU `emailProtection` only; critical `CA:FALSE`; SKI (SHA-1 of the key) and AKI (the
 * issuer's key id); CRL distribution point and AIA (`caIssuers`, `ocsp`). No CA/B Forum policy OIDs are asserted: this CA is
 * not audited. Nothing is taken from a CSR except the public key, which is re-validated here (defence in depth).
 *
 * The validity must be at most 825 days, and must not extend past the issuer's own `notAfter`; the signature is
 * verified against the issuer's public key before the certificate is returned.
 *
 * @param issuer The issuing CA.
 * @param urls Absolute CRL / caIssuers / OCSP URLs to embed.
 * @param req The certificate to issue.
 * @throws PkiPolicyError badPublicKey for an unacceptable key; Error for any other invalid input.
 */
export async function issueLeafCertificate(
    issuer: Issuer,
    urls: IssuerUrls,
    req: LeafCertificateRequest
): Promise<IssuedCertificate> {
    if (!CERTIFICATE_TYPES.includes(req.type)) {
        throw new Error(`Unknown certificate type ${String(req.type)}`);
    }
    const mailbox = canonicalMailbox(req.email);
    if (mailbox === undefined) {
        throw new Error("The e-mail address is not acceptable for a certificate");
    }
    const email: string = mailbox.certificateName;
    const { keyKind } = checkPublicKey(req.spki);
    const { nb, na } = checkValidity(req.notBefore, req.notAfter, issuer.certificate.notAfter, MAX_LEAF_VALIDITY_DAYS);

    let serial: Uint8Array;
    if (req.serial) {
        if (req.serial.length < 1 || req.serial.length > 20 || req.serial[0] === 0 || (req.serial[0] & 0x80) !== 0) {
            throw new Error("A serial must be 1-20 octets, positive, without leading zero octets");
        }
        serial = req.serial;
    } else {
        serial = randomSerial();
    }

    const flags = keyUsageFor(req.type, keyKind).reduce((acc, name) => acc | KEY_USAGE_FLAGS[name], 0);
    const useCn = Buffer.byteLength(email, "utf8") <= MAX_CN_OCTETS;
    const subject = new Name();
    if (useCn) {
        subject.push(
            new RelativeDistinguishedName([
                new AttributeTypeAndValue({ type: OID.commonName, value: new AttributeValue({ utf8String: email }) }),
            ])
        );
    }

    const tbs = new TBSCertificate({
        version: Version.v3,
        serialNumber: toArrayBuffer(serialHexToDerContent(bytesToHex(serial))),
        signature: signatureAlgorithmIdentifier(issuer.signer.algorithm),
        issuer: issuerName(issuer.subjectDer),
        validity: new Validity({ notBefore: nb, notAfter: na }),
        subject,
        subjectPublicKeyInfo: subjectPublicKeyInfo(req.spki),
        extensions: new Extensions([
            ext(OID.basicConstraints, true, new BasicConstraints({ cA: false })),
            ext(OID.keyUsage, true, new KeyUsage(flags)),
            ext(OID.extKeyUsage, false, new ExtendedKeyUsage([OID.kpEmailProtection])),
            // RFC 5280 s4.1.2.6: with an empty subject the SAN is the only identity and MUST be critical.
            ext(
                OID.subjectAltName,
                !useCn,
                new SubjectAlternativeName([
                    mailbox.form === "smtputf8"
                        ? new GeneralName({ otherName: new OtherName({ typeId: SMTP_UTF8_MAILBOX_OID, value: toArrayBuffer(derUtf8String(email)) }) })
                        : new GeneralName({ rfc822Name: email }),
                ]),
            ),
            ext(OID.subjectKeyIdentifier, false, new SubjectKeyIdentifier(keyIdentifierOf(req.spki))),
            ext(OID.authorityKeyIdentifier, false, new AuthorityKeyIdentifier({ keyIdentifier: new KeyIdentifier(issuer.keyId) })),
            ...locationExtensions(urls),
        ]),
    });
    return signAndAssemble(issuer.signer, tbs);
}

/**
 * Builds a CA certificate: a self-signed root (`issuer` undefined) or an intermediate signed by `issuer`.
 *
 * Extensions: critical `CA:TRUE` (with `pathLenConstraint` when `pathLen` is given: use 0 for an issuing CA), critical
 * KeyUsage `keyCertSign`+`cRLSign`, SKI, AKI, optionally EKU `emailProtection` (technical constraint of an S/MIME
 * issuing CA, so that a compromised issuer cannot mint TLS certificates) and CRLDP/AIA when `urls` are given (an
 * intermediate should point at its *parent's* CRL and certificate; a root has none).
 *
 * `signer` must hold the key that signs the certificate: the root's own key when self-signed, the parent's key otherwise; a
 * mismatch is rejected instead of producing a certificate nobody can verify.
 *
 * @param o Subject, key, validity and signing parameters. `subject` is an RFC 4514-style string, see {@link parseDistinguishedName}.
 * @throws Error on invalid input.
 */
export async function buildCaCertificate(o: {
    subject: string;
    subjectSpki: Uint8Array;
    issuer?: Issuer;
    signer: CaSigner;
    notBefore: Date;
    notAfter: Date;
    pathLen?: number;
    urls?: Partial<IssuerUrls>;
    ekuEmailProtection?: boolean;
}): Promise<IssuedCertificate> {
    checkPublicKey(o.subjectSpki);
    const subject = parseDistinguishedName(o.subject);
    const subjectKeyId = keyIdentifierOf(o.subjectSpki);
    if (o.pathLen !== undefined && (!Number.isInteger(o.pathLen) || o.pathLen < 0 || o.pathLen > 10)) {
        throw new Error("pathLen must be an integer between 0 and 10");
    }
    let authorityKeyId: Uint8Array;
    let issuerNameValue: Name;
    let issuerNotAfter: Date;
    if (o.issuer) {
        if (!bytesEqual(o.signer.spki, o.issuer.signer.spki)) {
            throw new Error("The signer is not the issuer's key");
        }
        authorityKeyId = o.issuer.keyId;
        issuerNameValue = issuerName(o.issuer.subjectDer);
        issuerNotAfter = o.issuer.certificate.notAfter;
    } else {
        if (!bytesEqual(o.signer.spki, o.subjectSpki)) {
            throw new Error("A self-signed certificate must be signed with its own key");
        }
        authorityKeyId = subjectKeyId;
        issuerNameValue = parseDistinguishedName(o.subject);
        issuerNotAfter = new Date(8640000000000000);
    }
    const { nb, na } = checkValidity(o.notBefore, o.notAfter, issuerNotAfter);

    const extensions: Extension[] = [
        ext(OID.subjectKeyIdentifier, false, new SubjectKeyIdentifier(subjectKeyId)),
        ext(OID.authorityKeyIdentifier, false, new AuthorityKeyIdentifier({ keyIdentifier: new KeyIdentifier(authorityKeyId) })),
        ext(OID.basicConstraints, true, new BasicConstraints({ cA: true, pathLenConstraint: o.pathLen })),
        ext(OID.keyUsage, true, new KeyUsage(KeyUsageFlags.keyCertSign | KeyUsageFlags.cRLSign)),
    ];
    if (o.ekuEmailProtection) {
        extensions.push(ext(OID.extKeyUsage, false, new ExtendedKeyUsage([OID.kpEmailProtection])));
    }
    extensions.push(...locationExtensions(o.urls));

    const tbs = new TBSCertificate({
        version: Version.v3,
        serialNumber: toArrayBuffer(serialHexToDerContent(bytesToHex(randomSerial()))),
        signature: signatureAlgorithmIdentifier(o.signer.algorithm),
        issuer: issuerNameValue,
        validity: new Validity({ notBefore: nb, notAfter: na }),
        subject,
        subjectPublicKeyInfo: subjectPublicKeyInfo(o.subjectSpki),
        extensions: new Extensions(extensions),
    });
    return signAndAssemble(o.signer, tbs);
}
