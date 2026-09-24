///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////

/**
 * Object identifiers used by the PKI library, in one place so a typo cannot silently produce a certificate that
 * names a different algorithm or extension than intended.
 */
export const OID = {
    // Public key algorithms and curves
    rsaEncryption: "1.2.840.113549.1.1.1",
    ecPublicKey: "1.2.840.10045.2.1",
    prime256v1: "1.2.840.10045.3.1.7",
    secp384r1: "1.3.132.0.34",
    secp521r1: "1.3.132.0.35",

    // Signature algorithms
    ecdsaWithSHA256: "1.2.840.10045.4.3.2",
    ecdsaWithSHA384: "1.2.840.10045.4.3.3",
    ecdsaWithSHA512: "1.2.840.10045.4.3.4",
    sha256WithRSAEncryption: "1.2.840.113549.1.1.11",
    sha384WithRSAEncryption: "1.2.840.113549.1.1.12",
    sha512WithRSAEncryption: "1.2.840.113549.1.1.13",

    // Digests (OCSP CertID hash algorithms)
    sha1: "1.3.14.3.2.26",
    sha256: "2.16.840.1.101.3.4.2.1",
    sha384: "2.16.840.1.101.3.4.2.2",
    sha512: "2.16.840.1.101.3.4.2.3",

    // Distinguished name attributes
    commonName: "2.5.4.3",
    countryName: "2.5.4.6",
    localityName: "2.5.4.7",
    stateOrProvinceName: "2.5.4.8",
    organizationName: "2.5.4.10",
    organizationalUnitName: "2.5.4.11",
    serialNumber: "2.5.4.5",
    domainComponent: "0.9.2342.19200300.100.1.25",

    // Extensions
    subjectKeyIdentifier: "2.5.29.14",
    keyUsage: "2.5.29.15",
    subjectAltName: "2.5.29.17",
    basicConstraints: "2.5.29.19",
    cRLNumber: "2.5.29.20",
    cRLReason: "2.5.29.21",
    cRLDistributionPoints: "2.5.29.31",
    authorityKeyIdentifier: "2.5.29.35",
    extKeyUsage: "2.5.29.37",
    authorityInfoAccess: "1.3.6.1.5.5.7.1.1",
    ocspNonce: "1.3.6.1.5.5.7.48.1.2",

    // Access methods and key purposes
    adOcsp: "1.3.6.1.5.5.7.48.1",
    adCaIssuers: "1.3.6.1.5.5.7.48.2",
    kpEmailProtection: "1.3.6.1.5.5.7.3.4",
    ocspBasic: "1.3.6.1.5.5.7.48.1.1",

    // PKCS #5 / #8 (encrypted private key at rest)
    pbes2: "1.2.840.113549.1.5.13",
    pbkdf2: "1.2.840.113549.1.5.12",
    hmacWithSHA256: "1.2.840.113549.2.9",
    aes256Cbc: "2.16.840.1.101.3.4.1.42",
} as const;
