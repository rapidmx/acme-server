///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { createHash } from "crypto";
import * as x509 from "@peculiar/x509";
import { DocDecorators, HttpRequest, HttpResponse, RouteDecorators } from "@rapidrest/service-core";
import { AcmeProblem } from "../lib/acme/AcmeProblem.js";
import { Issuer } from "../lib/pki/index.js";
import { AcmeResult, AcmeRoute } from "./AcmeRoute.js";
const { Description, Summary } = DocDecorators;
const { Get, Param, Request, Response, Route } = RouteDecorators;

/** How long the public trust material may be cached: CA certificates change on a scale of years. */
const CACHE = "public, max-age=86400";

/** The PEM of a certificate. */
function pem(cert: x509.X509Certificate): string {
    return cert.toString("pem").trim() + "\n";
}

/**
 * The public trust endpoints (docs/ARCHITECTURE.md, "Public trust endpoints"): everything a relying party needs to validate
 * a certificate this CA issued – the issuing CA certificates, the roots to trust, the public keys as JWKs, and the chains.
 * Unauthenticated and cacheable.
 *
 * @author Jean-Philippe Steinmetz
 */
@Route("/ca")
@Description("The CA certificates and public keys that validate issued certificates.")
export class CaRoute extends AcmeRoute {
    private urlsOf(issuer: Issuer): Record<string, string> {
        const urls = this.ctx.urls;
        return {
            certificate: urls.forPath(`/ca/${issuer.id}.crt`),
            pem: urls.forPath(`/ca/${issuer.id}.pem`),
            chain: urls.forPath(`/ca/${issuer.id}/chain.pem`),
            crl: urls.forPath(`/crl/${issuer.id}.crl`),
            ocsp: urls.forPath("/ocsp"),
        };
    }

    /** The certificate chain of `issuer`: the issuer, then every CA above it up to and including the root. */
    private chainOf(issuer: Issuer): x509.X509Certificate[] {
        return [issuer.certificate, ...issuer.chain];
    }

    @Summary("List the issuing CAs and roots")
    @Get()
    public async list(@Request req: HttpRequest, @Response res: HttpResponse): Promise<void> {
        await this.run(
            req,
            res,
            "endpointOther",
            async (): Promise<AcmeResult> => {
                const registry = this.ctx.registry;
                const active: Issuer = registry.active();
                return {
                    status: 200,
                    body: {
                        issuers: registry.all().map((issuer) => ({ ...issuer.info(), active: issuer.id === active.id, urls: this.urlsOf(issuer) })),
                        roots: registry.roots().map((root) => ({
                            subject: root.subject,
                            serialNumber: root.serialNumber.toLowerCase(),
                            notBefore: root.notBefore.toISOString(),
                            notAfter: root.notAfter.toISOString(),
                            sha256Fingerprint: createHash("sha256").update(Buffer.from(root.rawData)).digest("hex"),
                            pem: pem(root),
                        })),
                        bundles: { roots: this.ctx.urls.forPath("/ca/roots.pem"), chain: this.ctx.urls.forPath("/ca/chain.pem"), jwks: this.ctx.urls.forPath("/ca/jwks.json") },
                    },
                    cacheControl: CACHE,
                };
            },
            { nonce: false, plain: true },
        );
    }

    @Summary("Get a CA certificate, a bundle or the JWK set")
    @Get("/:file")
    public async file(@Param("file") file: string, @Request req: HttpRequest, @Response res: HttpResponse): Promise<void> {
        await this.run(
            req,
            res,
            "endpointOther",
            async (): Promise<AcmeResult> => {
                const registry = this.ctx.registry;
                if (file === "roots.pem") {
                    return { status: 200, raw: registry.roots().map(pem).join(""), contentType: "application/x-pem-file", cacheControl: CACHE };
                }
                if (file === "chain.pem") {
                    // Every issuer's chain, each CA once.
                    const seen: Set<string> = new Set();
                    const parts: string[] = [];
                    for (const issuer of registry.all()) {
                        for (const cert of this.chainOf(issuer)) {
                            const text: string = pem(cert);
                            if (!seen.has(text)) {
                                seen.add(text);
                                parts.push(text);
                            }
                        }
                    }
                    return { status: 200, raw: parts.join(""), contentType: "application/x-pem-file", cacheControl: CACHE };
                }
                if (file === "jwks.json") {
                    return { status: 200, body: { keys: registry.all().map((issuer) => issuer.info().jwk) }, contentType: "application/jwk-set+json", cacheControl: CACHE };
                }
                const match: RegExpExecArray | null = /^([a-z0-9][a-z0-9_-]{0,62})\.(crt|cer|der|pem)$/.exec(file);
                const issuer: Issuer | undefined = match ? registry.get(match[1]) : undefined;
                if (!match || !issuer) {
                    throw AcmeProblem.malformed("No such CA certificate.", 404);
                }
                if (match[2] === "pem") {
                    return { status: 200, raw: pem(issuer.certificate), contentType: "application/x-pem-file", cacheControl: CACHE };
                }
                // The AIA caIssuers target: DER, as RFC 5280 §4.2.2.1 wants.
                return { status: 200, raw: Buffer.from(issuer.certificate.rawData), contentType: "application/pkix-cert", cacheControl: CACHE };
            },
            { nonce: false, plain: true },
        );
    }

    @Summary("Get the certificate chain of one CA")
    @Get("/:id/chain.pem")
    public async chain(@Param("id") id: string, @Request req: HttpRequest, @Response res: HttpResponse): Promise<void> {
        await this.run(
            req,
            res,
            "endpointOther",
            async (): Promise<AcmeResult> => {
                const issuer: Issuer | undefined = this.ctx.registry.get(id);
                if (!issuer) {
                    throw AcmeProblem.malformed("No such CA.", 404);
                }
                return { status: 200, raw: this.chainOf(issuer).map(pem).join(""), contentType: "application/x-pem-file", cacheControl: CACHE };
            },
            { nonce: false, plain: true },
        );
    }
}
