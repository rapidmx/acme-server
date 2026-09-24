///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { DocDecorators, HttpRequest, HttpResponse, RouteDecorators } from "@rapidrest/service-core";
import { AcmeProblem } from "../lib/acme/AcmeProblem.js";
import { AcmeCertificate } from "../models/AcmeCertificate.js";
import { AcmeResult, AcmeRoute } from "./AcmeRoute.js";
const { Description, Summary } = DocDecorators;
const { Get, Param, Request, Response, Route } = RouteDecorators;

/**
 * A public look-up of an issued certificate by serial number: the certificate chain as PEM, or JSON with its status.
 * Certificates are public by nature; the look-up key is the serial only, so it cannot be used to find out which addresses
 * have certificates.
 *
 * @author Jean-Philippe Steinmetz
 */
@Route("/certs")
@Description("Look up an issued certificate by serial number.")
export class CertificateLookupRoute extends AcmeRoute {
    @Summary("Get an issued certificate by serial")
    @Get("/:serial")
    public async get(@Param("serial") serial: string, @Request req: HttpRequest, @Response res: HttpResponse): Promise<void> {
        await this.run(
            req,
            res,
            "endpointOther",
            async (): Promise<AcmeResult> => {
                if (!/^[0-9a-fA-F]{1,80}$/.test(serial)) {
                    throw AcmeProblem.malformed("The serial must be hexadecimal.", 404);
                }
                const cert: AcmeCertificate | null = await this.ctx.certificates.findBySerial(serial);
                if (!cert) {
                    throw AcmeProblem.malformed("No such certificate.", 404);
                }
                const wantsJson: boolean = String(req.headers["accept"] ?? "").includes("application/json");
                const headers: Record<string, string> = { "x-certificate-status": cert.status };
                if (wantsJson) {
                    return {
                        status: 200,
                        body: {
                            serial: cert.serial,
                            status: cert.status,
                            type: cert.certificateType,
                            issuer: cert.issuerId,
                            notBefore: cert.notBefore.toISOString(),
                            notAfter: cert.notAfter.toISOString(),
                            sha256Fingerprint: cert.sha256Fingerprint,
                            ...(cert.status === "revoked" ? { revokedAt: cert.revokedAt?.toISOString(), reason: cert.revocationReason } : {}),
                            renewalInfo: this.ctx.urls.renewalInfo(this.ctx.certificates.ariId(cert)),
                            pem: this.ctx.certificates.chainPem(cert),
                        },
                        headers,
                        cacheControl: "public, max-age=300",
                    };
                }
                return { status: 200, raw: this.ctx.certificates.chainPem(cert), contentType: "application/pem-certificate-chain", headers, cacheControl: "public, max-age=300" };
            },
            { nonce: false, plain: true },
        );
    }
}
