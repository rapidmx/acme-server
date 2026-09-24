///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////

/**
 * The certificate profiles offered in the directory's `meta.profiles` (draft-aaron-acme-profiles) and accepted in an order's
 * `profile`, with the description shown to clients.
 *
 * Kept under `lib/`, which RapidREST's class loader does not scan: it stamps a `fqn` property on every object a scanned module
 * exports, which would leak into the directory JSON if this constant lived beside the routes.
 */
export const PROFILE_DESCRIPTIONS: Readonly<Record<string, string>> = {
    signing: "An S/MIME certificate for signing mail: digital signature and non-repudiation.",
    encryption: "An S/MIME certificate for receiving encrypted mail: key encipherment (RSA) or key agreement (EC).",
    "signing-encryption": "One S/MIME certificate for both signing and encryption.",
};
