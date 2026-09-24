///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////

/** Minimal shape of the `nconf` config object the startup guard needs. */
export interface GuardedConfig {
    get(key: string): unknown;
}

/**
 * `NODE_ENV` values under which the service may run with development settings (`http://localhost` URLs, an unset
 * inbound secret, ...). Anything else, including an unset `NODE_ENV`, is treated as a real deployment: this is a
 * certificate authority, so a misconfigured production must fail to start rather than issue with a wrong URL in the
 * certificates it signs.
 */
export const DEVELOPMENT_ENVIRONMENTS: readonly string[] = ["dev", "development", "test"];

/**
 * Refuses to start a real deployment whose settings would put wrong or unsafe values into issued certificates or into
 * the URLs handed to ACME clients.
 *
 * @param config The loaded runtime configuration.
 * @param environment The raw `NODE_ENV`.
 * @throws If `acme.external_url` is not a plain `https://` origin, the challenge mail addresses are still the placeholders,
 * or there is no SMTP relay or no DKIM key to send the verification e-mail with.
 */
export function assertProductionConfig(config: GuardedConfig, environment: string | undefined): void {
    if (environment !== undefined && DEVELOPMENT_ENVIRONMENTS.includes(environment)) {
        return;
    }

    const problems: string[] = [];
    const externalUrl: string = String(config.get("acme:external_url") ?? "");
    try {
        const url: URL = new URL(externalUrl);
        if (url.protocol !== "https:") {
            problems.push("acme:external_url (env acme__external_url) must be an https:// URL");
        }
        if (url.username || url.password || url.search || url.hash || url.pathname.replace(/\/+$/, "") !== "") {
            problems.push("acme:external_url must be a bare origin without credentials, path, query or fragment");
        }
    } catch {
        problems.push("acme:external_url (env acme__external_url) is not set to a valid URL");
    }
    for (const key of ["from", "reply_to"]) {
        const value: string = String(config.get(`acme:mail:${key}`) ?? "");
        if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(value) || /@(?:[^@]*\.)?(?:localhost|localdomain|local)$/i.test(value)) {
            problems.push(`acme:mail:${key} (env acme__mail__${key}) must be a real address on this CA's domain`);
        }
    }

    const adminSecret: string = String(config.get("acme:admin_secret") ?? "");
    if (adminSecret !== "" && adminSecret.length < 32) {
        problems.push("acme:admin_secret (env acme__admin_secret) must be at least 32 characters: it can revoke every certificate this CA issued");
    }
    if (String(config.get("acme:dns:dnssec") ?? "validate").toLowerCase() === "off") {
        problems.push("acme:dns:dnssec is off: CAA policy must be DNSSEC-validated by a public CA (RFC 8659 §3.1)");
    }
    if (String(config.get("acme:rate_limits:enabled")) === "false") {
        problems.push("acme:rate_limits:enabled is false: a public CA that sends mail to strangers' addresses must be rate limited");
    }
    // RFC 8823: the verification e-mail must be signed, and it must be sent at all.
    const text = (key: string): string => String(config.get(`acme:mail:${key}`) ?? "").trim();
    if (text("smtp:url") === "" && text("smtp:host") === "") {
        problems.push("no outbound SMTP relay is configured (acme:mail:smtp:url or acme:mail:smtp:host), so verification e-mails cannot be sent");
    }
    if (text("dkim:domain") === "" || text("dkim:selector") === "" || (text("dkim:private_key_path") === "" && text("dkim:private_key") === "")) {
        problems.push("DKIM signing of the verification e-mail is not configured (acme:mail:dkim:domain, selector and private_key_path), which RFC 8823 requires");
    }

    if (problems.length > 0) {
        throw new Error(
            `Refusing to start (NODE_ENV=${environment ?? "unset"}): ${problems.join("; ")}. ` +
                `Set NODE_ENV to one of ${DEVELOPMENT_ENVIRONMENTS.join("/")} for local development.`
        );
    }
}
