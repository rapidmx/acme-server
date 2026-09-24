///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import type { CertificateTypeName } from "../models/AcmeOrder.js";
import type { RateLimitOverride } from "../lib/acme/RateLimits.js";

/** Minimal shape of the `nconf` object the settings read from. */
export interface SettingsSource {
    get(key: string): any;
}

/**
 * Typed, defaulted access to the `acme.*` configuration (see docs/ARCHITECTURE.md). Reads each key by its full path
 * instead of taking the whole `acme` object: nconf does not merge a nested object across the environment and the
 * defaults, so `acme__external_url` set in the environment would otherwise hide every other default under `acme`.
 *
 * @author Jean-Philippe Steinmetz
 */
export class AcmeSettings {
    private readonly source: SettingsSource;

    constructor(source: SettingsSource) {
        this.source = source;
    }

    private str(path: string, fallback: string): string {
        const value: unknown = this.source.get(`acme:${path}`);
        return typeof value === "string" && value !== "" ? value : fallback;
    }

    private num(path: string, fallback: number): number {
        const value: unknown = this.source.get(`acme:${path}`);
        const n: number = typeof value === "number" ? value : Number(value);
        return Number.isFinite(n) && value !== undefined && value !== "" && value !== null ? n : fallback;
    }

    private bool(path: string, fallback: boolean): boolean {
        const value: unknown = this.source.get(`acme:${path}`);
        return typeof value === "boolean" ? value : value === "true" ? true : value === "false" ? false : fallback;
    }

    /** The public base URL, no trailing slash. */
    public get externalUrl(): string {
        return this.str("external_url", "http://localhost:3000").replace(/\/+$/, "");
    }

    public get termsOfServiceUrl(): string {
        return this.str("terms_of_service_url", `${this.externalUrl}/terms`);
    }

    public get website(): string {
        return this.str("website", "https://rapidmx.io");
    }

    public get caaIdentities(): string[] {
        const value: unknown = this.source.get("acme:caa_identities");
        return Array.isArray(value) ? value.map(String) : typeof value === "string" && value !== "" ? value.split(",").map((s) => s.trim()) : ["rapidmx.io"];
    }

    public get orderExpiryHours(): number {
        return this.num("order_expiry_hours", 168);
    }

    public get authorizationExpiryHours(): number {
        return this.num("authorization_expiry_hours", 168);
    }

    public get nonceTtlSeconds(): number {
        return this.num("nonce_ttl_seconds", 3600);
    }

    public get maxIdentifiers(): number {
        return Math.max(1, Math.floor(this.num("max_identifiers", 1)));
    }

    public get caManifest(): string {
        return this.str("ca:manifest", "/var/lib/acme/ca/issuers.json");
    }

    public get backdateMinutes(): number {
        return this.num("ca:backdate_minutes", 60);
    }

    public validityDays(type: CertificateTypeName): number {
        return this.num(`ca:profiles:${type}:validity_days`, 90);
    }

    public get crlRefreshHours(): number {
        return this.num("ca:crl_refresh_hours", 12);
    }

    public get crlValidityHours(): number {
        return this.num("ca:crl_validity_hours", 168);
    }

    public get ocspValidityHours(): number {
        return this.num("ca:ocsp_validity_hours", 24);
    }

    public get mailFrom(): string {
        return this.str("mail:from", "acme-challenge@acme.localdomain");
    }

    public get mailReplyTo(): string {
        return this.str("mail:reply_to", "acme-response@acme.localdomain");
    }

    /** `strict` (DKIM d= equals the From domain) or `relaxed` (d= may be a parent of it). */
    public get dkimAlignment(): "strict" | "relaxed" {
        return this.str("mail:dkim_alignment", "strict") === "relaxed" ? "relaxed" : "strict";
    }

    public get inboundHttpSecret(): string {
        return this.str("mail:inbound:http_secret", "");
    }

    public get inboundSmtpEnabled(): boolean {
        return this.bool("mail:inbound:smtp:enabled", false);
    }

    public get inboundSmtpHost(): string {
        return this.str("mail:inbound:smtp:host", "0.0.0.0");
    }

    public get inboundSmtpPort(): number {
        return this.num("mail:inbound:smtp:port", 2525);
    }

    public get inboundSmtpMaxSizeBytes(): number {
        return this.num("mail:inbound:smtp:max_size_bytes", 1024 * 1024);
    }

    public get inboundSmtpTls(): { key: string; cert: string } | undefined {
        const key: string = this.str("mail:inbound:smtp:tls_key_path", "");
        const cert: string = this.str("mail:inbound:smtp:tls_cert_path", "");
        return key && cert ? { key, cert } : undefined;
    }

    public get dnsServers(): string[] {
        const value: unknown = this.source.get("acme:dns:servers");
        return Array.isArray(value) ? value.map(String) : [];
    }

    /** `validate` (default): CAA is looked up and DNSSEC-validated in-process; `off` uses the system resolver unvalidated. */
    public get dnssecValidation(): boolean {
        return this.str("acme:dns:dnssec", "validate").toLowerCase() !== "off";
    }

    /** Whether the account holders are sent expiry reminders (default: yes). */
    public get remindersEnabled(): boolean {
        return this.bool("reminders:enabled", true);
    }

    /** The most certificates one maintenance run sends reminders for. */
    public get reminderBatchSize(): number {
        return Math.max(1, Math.floor(this.num("reminders:batch_size", 500)));
    }

    public get rateLimitsEnabled(): boolean {
        return this.bool("rate_limits:enabled", true);
    }

    public get rateLimitOverrides(): RateLimitOverride[] {
        const value: unknown = this.source.get("acme:rate_limits:overrides");
        return Array.isArray(value) ? (value as RateLimitOverride[]) : [];
    }

    /** Bearer secret of the operator API (`/admin`). Unset = the API does not exist (404). */
    public get adminSecret(): string {
        return this.str("admin_secret", "");
    }

    public get metricsSecret(): string {
        return this.str("metrics_secret", "");
    }

    /** Whether the deployment is a development one (NODE_ENV dev/development/test). */
    public get development(): boolean {
        return ["dev", "development", "test"].includes(process.env.NODE_ENV ?? "");
    }
}
