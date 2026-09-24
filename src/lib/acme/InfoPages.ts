///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { LimitDefinition, LimitName } from "./RateLimits.js";

/** Escapes text for HTML. */
function esc(text: string): string {
    return text.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string);
}

const STYLE =
    "body{font:16px/1.5 system-ui,sans-serif;max-width:46rem;margin:2rem auto;padding:0 1rem;color:#1b1f24}" +
    "h1,h2{line-height:1.2}code{background:#eef1f4;padding:.1em .3em;border-radius:3px}table{border-collapse:collapse;width:100%}" +
    "th,td{border-bottom:1px solid #d6dbe0;padding:.4rem .5rem;text-align:left}";

function page(title: string, body: string): string {
    return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title><style>${STYLE}</style></head><body>${body}</body></html>`;
}

/**
 * The terms of service page the directory's `meta.termsOfService` points at.
 *
 * This text is a **starting point for the operator**, not legal advice: whoever runs a public instance must review it (and the
 * certificate policy in docs/CPS.md) with counsel before offering the service to others.
 */
export function renderTerms(o: { externalUrl: string; caIdentities: string[]; website: string }): string {
    return page(
        "Terms of service",
        `<h1>Terms of service</h1>
<p>This service issues S/MIME certificates for e-mail addresses using the ACME protocol (RFC 8555, RFC 8823).
By creating an account you agree to the following.</p>
<h2>What you may request</h2>
<p>Only certificates for e-mail addresses that you control. Control is proved by replying to a verification e-mail; you must
not request certificates for addresses that are not yours, and you must not use the service to send unsolicited
verification e-mails to third parties.</p>
<h2>What you get</h2>
<p>Certificates issued here are valid for a short period and are meant to be renewed automatically. They chain to the root
published at <a href="${esc(o.externalUrl)}/ca">${esc(o.externalUrl)}/ca</a>. That root is <strong>not</strong> included in
operating system, browser or mail client trust stores; a relying party has to choose to trust it.</p>
<h2>Your responsibilities</h2>
<p>Keep your private keys secret. If a key is (or may be) compromised, revoke the certificate at once. You are responsible for
everything done with your keys and certificates.</p>
<h2>Revocation</h2>
<p>We may revoke any certificate that was issued in error, whose key is compromised, or that is used in breach of these terms.</p>
<h2>No warranty</h2>
<p>The service is provided as is, without warranty of any kind, and may change or stop at any time.</p>
<h2>Rate limits</h2>
<p>To protect the service and the people it sends e-mail to, requests are limited; see
<a href="${esc(o.externalUrl)}/rate-limits">${esc(o.externalUrl)}/rate-limits</a>.</p>
<h2>CAA</h2>
<p>Domains that publish an <code>issuemail</code> CAA record are only served if it names one of: ${o.caIdentities.map((i) => `<code>${esc(i)}</code>`).join(", ")}.</p>
<p><a href="${esc(o.website)}">${esc(o.website)}</a></p>`,
    );
}

/** The rate-limit page every `rateLimited` problem links to (one section per anchor). */
export function renderRateLimits(limits: Readonly<Record<LimitName, LimitDefinition>>): string {
    const byAnchor: Map<string, Array<[LimitName, LimitDefinition]>> = new Map();
    for (const [name, def] of Object.entries(limits) as Array<[LimitName, LimitDefinition]>) {
        byAnchor.set(def.anchor, [...(byAnchor.get(def.anchor) ?? []), [name, def]]);
    }
    const rows = (entries: Array<[LimitName, LimitDefinition]>): string =>
        entries
            .map(
                ([, def]) =>
                    `<tr><td>${esc(def.what)}</td><td>${def.count}${def.periodSeconds === 1 ? " per second" : ` per ${def.periodSeconds % 86400 === 0 ? `${def.periodSeconds / 86400} day(s)` : def.periodSeconds % 3600 === 0 ? `${def.periodSeconds / 3600} hour(s)` : `${def.periodSeconds} seconds`}`}</td><td>${def.burst}</td><td>${esc(def.scope)}</td></tr>`,
            )
            .join("");
    const sections: string = [...byAnchor.entries()]
        .map(([anchor, entries]) => `<h2 id="${esc(anchor)}">${esc(anchor.replace(/-/g, " "))}</h2><table><tr><th>Limit</th><th>Rate</th><th>Burst</th><th>Counted per</th></tr>${rows(entries)}</table>`)
        .join("");
    return page(
        "Rate limits",
        `<h1>Rate limits</h1>
<p>Limits are token buckets: the burst is how many requests can be made back to back, and the bucket refills at the given rate.
A request over a limit is answered with HTTP 429, <code>urn:ietf:params:acme:error:rateLimited</code> and a
<code>Retry-After</code> header.</p>
<p>The limits on verification e-mails exist to protect the people who receive them: this service sends mail to addresses that
someone else names.</p>${sections}
<h2 id="pending-authorizations">pending authorizations</h2>
<p>An account can have at most 300 pending authorizations (verification e-mails not yet answered) at a time. Answer or let them
expire (after 7 days) before ordering more.</p>`,
    );
}
