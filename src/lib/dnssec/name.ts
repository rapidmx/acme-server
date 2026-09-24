///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { indeterminate } from "./types.js";

/**
 * Domain names inside this library are strings in presentation form without a trailing dot, lower-cased, with backslash
 * escapes (a backslash before a dot or backslash, or a backslash and three decimal digits) for the bytes that are not plain
 * label characters. The root is the empty string. Keeping one normalised
 * spelling makes names usable as map keys and comparable with `===`.
 */
export type DnsName = string;

const MAX_LABEL = 63;
const MAX_WIRE_NAME = 255;

function lowerByte(code: number): number {
    return code >= 0x41 && code <= 0x5a ? code + 0x20 : code;
}

function asciiLower(label: string): string {
    let out = "";
    for (let i = 0; i < label.length; i++) {
        out += String.fromCharCode(lowerByte(label.charCodeAt(i)));
    }
    return out;
}

function escapeLabel(label: string): string {
    let out = "";
    for (let i = 0; i < label.length; i++) {
        const code: number = label.charCodeAt(i);
        if (code === 0x2e || code === 0x5c) {
            out += "\\" + label[i];
        } else if (code < 0x21 || code > 0x7e) {
            out += "\\" + code.toString().padStart(3, "0");
        } else {
            out += label[i];
        }
    }
    return out;
}

/**
 * Splits a presentation-form name into labels, each a string whose character codes are the label's bytes (lower-cased).
 *
 * @throws `indeterminate` for an empty label, an over-long label or name, an unfinished escape or a character above 0x7f
 * (internationalised names must be given in their ASCII form).
 */
export function nameToLabels(name: string): string[] {
    const labels: string[] = [];
    let current = "";
    let started = false;
    for (let i = 0; i < name.length; i++) {
        let code: number = name.charCodeAt(i);
        if (code > 0x7f) {
            throw indeterminate(`name "${name}" is not in ASCII form`);
        }
        if (code === 0x5c) {
            i++;
            if (i >= name.length) {
                throw indeterminate(`name "${name}" ends in an unfinished escape`);
            }
            const next: number = name.charCodeAt(i);
            if (next >= 0x30 && next <= 0x39) {
                const value: number = parseInt(name.slice(i, i + 3), 10);
                if (!/^\d{3}$/.test(name.slice(i, i + 3)) || value > 255) {
                    throw indeterminate(`name "${name}" has a bad escape`);
                }
                code = value;
                i += 2;
            } else {
                code = next;
            }
            current += String.fromCharCode(lowerByte(code));
            started = true;
        } else if (code === 0x2e) {
            if (!started) {
                if (name === "." && labels.length === 0) {
                    return [];
                }
                throw indeterminate(`name "${name}" has an empty label`);
            }
            labels.push(current);
            current = "";
            started = false;
        } else {
            current += String.fromCharCode(lowerByte(code));
            started = true;
        }
    }
    if (started) {
        labels.push(current);
    }
    let total = 1;
    for (const label of labels) {
        if (label.length > MAX_LABEL) {
            throw indeterminate(`name "${name}" has a label longer than ${MAX_LABEL} bytes`);
        }
        total += label.length + 1;
    }
    if (total > MAX_WIRE_NAME) {
        throw indeterminate(`name "${name}" is longer than ${MAX_WIRE_NAME} bytes`);
    }
    return labels;
}

/** Joins labels (byte-strings) into the normalised presentation form. */
export function labelsToName(labels: readonly string[]): DnsName {
    return labels.map((l) => escapeLabel(asciiLower(l))).join(".");
}

/** Normalises a caller-supplied name: lower-case, no trailing dot, validated. */
export function normalizeName(name: string): DnsName {
    return labelsToName(nameToLabels(name));
}

/** The number of labels of the name, not counting the root. */
export function labelCount(name: DnsName): number {
    return nameToLabels(name).length;
}

/** The uncompressed, lower-cased wire form of a name (RFC 4034 §6.2). */
export function nameToWire(name: DnsName): Buffer {
    const labels: string[] = nameToLabels(name);
    const parts: Buffer[] = [];
    for (const label of labels) {
        parts.push(Buffer.from([label.length]), Buffer.from(label, "latin1"));
    }
    parts.push(Buffer.from([0]));
    return Buffer.concat(parts);
}

/** `label` prepended to `name` (`label` is a byte-string, not escaped). */
export function prependLabel(label: string, name: DnsName): DnsName {
    const escaped: string = escapeLabel(asciiLower(label));
    return name === "" ? escaped : `${escaped}.${name}`;
}

/** The name with its leftmost label removed (the root's parent is the root). */
export function parentName(name: DnsName): DnsName {
    return labelsToName(nameToLabels(name).slice(1));
}

/** Whether `name` is `ancestor` or lies below it. */
export function isSubdomain(name: DnsName, ancestor: DnsName): boolean {
    if (ancestor === "" || name === ancestor) {
        return true;
    }
    const a: string[] = nameToLabels(name);
    const b: string[] = nameToLabels(ancestor);
    if (b.length > a.length) {
        return false;
    }
    for (let i = 1; i <= b.length; i++) {
        if (a[a.length - i] !== b[b.length - i]) {
            return false;
        }
    }
    return true;
}

/** Whether `name` lies strictly below `ancestor`. */
export function isProperSubdomain(name: DnsName, ancestor: DnsName): boolean {
    return name !== ancestor && isSubdomain(name, ancestor);
}

/** The labels shared by the right-hand ends of both names, as a name. */
export function commonAncestor(a: DnsName, b: DnsName): DnsName {
    const la: string[] = nameToLabels(a);
    const lb: string[] = nameToLabels(b);
    const shared: string[] = [];
    for (let i = 1; i <= Math.min(la.length, lb.length); i++) {
        if (la[la.length - i] !== lb[lb.length - i]) {
            break;
        }
        shared.unshift(la[la.length - i]);
    }
    return labelsToName(shared);
}

/** Canonical DNS name order (RFC 4034 §6.1): label by label from the right, byte-wise, a prefix sorting first. */
export function compareNames(a: DnsName, b: DnsName): number {
    if (a === b) {
        return 0;
    }
    const la: string[] = nameToLabels(a);
    const lb: string[] = nameToLabels(b);
    let i: number = la.length - 1;
    let j: number = lb.length - 1;
    while (i >= 0 && j >= 0) {
        if (la[i] !== lb[j]) {
            return la[i] < lb[j] ? -1 : 1;
        }
        i--;
        j--;
    }
    return la.length - lb.length < 0 ? -1 : la.length === lb.length ? 0 : 1;
}

/** The FQDN form sent to a transport: escaped presentation with a trailing dot (the root is `.`). */
export function toFqdn(name: DnsName): string {
    return name === "" ? "." : `${name}.`;
}
