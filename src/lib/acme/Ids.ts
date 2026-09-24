///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { createHash, randomBytes, timingSafeEqual } from "crypto";

/** A random 128-bit id, base64url: the last URL segment of an account, order or authorization. Unguessable by design. */
export function randomId(): string {
    return randomBytes(16).toString("base64url");
}

/** A random 256-bit token, base64url (RFC 8823 asks for at least 128 bits for each half). */
export function randomToken(): string {
    return randomBytes(32).toString("base64url");
}

/** SHA-256 of a string or bytes, hex. */
export function sha256Hex(data: string | Uint8Array): string {
    return createHash("sha256").update(data).digest("hex");
}

/** SHA-256 of a string, base64url. */
export function sha256B64url(data: string): string {
    return createHash("sha256").update(data).digest("base64url");
}

/** Compares two strings in constant time (false for different lengths, which is not a secret here). */
export function safeEqual(a: string, b: string): boolean {
    const x: Buffer = Buffer.from(a);
    const y: Buffer = Buffer.from(b);
    return x.length === y.length && timingSafeEqual(x, y);
}
