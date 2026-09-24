///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import type { HttpRequest } from "@rapidrest/service-core";
import { safeEqual } from "./Ids.js";

/**
 * Whether `req` carries `Authorization: Bearer <secret>`, compared in constant time. `false` when `secret` is empty: a route
 * guarded this way answers 404 in that case instead of ever accepting an empty token.
 */
export function bearerMatches(req: HttpRequest, secret: string): boolean {
    const header: string = String(req.headers["authorization"] ?? "");
    return secret !== "" && header.startsWith("Bearer ") && safeEqual(header.slice("Bearer ".length), secret);
}
