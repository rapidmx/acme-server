///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
export { DnssecUdpTcpTransport, parseServer } from "./transport.js";
export { CLASS_IN, DnssecError, RRTYPE } from "./types.js";
export type { CaaRdata, DnssecStatus, DnssecTransport, DsRecord } from "./types.js";
export { DnssecResolver, IANA_ROOT_TRUST_ANCHORS } from "./validator.js";
export type { DnssecResolverOptions, DnssecResult } from "./validator.js";
