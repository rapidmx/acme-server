///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// Kept under lib/, which RapidREST's class loader does not scan: it stamps a `fqn` property on every object a scanned module exports.

/** The RFC 5280 reasons an operator may give, by name. `certificateHold` (6) and `removeFromCRL` (8) are never used: a held certificate would flap on the CRL. */
export const OPERATOR_REVOCATION_REASONS: Readonly<Record<string, number>> = {
    unspecified: 0,
    keyCompromise: 1,
    affiliationChanged: 3,
    superseded: 4,
    cessationOfOperation: 5,
    privilegeWithdrawn: 9,
};

/** The most certificates one bulk revocation may touch: a bigger blast radius than this is a decision to make in smaller steps. */
export const MAX_BULK_REVOCATION = 1000;
