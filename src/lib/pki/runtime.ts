///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import "reflect-metadata";
import * as x509 from "@peculiar/x509";

// @peculiar/x509 needs a WebCrypto provider before it can parse or verify anything. Node's is the only one this
// library ever uses; setting it once here (every other module in this directory imports this file first) keeps the
// library self-contained instead of relying on the host application to have configured it.
x509.cryptoProvider.set(globalThis.crypto);

export { x509 };
