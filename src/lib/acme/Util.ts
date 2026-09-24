///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////

/** Whether `err` is MongoDB's duplicate key error (a unique index refused an insert or update). */
export function isDuplicateKey(err: any): boolean {
    return err?.code === 11000;
}

/**
 * The canonical form of a certificate serial, stored and compared everywhere: lower-case hex of whole bytes, without leading
 * zero *bytes* (the form the PKI library produces). A leading zero nibble is significant – serial `0a bc` is not `abc` – so an
 * odd-length input is padded with a zero, never trimmed.
 */
export function normalizeSerial(serial: string): string {
    let hex: string = serial.toLowerCase();
    if (hex.length % 2 === 1) {
        hex = `0${hex}`;
    }
    while (hex.length > 2 && hex.startsWith("00")) {
        hex = hex.slice(2);
    }
    return hex;
}
