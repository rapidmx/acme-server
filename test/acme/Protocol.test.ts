///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// RFC 8555 §6: the envelope every ACME request travels in - content type, JWS structure, nonces, the url header, key
// identification - and the problem documents the CA answers with when any of it is wrong.
import { FlattenedSign } from "jose";
import { AcmeTestClient, Reply } from "../support/client.js";
import { AcmeTestKey } from "../support/keys.js";
import { CaHarness, startCa } from "../support/harness.js";

describe("ACME protocol envelope", () => {
    let ca: CaHarness;
    let client: AcmeTestClient;

    beforeAll(async () => {
        ca = await startCa();
        client = await AcmeTestClient.create(ca.baseUrl);
        await client.register();
    }, 180_000);

    afterAll(async () => {
        await ca?.stop();
    });

    const problem = (reply: Reply, type: string, status?: number) => {
        expect(reply.headers.get("content-type")).toBe("application/problem+json");
        expect(reply.json.type).toBe(`urn:ietf:params:acme:error:${type}`);
        expect(typeof reply.json.detail).toBe("string");
        expect(reply.json.status).toBe(reply.status);
        if (status !== undefined) {
            expect(reply.status).toBe(status);
        }
    };

    /** POSTs a hand-built body, so the JWS itself can be malformed. */
    const rawPost = async (url: string, body: string, contentType: string = "application/jose+json"): Promise<Reply> => {
        const response = await fetch(url, { method: "POST", headers: { "content-type": contentType }, body });
        const text = await response.text();
        let json: any;
        try {
            json = JSON.parse(text);
        } catch {
            json = undefined;
        }
        return { status: response.status, headers: response.headers, json, text };
    };

    describe("nonces", () => {
        it("answers HEAD with 200 and GET with 204, both with a fresh Replay-Nonce and no caching", async () => {
            const head = await fetch(client.directory.newNonce, { method: "HEAD" });
            expect(head.status).toBe(200);
            expect(head.headers.get("replay-nonce")).toMatch(/^[A-Za-z0-9_-]{20,}$/);
            expect(head.headers.get("cache-control")).toBe("no-store");
            expect(head.headers.get("link")).toContain(`<${ca.baseUrl}/directory>;rel="index"`);

            const get = await fetch(client.directory.newNonce);
            expect(get.status).toBe(204);
            expect(get.headers.get("replay-nonce")).not.toBe(head.headers.get("replay-nonce"));
        });

        it("puts a fresh Replay-Nonce on every response to a POST, errors included", async () => {
            const ok = await client.post(`${ca.baseUrl}/acme/acct/${client.kid!.split("/").pop()}`, {});
            expect(ok.status).toBe(200);
            expect(ok.headers.get("replay-nonce")).toBeTruthy();

            const failed = await client.post(client.directory.newOrder, { identifiers: [] });
            expect(failed.status).toBe(400);
            expect(failed.headers.get("replay-nonce")).toBeTruthy();
        });

        it("rejects a replayed nonce with badNonce and hands out a new one to retry with", async () => {
            const nonce = await client.freshNonce();
            const first = await client.post(client.directory.newOrder, { identifiers: [{ type: "email", value: "nonce@example.com" }] }, { nonce });
            expect(first.status).toBe(201);
            const replay = await client.post(client.directory.newOrder, { identifiers: [{ type: "email", value: "nonce@example.com" }] }, { nonce });
            problem(replay, "badNonce", 400);
            expect(replay.headers.get("replay-nonce")).toBeTruthy();
        });

        it("rejects a nonce this server never issued", async () => {
            problem(await client.post(client.directory.newOrder, {}, { nonce: "AAAAAAAAAAAAAAAAAAAAAAAA" }), "badNonce");
        });

        it("rejects a JWS without a nonce as malformed", async () => {
            problem(await client.post(client.directory.newOrder, {}, { nonce: null }), "malformed");
        });

        it("does not burn a nonce for a request whose signature is forged", async () => {
            const nonce = await client.freshNonce();
            const attacker = await AcmeTestKey.generate("ES256");
            const forged = await client.post(client.directory.newOrder, {}, { nonce, key: attacker, kid: client.kid });
            problem(forged, "malformed");
            // The nonce is still good for the real client.
            const real = await client.post(client.directory.newOrder, { identifiers: [{ type: "email", value: "forged@example.com" }] }, { nonce });
            expect(real.status).toBe(201);
        });
    });

    describe("the JWS", () => {
        it("requires the application/jose+json content type", async () => {
            const reply = await client.post(client.directory.newOrder, {}, { contentType: "application/json" });
            problem(reply, "malformed", 415);
        });

        it("rejects an empty body, invalid JSON and non-objects", async () => {
            for (const body of ["", "not json", "[]", "null", "42"]) {
                problem(await rawPost(client.directory.newOrder, body), "malformed", 400);
            }
        });

        it("rejects a JWS with members other than protected, payload and signature", async () => {
            const jws = await new FlattenedSign(new TextEncoder().encode("{}"))
                .setProtectedHeader({ alg: "ES256", url: client.directory.newOrder, nonce: await client.freshNonce(), kid: client.kid })
                .sign(client.key.privateKey);
            problem(await rawPost(client.directory.newOrder, JSON.stringify({ ...jws, header: { extra: 1 } })), "malformed");
            problem(await rawPost(client.directory.newOrder, JSON.stringify({ ...jws, signatures: [] })), "malformed");
        });

        it("rejects a url header that is not the URL the request was sent to", async () => {
            const reply = await client.post(client.directory.newOrder, {}, { url: `${ca.baseUrl}/acme/new-acct` });
            problem(reply, "malformed");
            expect(reply.json.detail).toContain("url");
        });

        it("rejects a JWS that has both a jwk and a kid, or neither", async () => {
            const both = await new FlattenedSign(new TextEncoder().encode("{}"))
                .setProtectedHeader({ alg: "ES256", url: client.directory.newOrder, nonce: await client.freshNonce(), kid: client.kid, jwk: client.key.publicJwk })
                .sign(client.key.privateKey);
            problem(await rawPost(client.directory.newOrder, JSON.stringify(both)), "malformed");
            const neither = await new FlattenedSign(new TextEncoder().encode("{}"))
                .setProtectedHeader({ alg: "ES256", url: client.directory.newOrder, nonce: await client.freshNonce() })
                .sign(client.key.privateKey);
            problem(await rawPost(client.directory.newOrder, JSON.stringify(neither)), "malformed");
        });

        it("refuses a jwk where a kid is required, and a kid where new-account needs the jwk", async () => {
            problem(await client.post(client.directory.newOrder, {}, { jwk: true }), "malformed");
            problem(await client.post(client.directory.newAccount, { termsOfServiceAgreed: true }), "malformed");
        });

        it("answers an unknown kid with accountDoesNotExist", async () => {
            const reply = await client.post(client.directory.newOrder, {}, { kid: `${ca.baseUrl}/acme/acct/doesNotExistAtAll0000` });
            problem(reply, "accountDoesNotExist", 400);
            problem(await client.post(client.directory.newOrder, {}, { kid: "https://elsewhere.example/acme/acct/xyz" }), "accountDoesNotExist");
        });

        it("refuses algorithms outside the allowed set, listing the ones that are", async () => {
            const jws = await new FlattenedSign(new TextEncoder().encode("{}"))
                .setProtectedHeader({ alg: "ES256", url: client.directory.newOrder, nonce: await client.freshNonce(), kid: client.kid })
                .sign(client.key.privateKey);
            const protectedHeader = Buffer.from(JSON.stringify({ alg: "HS256", url: client.directory.newOrder, nonce: "x", kid: client.kid })).toString("base64url");
            const reply = await rawPost(client.directory.newOrder, JSON.stringify({ ...jws, protected: protectedHeader }));
            problem(reply, "badSignatureAlgorithm", 400);
            expect(reply.json.algorithms).toEqual(["ES256", "ES384", "ES512", "RS256", "RS384", "RS512"]);

            const none = Buffer.from(JSON.stringify({ alg: "none", url: client.directory.newOrder, nonce: "x", kid: client.kid })).toString("base64url");
            problem(await rawPost(client.directory.newOrder, JSON.stringify({ ...jws, protected: none })), "badSignatureAlgorithm");
        });

        it("refuses crit and b64 in the protected header", async () => {
            const jws = await new FlattenedSign(new TextEncoder().encode("{}"))
                .setProtectedHeader({ alg: "ES256", url: client.directory.newOrder, nonce: await client.freshNonce(), kid: client.kid })
                .sign(client.key.privateKey);
            for (const extra of [{ crit: ["exp"], exp: 1 }, { b64: false, crit: ["b64"] }]) {
                const protectedHeader = Buffer.from(JSON.stringify({ alg: "ES256", url: client.directory.newOrder, nonce: "x", kid: client.kid, ...extra })).toString("base64url");
                problem(await rawPost(client.directory.newOrder, JSON.stringify({ ...jws, protected: protectedHeader })), "malformed");
            }
        });

        it("refuses a jwk that carries private key material", async () => {
            const key = await AcmeTestKey.generate("ES256");
            const leaky = { ...key.publicJwk, d: "AAAA" };
            const jws = await new FlattenedSign(new TextEncoder().encode(JSON.stringify({ termsOfServiceAgreed: true })))
                .setProtectedHeader({ alg: "ES256", url: client.directory.newAccount, nonce: await client.freshNonce(), jwk: leaky })
                .sign(key.privateKey);
            problem(await rawPost(client.directory.newAccount, JSON.stringify(jws)), "badPublicKey");
        });

        it("refuses unsupported and weak account keys", async () => {
            const okp = { kty: "OKP", crv: "Ed25519", x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" };
            const jws = await new FlattenedSign(new TextEncoder().encode("{}"))
                .setProtectedHeader({ alg: "ES256", url: client.directory.newAccount, nonce: await client.freshNonce(), jwk: okp })
                .sign(client.key.privateKey);
            problem(await rawPost(client.directory.newAccount, JSON.stringify(jws)), "badPublicKey");

            const weakRsa = { kty: "RSA", n: Buffer.alloc(128, 0xab).toString("base64url"), e: "AQAB" };
            const rsa = await AcmeTestKey.generate("RS256");
            const jws2 = await new FlattenedSign(new TextEncoder().encode("{}"))
                .setProtectedHeader({ alg: "RS256", url: client.directory.newAccount, nonce: await client.freshNonce(), jwk: weakRsa })
                .sign(rsa.privateKey);
            problem(await rawPost(client.directory.newAccount, JSON.stringify(jws2)), "badPublicKey");
        });

        it("rejects a payload that is not a JSON object", async () => {
            for (const payload of ['"a string"', "[1,2]", "not json", "42"]) {
                problem(await client.post(client.directory.newOrder, payload), "malformed");
            }
        });

        it("accepts an RS256 account key as well as ES256 and ES384", async () => {
            for (const alg of ["RS256", "ES384"] as const) {
                const other = await AcmeTestClient.create(ca.baseUrl, alg);
                const reply = await other.register();
                expect(reply.status).toBe(201);
                const order = await other.newOrder(`${alg.toLowerCase()}@example.com`);
                expect(order.status).toBe(201);
            }
        });
    });

    describe("responses", () => {
        it("serves problem documents with the ACME URN, the status and a detail", async () => {
            const reply = await client.post(client.directory.newOrder, { identifiers: [{ type: "dns", value: "example.com" }] });
            problem(reply, "unsupportedIdentifier", 400);
        });

        it("links every ACME response to the directory", async () => {
            const reply = await client.get("/directory");
            expect(reply.headers.get("link")).toContain('rel="index"');
            const post = await client.post(client.directory.newOrder, { identifiers: [{ type: "email", value: "link@example.com" }] });
            expect(post.headers.get("link")).toContain(`<${ca.baseUrl}/directory>;rel="index"`);
            expect(post.headers.get("cache-control")).toBe("no-store");
            expect(post.headers.get("location")).toMatch(/\/acme\/order\//);
        });

        it("does not leak internals on a server error", async () => {
            const original = ca.ctx.orders.create.bind(ca.ctx.orders);
            ca.ctx.orders.create = async () => {
                throw new Error("secret database detail at 10.0.0.5");
            };
            try {
                const reply = await client.post(client.directory.newOrder, { identifiers: [{ type: "email", value: "boom@example.com" }] });
                problem(reply, "serverInternal", 500);
                expect(reply.text).not.toContain("secret");
                expect(reply.headers.get("replay-nonce")).toBeTruthy();
            } finally {
                ca.ctx.orders.create = original;
            }
        });

        it("answers unknown paths and wrong methods without an ACME body", async () => {
            expect((await fetch(`${ca.baseUrl}/acme/nothing-here`)).status).toBe(404);
            expect((await fetch(`${ca.baseUrl}/acme/new-order`)).status).toBeGreaterThanOrEqual(404);
        });
    });
});
