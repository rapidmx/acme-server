///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
// RFC 8555 §7.3: account registration, contact updates, deactivation, key rollover and the order list.
import { FlattenedSign } from "jose";
import { AcmeTestClient, Reply } from "../support/client.js";
import { uniqueEmail } from "../support/flow.js";
import { AcmeTestKey } from "../support/keys.js";
import { CaHarness, startCa } from "../support/harness.js";

describe("ACME accounts", () => {
    let ca: CaHarness;

    beforeAll(async () => {
        ca = await startCa();
    }, 180_000);

    afterAll(async () => {
        await ca?.stop();
    });

    const problem = (reply: Reply, type: string, status?: number) => {
        expect(reply.json?.type).toBe(`urn:ietf:params:acme:error:${type}`);
        if (status !== undefined) {
            expect(reply.status).toBe(status);
        }
    };

    describe("registration", () => {
        it("creates an account (201) and answers the same key again with the same account (200)", async () => {
            const client = await AcmeTestClient.create(ca.baseUrl);
            const created = await client.register(["mailto:ops@example.com"]);
            expect(created.status).toBe(201);
            const url = created.headers.get("location")!;
            expect(url).toMatch(new RegExp(`^${ca.baseUrl}/acme/acct/[A-Za-z0-9_-]{22}$`));
            expect(created.json).toEqual({
                status: "valid",
                contact: ["mailto:ops@example.com"],
                termsOfServiceAgreed: true,
                orders: `${url}/orders`,
            });

            const again = await client.post(client.directory.newAccount, { termsOfServiceAgreed: true }, { jwk: true });
            expect(again.status).toBe(200);
            expect(again.headers.get("location")).toBe(url);
        });

        it("answers onlyReturnExisting with the account, or accountDoesNotExist for an unknown key", async () => {
            const known = await AcmeTestClient.create(ca.baseUrl);
            await known.register();
            const found = await known.post(known.directory.newAccount, { onlyReturnExisting: true }, { jwk: true });
            expect(found.status).toBe(200);
            expect(found.headers.get("location")).toBe(known.kid);

            const stranger = await AcmeTestClient.create(ca.baseUrl);
            problem(await stranger.post(stranger.directory.newAccount, { onlyReturnExisting: true }, { jwk: true }), "accountDoesNotExist", 400);
        });

        it("requires the terms of service to be agreed to", async () => {
            const client = await AcmeTestClient.create(ca.baseUrl);
            for (const payload of [{}, { termsOfServiceAgreed: false }, { termsOfServiceAgreed: "yes" }]) {
                const reply = await client.post(client.directory.newAccount, payload, { jwk: true });
                problem(reply, "userActionRequired", 403);
                expect(reply.json.detail).toContain(`${ca.baseUrl}/terms`);
            }
        });

        it("validates contacts: only mailto:, plain addresses, at most five", async () => {
            const client = await AcmeTestClient.create(ca.baseUrl);
            const register = (contact: unknown) => client.post(client.directory.newAccount, { termsOfServiceAgreed: true, contact }, { jwk: true });
            problem(await register(["tel:+15555550100"]), "unsupportedContact");
            problem(await register(["https://example.com/contact"]), "unsupportedContact");
            problem(await register(["mailto:someone@example.com?subject=hi"]), "invalidContact");
            problem(await register(["mailto:a@example.com,b@example.com"]), "invalidContact");
            problem(await register(["mailto:not an address"]), "invalidContact");
            problem(await register(["mailto:"]), "invalidContact");
            problem(await register("mailto:a@example.com"), "invalidContact");
            problem(await register([42]), "invalidContact");
            problem(await register(Array.from({ length: 6 }, (_, i) => `mailto:c${i}@example.com`)), "invalidContact");
            expect((await register(["mailto:ok@example.com", "mailto:also.ok+tag@example.com"])).status).toBe(201);
        });
    });

    describe("management", () => {
        it("reads an account with a POST-as-GET and updates its contacts", async () => {
            const client = await AcmeTestClient.create(ca.baseUrl);
            await client.register(["mailto:old@example.com"]);
            const read = await client.post(client.kid!);
            expect(read.status).toBe(200);
            expect(read.json.contact).toEqual(["mailto:old@example.com"]);

            const updated = await client.post(client.kid!, { contact: ["mailto:new@example.com"] });
            expect(updated.status).toBe(200);
            expect(updated.json.contact).toEqual(["mailto:new@example.com"]);
            expect((await client.post(client.kid!)).json.contact).toEqual(["mailto:new@example.com"]);

            problem(await client.post(client.kid!, { contact: ["tel:1"] }), "unsupportedContact");
        });

        it("only ever lets an account manage itself", async () => {
            const alice = await AcmeTestClient.create(ca.baseUrl);
            await alice.register();
            const mallory = await AcmeTestClient.create(ca.baseUrl);
            await mallory.register();
            problem(await mallory.post(alice.kid!), "unauthorized", 403);
            problem(await mallory.post(alice.kid!, { contact: ["mailto:evil@example.com"] }), "unauthorized");
            problem(await mallory.post(`${alice.kid}/orders`), "unauthorized");
            expect((await alice.post(alice.kid!)).json.contact).not.toContain("mailto:evil@example.com");
        });

        it("refuses a status change other than deactivation", async () => {
            const client = await AcmeTestClient.create(ca.baseUrl);
            await client.register();
            problem(await client.post(client.kid!, { status: "valid" }), "malformed");
            problem(await client.post(client.kid!, { status: "revoked" }), "malformed");
        });

        it("deactivates an account, cancelling its open orders and refusing everything after", async () => {
            const client = await AcmeTestClient.create(ca.baseUrl);
            await client.register();
            const order = await client.newOrder(uniqueEmail("deact"));
            const orderUrl = order.headers.get("location")!;

            const gone = await client.post(client.kid!, { status: "deactivated" });
            expect(gone.status).toBe(200);
            expect(gone.json.status).toBe("deactivated");

            problem(await client.post(client.kid!), "unauthorized", 403);
            problem(await client.newOrder(uniqueEmail("deact")), "unauthorized");
            const stored = await ca.ctx.orderRepo.findOne({ uid: orderUrl.split("/").pop() });
            expect(stored?.status).toBe("invalid");
            const authz = await ca.ctx.authzRepo.findOne({ orderUid: orderUrl.split("/").pop() });
            expect(authz?.status).toBe("deactivated");

            // The key is still registered to the deactivated account: it cannot open a second one.
            const again = await client.post(client.directory.newAccount, { termsOfServiceAgreed: true }, { jwk: true });
            expect(again.headers.get("location")).toBe(client.kid);
        });
    });

    describe("key rollover", () => {
        /** Builds the doubly-signed key-change request of RFC 8555 §7.3.5. */
        const keyChange = async (client: AcmeTestClient, newKey: AcmeTestKey, o: { account?: string; oldKey?: unknown; innerUrl?: string; innerNonce?: string } = {}): Promise<Reply> => {
            const url = client.directory.keyChange;
            const inner = await new FlattenedSign(
                new TextEncoder().encode(JSON.stringify({ account: o.account ?? client.kid, oldKey: o.oldKey ?? client.key.publicJwk })),
            )
                .setProtectedHeader({ alg: newKey.alg, url: o.innerUrl ?? url, jwk: newKey.publicJwk, ...(o.innerNonce ? { nonce: o.innerNonce } : {}) })
                .sign(newKey.privateKey);
            return await client.post(url, inner);
        };

        it("moves the account to a new key: the old key stops working, the new one works", async () => {
            const client = await AcmeTestClient.create(ca.baseUrl);
            await client.register();
            const oldKey = client.key;
            const newKey = await AcmeTestKey.generate("ES384");

            const changed = await keyChange(client, newKey);
            expect(changed.status).toBe(200);
            expect(changed.json.status).toBe("valid");

            problem(await client.post(client.kid!, undefined, { key: oldKey }), "malformed");
            const withNew = await client.post(client.kid!, undefined, { key: newKey });
            expect(withNew.status).toBe(200);
            // The new key finds its account by registration too.
            const lookup = await client.post(client.directory.newAccount, { onlyReturnExisting: true }, { jwk: true, key: newKey });
            expect(lookup.headers.get("location")).toBe(client.kid);
            problem(await client.post(client.directory.newAccount, { onlyReturnExisting: true }, { jwk: true, key: oldKey }), "accountDoesNotExist");
        });

        it("answers 409 with the owning account when the new key is already registered", async () => {
            const first = await AcmeTestClient.create(ca.baseUrl);
            await first.register();
            const second = await AcmeTestClient.create(ca.baseUrl);
            await second.register();
            const reply = await keyChange(first, second.key);
            expect(reply.status).toBe(409);
            expect(reply.headers.get("location")).toBe(second.kid);
        });

        it("rejects a change to the key it already has", async () => {
            const client = await AcmeTestClient.create(ca.baseUrl);
            await client.register();
            problem(await keyChange(client, client.key), "malformed");
        });

        it("rejects an inner JWS that names another account, a wrong old key, another url or carries a nonce", async () => {
            const client = await AcmeTestClient.create(ca.baseUrl);
            await client.register();
            const other = await AcmeTestClient.create(ca.baseUrl);
            await other.register();
            const fresh = async () => await AcmeTestKey.generate("ES256");
            problem(await keyChange(client, await fresh(), { account: other.kid }), "unauthorized");
            problem(await keyChange(client, await fresh(), { oldKey: other.key.publicJwk }), "unauthorized");
            problem(await keyChange(client, await fresh(), { innerUrl: `${ca.baseUrl}/acme/new-order` }), "malformed");
            problem(await keyChange(client, await fresh(), { innerNonce: await client.freshNonce() }), "malformed");
            problem(await client.post(client.directory.keyChange, {}), "malformed");
            problem(await client.post(client.directory.keyChange), "malformed");
        });

        it("rejects an inner JWS that was not signed by the new key", async () => {
            const client = await AcmeTestClient.create(ca.baseUrl);
            await client.register();
            const newKey = await AcmeTestKey.generate("ES256");
            const impostor = await AcmeTestKey.generate("ES256");
            const url = client.directory.keyChange;
            const inner = await new FlattenedSign(new TextEncoder().encode(JSON.stringify({ account: client.kid, oldKey: client.key.publicJwk })))
                .setProtectedHeader({ alg: "ES256", url, jwk: newKey.publicJwk })
                .sign(impostor.privateKey);
            problem(await client.post(url, inner), "malformed");
        });
    });

    describe("the order list", () => {
        it("lists the account's orders, newest first, and pages through them with a Link header", async () => {
            const client = await AcmeTestClient.create(ca.baseUrl);
            await client.register();
            const urls: string[] = [];
            for (let i = 0; i < 52; i++) {
                urls.push((await client.newOrder(uniqueEmail("list"))).headers.get("location")!);
            }
            const ordersUrl = `${client.kid}/orders`;
            const first = await client.post(ordersUrl);
            expect(first.status).toBe(200);
            expect(first.json.orders).toHaveLength(50);
            expect(new Set(first.json.orders).size).toBe(50);
            const link = first.headers.get("link")!;
            const next = /<([^>]+)>;rel="next"/.exec(link)![1];
            expect(next).toBe(`${ordersUrl}?cursor=50`);

            const second = await client.post(next);
            expect(second.status).toBe(200);
            expect(second.json.orders).toHaveLength(2);
            expect(second.headers.get("link") ?? "").not.toContain('rel="next"');
            expect(new Set([...first.json.orders, ...second.json.orders])).toEqual(new Set(urls));
        }, 60_000);

        it("is empty for an account with no orders", async () => {
            const client = await AcmeTestClient.create(ca.baseUrl);
            await client.register();
            expect((await client.post(`${client.kid}/orders`)).json).toEqual({ orders: [] });
        });
    });
});
