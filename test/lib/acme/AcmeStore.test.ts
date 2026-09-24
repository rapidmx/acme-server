///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import { BucketMode, BucketPolicy, gcra, GCRA_LUA, MemoryAcmeStore, RedisAcmeStore } from "../../../src/lib/acme/AcmeStore.js";
import { LuaRedis } from "../../support/luaRedis.js";

describe("gcra (the token bucket)", () => {
    const policy: BucketPolicy = { intervalMs: 1000, burst: 5 };

    it("lets a full bucket spend its burst back to back, then refuses with the time to the next token", () => {
        let tat: number | undefined;
        for (let i = 0; i < 5; i++) {
            const step = gcra(tat, 0, policy, 1, "spend");
            expect(step.result.allowed).toBe(true);
            expect(step.result.remaining).toBe(4 - i);
            tat = step.tat;
        }
        const refused = gcra(tat, 0, policy, 1, "spend");
        expect(refused.result).toEqual({ allowed: false, retryAfterMs: 1000, remaining: 0 });
        expect(refused.tat).toBe(tat);
    });

    it("refills one token per interval", () => {
        let tat: number | undefined;
        for (let i = 0; i < 5; i++) {
            tat = gcra(tat, 0, policy, 1, "spend").tat;
        }
        expect(gcra(tat, 400, policy, 1, "spend").result).toEqual({ allowed: false, retryAfterMs: 600, remaining: 0 });
        const after = gcra(tat, 1000, policy, 1, "spend");
        expect(after.result.allowed).toBe(true);
        expect(gcra(after.tat, 1000, policy, 1, "spend").result.allowed).toBe(false);
        // After a long idle the bucket is full again, never more than full.
        expect(gcra(tat, 100_000, policy, 1, "check").result.remaining).toBe(5);
        expect(gcra(undefined, 5, policy, 1, "check").result.remaining).toBe(5);
    });

    it("check looks without spending, refund gives tokens back (never beyond full)", () => {
        const spent = gcra(undefined, 0, policy, 3, "spend");
        expect(spent.result.remaining).toBe(2);
        const looked = gcra(spent.tat, 0, policy, 2, "check");
        expect(looked.result).toEqual({ allowed: true, retryAfterMs: 0, remaining: 2 });
        expect(looked.tat).toBe(spent.tat);
        const refunded = gcra(spent.tat, 0, policy, 2, "refund");
        expect(refunded.result.remaining).toBe(4);
        const overRefunded = gcra(refunded.tat, 0, policy, 10, "refund");
        expect(overRefunded.result.remaining).toBe(5);
    });

    it("never allows a request bigger than the bucket, and reports when it could at best fit", () => {
        const refused = gcra(undefined, 0, policy, 6, "spend");
        expect(refused.result.allowed).toBe(false);
        expect(refused.tat).toBeUndefined();
    });
});

describe("MemoryAcmeStore", () => {
    let now: number;
    let store: MemoryAcmeStore;

    beforeEach(() => {
        now = 1_000_000;
        store = new MemoryAcmeStore(() => now);
    });

    afterEach(async () => {
        await store.close();
    });

    it("sets a key once until it expires", async () => {
        expect(await store.putIfAbsent("k", 10)).toBe(true);
        expect(await store.putIfAbsent("k", 10)).toBe(false);
        now += 9_999;
        expect(await store.putIfAbsent("k", 10)).toBe(false);
        now += 2;
        expect(await store.putIfAbsent("k", 10)).toBe(true);
    });

    it("take succeeds exactly once, and never for an expired or missing key", async () => {
        await store.putIfAbsent("k", 10);
        expect(await store.take("k")).toBe(true);
        expect(await store.take("k")).toBe(false);
        expect(await store.take("never")).toBe(false);
        await store.putIfAbsent("old", 1);
        now += 5_000;
        expect(await store.take("old")).toBe(false);
    });

    it("lets exactly one of many concurrent takers win", async () => {
        await store.putIfAbsent("nonce", 60);
        const results = await Promise.all(Array.from({ length: 25 }, () => store.take("nonce")));
        expect(results.filter(Boolean)).toHaveLength(1);
    });

    it("runs buckets independently per key and forgets a bucket once it is full again", async () => {
        const policy: BucketPolicy = { intervalMs: 1000, burst: 2 };
        expect((await store.bucket("a", policy, 1, "spend")).allowed).toBe(true);
        expect((await store.bucket("a", policy, 1, "spend")).allowed).toBe(true);
        expect((await store.bucket("a", policy, 1, "spend")).allowed).toBe(false);
        expect((await store.bucket("b", policy, 1, "spend")).allowed).toBe(true);
        expect(store.size()).toBe(2);
        now += 10_000;
        store.sweep();
        expect(store.size()).toBe(0);
        expect((await store.bucket("a", policy, 2, "spend")).allowed).toBe(true);
    });

    it("does not let a check or a refused spend create state", async () => {
        const policy: BucketPolicy = { intervalMs: 1000, burst: 2 };
        await store.bucket("a", policy, 1, "check");
        await store.bucket("a", policy, 5, "spend");
        expect(store.size()).toBe(0);
    });
});

describe("RedisAcmeStore and its Lua script", () => {
    it("runs the bucket script in Redis and reads its answer", async () => {
        const redis = new LuaRedis();
        const store = new RedisAcmeStore(redis, "t:");
        const policy: BucketPolicy = { intervalMs: 1000, burst: 2 };
        expect(await store.bucket("k", policy, 1, "spend")).toEqual({ allowed: true, retryAfterMs: 0, remaining: 1 });
        expect(await store.bucket("k", policy, 1, "spend")).toEqual({ allowed: true, retryAfterMs: 0, remaining: 0 });
        expect(await store.bucket("k", policy, 1, "spend")).toEqual({ allowed: false, retryAfterMs: 1000, remaining: 0 });
        expect([...redis.data.keys()]).toEqual(["t:bucket:k"]);
        redis.now += 1000;
        expect((await store.bucket("k", policy, 1, "check")).allowed).toBe(true);
        redis.now += 100_000;
        await store.bucket("k", policy, 0, "check");
        expect(redis.data.size).toBe(0);
    });

    it("gives the same answers as the reference algorithm for a long random sequence of operations", async () => {
        const redis = new LuaRedis();
        const store = new RedisAcmeStore(redis, "");
        let seed = 12345;
        const random = (): number => {
            seed = (seed * 1103515245 + 12345) & 0x7fffffff;
            return seed / 0x7fffffff;
        };
        const policies: BucketPolicy[] = [
            { intervalMs: 1000, burst: 5 },
            { intervalMs: 3, burst: 200 },
            { intervalMs: 1_080_000, burst: 10 },
            { intervalMs: 120_960_000, burst: 5 },
        ];
        const modes: BucketMode[] = ["spend", "spend", "spend", "check", "refund"];
        for (const policy of policies) {
            let tat: number | undefined;
            for (let step = 0; step < 400; step++) {
                redis.now += Math.floor(random() * policy.intervalMs * 2.5);
                const mode: BucketMode = modes[Math.floor(random() * modes.length)];
                const cost: number = 1 + Math.floor(random() * 3);
                const expected = gcra(tat, redis.now, policy, cost, mode);
                tat = expected.tat !== undefined && expected.tat > redis.now ? expected.tat : undefined;
                const actual = await store.bucket("seq", policy, cost, mode);
                expect(actual, `${JSON.stringify(policy)} step ${step} ${mode} x${cost}`).toEqual(expected.result);
            }
            redis.data.clear();
        }
    });

    it("uses only commands the script needs, with the clock from Redis itself", async () => {
        const redis = new LuaRedis();
        const store = new RedisAcmeStore(redis);
        await store.bucket("k", { intervalMs: 1000, burst: 3 }, 1, "spend");
        expect(redis.commands.map((c) => c[0].toUpperCase())).toEqual(["TIME", "GET", "SET"]);
        expect(GCRA_LUA).toContain("redis.call('TIME')");
    });

    it("sets a key with a TTL only when absent and deletes it atomically", async () => {
        const redis = new LuaRedis();
        const store = new RedisAcmeStore(redis, "p:");
        expect(await store.putIfAbsent("n", 5)).toBe(true);
        expect(await store.putIfAbsent("n", 5)).toBe(false);
        expect(redis.data.get("p:n")?.expiresAt).toBe(redis.now + 5000);
        expect(await store.take("n")).toBe(true);
        expect(await store.take("n")).toBe(false);
        await store.close();
    });
});
