///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////

/**
 * A token bucket described the way Let's Encrypt's rate-limit documentation does: `burst` tokens of capacity, refilled
 * one every `intervalMs`.
 */
export interface BucketPolicy {
    /** Milliseconds for one token to refill (the GCRA emission interval, `period / count`). */
    intervalMs: number;
    /** The bucket capacity: how many tokens can be spent back to back. */
    burst: number;
}

/** What asking a bucket for tokens answered. */
export interface BucketResult {
    /** Whether the tokens were available (and, for `spend`, have been taken). */
    allowed: boolean;
    /** When `allowed` is `false`: milliseconds until the request could succeed. */
    retryAfterMs: number;
    /** Whole tokens left in the bucket after the operation. */
    remaining: number;
}

/** `spend` takes tokens if there are enough; `check` only looks; `refund` gives tokens back. */
export type BucketMode = "spend" | "check" | "refund";

/**
 * The small set of atomic operations the nonce store and the rate limiters need. Two implementations: Redis (shared
 * by every replica) and process memory (a single node, development and the test suite).
 */
export interface AcmeStore {
    /** Sets `key` for `ttlSeconds` unless it exists. Resolves `true` when it was set. */
    putIfAbsent(key: string, ttlSeconds: number): Promise<boolean>;
    /** Deletes `key`. Resolves `true` when it existed – so of two concurrent callers exactly one gets `true`. */
    take(key: string): Promise<boolean>;
    /** Runs one token-bucket operation (see `gcra()`), atomically. */
    bucket(key: string, policy: BucketPolicy, cost: number, mode: BucketMode): Promise<BucketResult>;
    /** Releases resources. */
    close(): Promise<void>;
}

/**
 * The generic cell rate algorithm – a token bucket stored as a single number, the *theoretical arrival time* (TAT):
 * the moment the bucket would be full again. This is the reference the Redis script below mirrors line for line.
 *
 * Spending `cost` tokens moves the TAT forward by `cost * intervalMs`; the request is allowed when that new TAT is no
 * further ahead of `now` than the bucket's capacity (`burst * intervalMs`). A refund moves the TAT back.
 *
 * @param tat The stored TAT (ms since epoch), or `undefined` for a bucket that has never been used (= full).
 * @returns The TAT to store (or `undefined` to store nothing) and the answer.
 */
export function gcra(
    tat: number | undefined,
    now: number,
    policy: BucketPolicy,
    cost: number,
    mode: BucketMode,
): { tat: number | undefined; result: BucketResult } {
    const interval: number = policy.intervalMs;
    const capacity: number = policy.burst * interval;
    const current: number = Math.max(tat ?? now, now);

    if (mode === "refund") {
        const refunded: number = Math.max(current - cost * interval, now);
        return { tat: refunded, result: { allowed: true, retryAfterMs: 0, remaining: remaining(refunded, now, capacity, interval) } };
    }

    const next: number = current + cost * interval;
    const earliest: number = next - capacity;
    if (now < earliest) {
        return {
            tat: tat === undefined ? undefined : current,
            result: { allowed: false, retryAfterMs: Math.ceil(earliest - now), remaining: remaining(current, now, capacity, interval) },
        };
    }
    const stored: number = mode === "spend" ? next : current;
    return { tat: stored, result: { allowed: true, retryAfterMs: 0, remaining: remaining(stored, now, capacity, interval) } };
}

function remaining(tat: number, now: number, capacity: number, interval: number): number {
    return Math.max(0, Math.floor((capacity - Math.max(tat - now, 0)) / interval));
}

/**
 * An `AcmeStore` in process memory. Correct for one node: JavaScript runs each method to completion, which makes every
 * operation atomic. Expired entries are dropped lazily and by a periodic sweep so the map cannot grow without bound.
 *
 * @author Jean-Philippe Steinmetz
 */
export class MemoryAcmeStore implements AcmeStore {
    private readonly keys: Map<string, number> = new Map();
    private readonly buckets: Map<string, { tat: number; expiresAt: number }> = new Map();
    private readonly now: () => number;
    private sweeper?: NodeJS.Timeout;

    /** @param now The clock, in ms since epoch. Injectable for tests. */
    constructor(now: () => number = Date.now) {
        this.now = now;
        this.sweeper = setInterval(() => this.sweep(), 60_000);
        this.sweeper.unref();
    }

    public async putIfAbsent(key: string, ttlSeconds: number): Promise<boolean> {
        const now: number = this.now();
        const expiresAt: number | undefined = this.keys.get(key);
        if (expiresAt !== undefined && expiresAt > now) {
            return false;
        }
        this.keys.set(key, now + ttlSeconds * 1000);
        return true;
    }

    public async take(key: string): Promise<boolean> {
        const expiresAt: number | undefined = this.keys.get(key);
        if (expiresAt === undefined) {
            return false;
        }
        this.keys.delete(key);
        return expiresAt > this.now();
    }

    public async bucket(key: string, policy: BucketPolicy, cost: number, mode: BucketMode): Promise<BucketResult> {
        const now: number = this.now();
        const entry = this.buckets.get(key);
        const tat: number | undefined = entry && entry.expiresAt > now ? entry.tat : undefined;
        const outcome = gcra(tat, now, policy, cost, mode);
        if (outcome.tat !== undefined && outcome.tat > now) {
            this.buckets.set(key, { tat: outcome.tat, expiresAt: outcome.tat });
        } else {
            this.buckets.delete(key);
        }
        return outcome.result;
    }

    public async close(): Promise<void> {
        if (this.sweeper) {
            clearInterval(this.sweeper);
            this.sweeper = undefined;
        }
    }

    /** Drops every expired entry. */
    public sweep(): void {
        const now: number = this.now();
        for (const [key, expiresAt] of this.keys) {
            if (expiresAt <= now) {
                this.keys.delete(key);
            }
        }
        for (const [key, entry] of this.buckets) {
            if (entry.expiresAt <= now) {
                this.buckets.delete(key);
            }
        }
    }

    /** The number of live keys and buckets (for tests). */
    public size(): number {
        return this.keys.size + this.buckets.size;
    }
}

/**
 * The Lua script `RedisAcmeStore` runs a token-bucket operation with. It is `gcra()` above, executed inside Redis so
 * that the read-modify-write is one atomic step no matter how many replicas share the bucket; the clock is Redis's own
 * (`TIME`), so replica clock skew cannot open or close a bucket.
 *
 * KEYS[1] bucket key; ARGV: interval ms, burst, cost, mode ("spend" | "check" | "refund").
 * Returns `{allowed (0|1), retryAfterMs, remaining}`.
 */
export const GCRA_LUA = `
local t = redis.call('TIME')
local now = t[1] * 1000 + math.floor(t[2] / 1000)
local interval = tonumber(ARGV[1])
local capacity = tonumber(ARGV[2]) * interval
local cost = tonumber(ARGV[3])
local mode = ARGV[4]
local stored = redis.call('GET', KEYS[1])
local tat = now
if stored then tat = tonumber(stored) end
local current = math.max(tat, now)
local function left(value)
  return math.max(0, math.floor((capacity - math.max(value - now, 0)) / interval))
end
local function save(value)
  if value > now then
    redis.call('SET', KEYS[1], string.format('%.0f', value), 'PX', math.max(1, math.ceil(value - now)))
  else
    redis.call('DEL', KEYS[1])
  end
end
if mode == 'refund' then
  local refunded = math.max(current - cost * interval, now)
  save(refunded)
  return {1, 0, left(refunded)}
end
local nextTat = current + cost * interval
local earliest = nextTat - capacity
if now < earliest then
  return {0, math.ceil(earliest - now), left(current)}
end
local keep = current
if mode == 'spend' then keep = nextTat end
save(keep)
return {1, 0, left(keep)}
`;

/** The subset of a `redis` (node-redis v5+) client `RedisAcmeStore` uses. */
export interface RedisLike {
    set(key: string, value: string, options: { EX: number; NX: true }): Promise<string | null>;
    del(key: string): Promise<number>;
    eval(script: string, options: { keys: string[]; arguments: string[] }): Promise<unknown>;
}

/**
 * An `AcmeStore` in Redis, shared by every replica. Keys are prefixed so the CA can share a Redis with other services.
 *
 * @author Jean-Philippe Steinmetz
 */
export class RedisAcmeStore implements AcmeStore {
    private readonly client: RedisLike;
    private readonly prefix: string;

    constructor(client: RedisLike, prefix: string = "acme:") {
        this.client = client;
        this.prefix = prefix;
    }

    public async putIfAbsent(key: string, ttlSeconds: number): Promise<boolean> {
        return (await this.client.set(this.prefix + key, "1", { EX: Math.max(1, Math.ceil(ttlSeconds)), NX: true })) === "OK";
    }

    public async take(key: string): Promise<boolean> {
        return (await this.client.del(this.prefix + key)) === 1;
    }

    public async bucket(key: string, policy: BucketPolicy, cost: number, mode: BucketMode): Promise<BucketResult> {
        const reply = (await this.client.eval(GCRA_LUA, {
            keys: [`${this.prefix}bucket:${key}`],
            arguments: [String(Math.max(1, Math.round(policy.intervalMs))), String(policy.burst), String(cost), mode],
        })) as number[];
        return { allowed: Number(reply[0]) === 1, retryAfterMs: Number(reply[1]), remaining: Number(reply[2]) };
    }

    public async close(): Promise<void> {
        // The connection belongs to the framework's ConnectionManager, which closes it.
    }
}
