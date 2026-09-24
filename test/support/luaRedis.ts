///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import fengari from "fengari";
import type { RedisLike } from "../../src/lib/acme/AcmeStore.js";

const { lua, lauxlib, lualib } = fengari;
const to_luastring = fengari.to_luastring; // eslint-disable-line typescript/naming-convention

/**
 * A stand-in for Redis that runs the CA's real Lua script in a Lua VM (fengari, in pure JavaScript) against an in-memory
 * key space and a clock the test controls. Only the commands the script uses exist (`TIME`, `GET`, `SET ... PX`, `DEL`) plus
 * the ones `RedisAcmeStore` itself calls (`SET ... EX NX`, `DEL`).
 *
 * It exists because no Redis server is available where the tests run, and the token-bucket script is the one piece of code
 * that only ever executes inside Redis: this proves the *text* of the script, not a reimplementation of it.
 */
export class LuaRedis implements RedisLike {
    /** The clock, in ms since epoch: what `TIME` reports and what expiries are measured against. */
    public now: number = Date.UTC(2030, 0, 1);
    public readonly data: Map<string, { value: string; expiresAt?: number }> = new Map();
    /** Every command the script issued, for assertions. */
    public readonly commands: string[][] = [];

    private live(key: string): string | undefined {
        const entry = this.data.get(key);
        if (!entry) {
            return undefined;
        }
        if (entry.expiresAt !== undefined && entry.expiresAt <= this.now) {
            this.data.delete(key);
            return undefined;
        }
        return entry.value;
    }

    public async set(key: string, value: string, options: { EX: number; NX: true }): Promise<string | null> {
        if (this.live(key) !== undefined) {
            return null;
        }
        this.data.set(key, { value, expiresAt: this.now + options.EX * 1000 });
        return "OK";
    }

    public async del(key: string): Promise<number> {
        const existed: boolean = this.live(key) !== undefined;
        this.data.delete(key);
        return existed ? 1 : 0;
    }

    public async eval(script: string, options: { keys: string[]; arguments: string[] }): Promise<unknown> {
        const L = lauxlib.luaL_newstate();
        lualib.luaL_openlibs(L);
        try {
            const table = (name: string, values: string[]): void => {
                lua.lua_createtable(L, values.length, 0);
                values.forEach((value, index) => {
                    lua.lua_pushstring(L, to_luastring(value));
                    lua.lua_rawseti(L, -2, index + 1);
                });
                lua.lua_setglobal(L, to_luastring(name));
            };
            table("KEYS", options.keys);
            table("ARGV", options.arguments);

            const call = (state: any): number => {
                const args: string[] = [];
                for (let i = 1; i <= lua.lua_gettop(state); i++) {
                    args.push(fengari.to_jsstring(lua.lua_tolstring(state, i)));
                }
                this.commands.push(args);
                const [command, key] = [args[0].toUpperCase(), args[1]];
                if (command === "TIME") {
                    lua.lua_createtable(state, 2, 0);
                    lua.lua_pushstring(state, to_luastring(String(Math.floor(this.now / 1000))));
                    lua.lua_rawseti(state, -2, 1);
                    lua.lua_pushstring(state, to_luastring(String((this.now % 1000) * 1000)));
                    lua.lua_rawseti(state, -2, 2);
                    return 1;
                }
                if (command === "GET") {
                    const value: string | undefined = this.live(key);
                    if (value === undefined) {
                        lua.lua_pushboolean(state, false);
                    } else {
                        lua.lua_pushstring(state, to_luastring(value));
                    }
                    return 1;
                }
                if (command === "SET") {
                    const px: number = args[3]?.toUpperCase() === "PX" ? Number(args[4]) : NaN;
                    if (!Number.isFinite(px) || px < 1) {
                        throw new Error(`the script must SET with a positive PX, got ${args.join(" ")}`);
                    }
                    this.data.set(key, { value: args[2], expiresAt: this.now + px });
                    lua.lua_pushstring(state, to_luastring("OK"));
                    return 1;
                }
                if (command === "DEL") {
                    lua.lua_pushinteger(state, this.data.delete(key) ? 1 : 0);
                    return 1;
                }
                throw new Error(`the script used an unsupported command: ${command}`);
            };
            lua.lua_createtable(L, 0, 1);
            lua.lua_pushjsfunction(L, call);
            lua.lua_setfield(L, -2, to_luastring("call"));
            lua.lua_setglobal(L, to_luastring("redis"));

            const status: number = lauxlib.luaL_loadstring(L, to_luastring(script));
            if (status !== lua.LUA_OK || lua.lua_pcall(L, 0, 1, 0) !== lua.LUA_OK) {
                throw new Error(`Lua error: ${fengari.to_jsstring(lua.lua_tolstring(L, -1))}`);
            }
            const result: number[] = [];
            const length: number = lua.lua_rawlen(L, -1);
            for (let i = 1; i <= length; i++) {
                lua.lua_rawgeti(L, -1, i);
                result.push(lua.lua_tonumber(L, -1));
                lua.lua_pop(L, 1);
            }
            return result;
        } finally {
            lua.lua_close(L);
        }
    }
}
