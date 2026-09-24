import { defineConfig } from "vitest/config";
import swc from "unplugin-swc";
import { resolve } from "path";

export default defineConfig({
    resolve: {
        alias: {
            "@rapidrest/service-core/dist/lib/test/request.js": resolve(
                "node_modules/@rapidrest/service-core/dist/lib/test/request.js",
            ),
            "@rapidrest/service-core/dist/lib/test/requestws.js": resolve(
                "node_modules/@rapidrest/service-core/dist/lib/test/requestws.js",
            ),
        },
    },
    ssr: {
        noExternal: ["@rapidrest/service-core", "@rapidrest/core"],
    },
    plugins: [
        swc.vite({
            jsc: {
                parser: {
                    syntax: "typescript",
                    decorators: true,
                },
                transform: {
                    decoratorMetadata: true,
                    legacyDecorator: true,
                },
                target: "es2020",
            },
        }),
    ],
    test: {
        globals: true,
        environment: "node",
        include: ["test/**/*.test.ts"],
        fileParallelism: false,
        pool: "forks",
        poolOptions: {
            forks: {
                execArgv: ["--no-experimental-strip-types"],
            },
        },
        clearMocks: true,
        coverage: {
            enabled: true,
            provider: "v8",
            include: ["src/**/*.ts"],
            exclude: ["**/node_modules/**", "**/test/**"],
            reporter: ["text", "json", "html", "lcov"],
            thresholds: {
                branches: 0,
                functions: 0,
                lines: 0,
                statements: 0,
            },
            reportsDirectory: "coverage",
        },
        reporters: ["default", "junit"],
        outputFile: {
            junit: "junit.xml",
        },
    },
});
