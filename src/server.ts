#!/usr/bin/env node
///////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2026 Jean-Philippe Steinmetz
// SPDX-License-Identifier: MPL-2.0
///////////////////////////////////////////////////////////////////////////////
import config from "./config.js";
import { Logger } from "@rapidrest/core";
import { ObjectFactory, Server } from "@rapidrest/service-core";
import { assertProductionConfig, DEVELOPMENT_ENVIRONMENTS } from "./config.defaults.js";
import { AcmeContext } from "./services/AcmeContext.js";

// A certificate authority must not start half-configured: a wrong external URL would put wrong CRL/OCSP addresses into every
// certificate it signs.
assertProductionConfig(config, process.env.NODE_ENV);

const environment: string = process.env.NODE_ENV || "production";
const logLevel: string = config.get("logger:level") || (DEVELOPMENT_ENVIRONMENTS.includes(environment) ? "debug" : "info");
const logger = Logger(logLevel, config.get("logger:file"));
console.log("Log Level=" + logLevel);

const objectFactory = new ObjectFactory(config, logger);
let server: any = undefined;

const start = async function (config: any, logger: any) {
    server = new Server({ config, basePath: config.get("base_path"), logger, objectFactory });
    await server.start();

    // `AcmeContext` loads the issuers and opens the shared stores while the routes are being created. If that failed the
    // routes would answer every request with an internal error: better to stop, loudly, and let the orchestrator restart it.
    const context: AcmeContext | undefined = objectFactory.getInstance(AcmeContext);
    if (!context?.ready) {
        logger.error("The CA did not initialize (see the errors above: usually the issuer manifest or a key file). Exiting.");
        await shutdown(1);
    }
};

start(config, logger).catch(async (err) => {
    logger.error("The server failed to start.");
    logger.error(err);
    await shutdown(1);
});

let shuttingDown: boolean = false;
const shutdown = async (code: number = 0) => {
    if (shuttingDown) {
        return;
    }
    shuttingDown = true;
    logger.info("Shutting down...");
    try {
        if (server) {
            await server.stop();
        }
        if (objectFactory) {
            await objectFactory.destroy();
        }
    } catch (err) {
        logger.error(err);
    }
    process.exit(code);
};

process.on("SIGINT", () => void shutdown());
process.on("SIGTERM", () => void shutdown());
