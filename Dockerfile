# The RapidMX ACME certificate authority.
#
# Stages: builder (full toolchain) -> prod-deps (production node_modules only) -> ca-init (throw-away development CA
# generator, see docker-compose.yml) -> runtime (the image that is published; it is the last stage, so a plain
# `docker build .` produces it).
FROM node:24-trixie-slim AS builder
WORKDIR /app

# Corepack fetches the yarn release named by package.json's packageManager on first use.
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0
# The in-memory database servers the tests use download hundreds of MB of binaries in their postinstall; the build never
# runs a test.
ENV MONGOMS_DISABLE_POSTINSTALL=1
ENV REDISMS_DISABLE_POSTINSTALL=true
RUN corepack enable

# Manifests first so the (slow) dependency layer is reused until they change.
COPY package.json yarn.lock .yarnrc.yml ./
COPY .yarn/releases ./.yarn/releases
RUN yarn install --immutable

COPY tsconfig.json tsconfig.eslint.json eslint.config.mjs ./
COPY src ./src
COPY scripts ./scripts
# `rapidrest build`: lints ./src, then compiles with tsc into dist/src (the entry point is dist/src/server.js).
RUN yarn build

# The runtime's node_modules: production dependencies only, so the build and test tooling (vite, vitest, tsx, the rapidrest
# CLI, the in-memory database servers, eslint, typescript...) never ships. Checked to start and serve with NODE_ENV=production.
FROM builder AS prod-deps
RUN yarn workspaces focus --production
# uWebSockets.js ships prebuilt binaries for every OS and Node ABI; only the Linux ones can ever load here. (The ABI and
# architecture variants are kept: they are picked at run time, and the base image's Node major may change.)
RUN find node_modules/uWebSockets.js -maxdepth 1 -type f \( -name 'uws_darwin_*' -o -name 'uws_win32_*' \) -delete

# A generator for a throw-away development CA, run by docker-compose.yml's `ca-init` service (`docker compose run --rm ca-init
# --help` lists the options). It is built from the builder stage because scripts/ca-init.ts runs with tsx, a dev dependency
# the runtime image deliberately does not have. Do not use it for a production root: see docs/DEPLOYMENT.md.
FROM builder AS ca-init
# Created and owned by `node` before any volume is mounted, so a fresh named volume inherits that ownership and both this
# stage and the runtime (also `node`) can use it.
RUN mkdir -p /var/lib/acme/ca && chown node:node /var/lib/acme/ca
USER node
ENTRYPOINT ["node", "/app/node_modules/tsx/dist/cli.mjs", "/app/scripts/ca-init.ts"]
CMD ["--help"]

FROM node:24-trixie-slim AS runtime
LABEL org.opencontainers.image.title="acme" \
      org.opencontainers.image.description="The RapidMX ACME certificate authority for S/MIME certificates (RFC 8555, RFC 8823)." \
      org.opencontainers.image.source="https://github.com/rapidmx/acme" \
      org.opencontainers.image.licenses="MPL-2.0"
WORKDIR /app

# Root-owned and not writable by the `node` user the service runs as: a compromised process cannot alter its own code. The
# service writes nothing to disk (logs go to stdout), so the root file system can be mounted read-only, with an empty
# volume at /tmp for Node's own needs. config.ts reads ./package.json from the working directory at start-up.
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/dist ./dist
COPY --from=prod-deps /app/node_modules ./node_modules

ENV NODE_ENV=production
# Informational: the HTTP server reads the lower-case `port` setting (default 3000), not PORT.
ENV PORT=3000

# 3000: the ACME API and the CA's public trust endpoints (HTTP). 2525: the built-in SMTP receiver for reply e-mails; it
# listens only when acme__mail__inbound__smtp__enabled=true (a Service maps it to port 25, see helm/).
EXPOSE 3000 2525

# There is no volume: the issuing CA's certificate and key, the DKIM key and any SMTP TLS certificate arrive as mounted
# secrets (by default under /var/lib/acme/ca and /var/lib/acme/dkim), never as image content.
USER node

# No curl in the image: a one-line Node client against GET /status. 127.0.0.1, not localhost, so an IPv6-only resolution
# cannot fail the check.
HEALTHCHECK --interval=30s --timeout=6s --start-period=30s --retries=3 \
    CMD ["node", "-e", "fetch('http://127.0.0.1:'+(process.env.port||3000)+'/status',{signal:AbortSignal.timeout(5000)}).then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]

# `node` itself (not yarn or rapidrest) as PID 1, so SIGTERM reaches the server's own graceful shutdown.
CMD ["node", "dist/src/server.js"]
