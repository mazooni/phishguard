# syntax = docker/dockerfile:1
# PhishGuard relay — multi-stage build on node:22-slim.
# The build stage carries the toolchain better-sqlite3 needs when no prebuilt binary matches
# (build-essential, node-gyp, python); the runtime stage ships only the compiled app.

ARG NODE_VERSION=22
FROM node:${NODE_VERSION}-slim AS base
LABEL fly_launch_runtime="Node.js"
WORKDIR /app
ENV NODE_ENV="production"

# ---- build ----------------------------------------------------------------
FROM base AS build
RUN apt-get update -qq && \
    apt-get install --no-install-recommends -y build-essential node-gyp pkg-config python-is-python3 ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json ./
RUN npm ci --include=dev

COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev

# ---- runtime --------------------------------------------------------------
FROM base
RUN apt-get update -qq && \
    apt-get install --no-install-recommends -y ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /data && chown node:node /data

COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist ./dist
COPY --chown=node:node package.json ./

USER node
ENV PORT=8080 DATA_DIR=/data
EXPOSE 8080
CMD ["node", "dist/index.js"]
