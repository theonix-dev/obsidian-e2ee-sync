# Obsidian E2EE Sync — storage server container image.
#
# Build:        docker build -t obsidian-e2ee-sync -f server/Dockerfile .
# Run:          docker run -v obsidian-sync-data:/data -p 127.0.0.1:8080:8080 \
#                   -e AUTH_TOKEN=<token> obsidian-e2ee-sync
#
# The container binds 0.0.0.0 by design (Docker network semantics); exposure
# is governed by the host port mapping — publish to 127.0.0.1 only and
# terminate TLS with a reverse proxy (see server/nginx.conf.example).

FROM node:22-alpine

LABEL org.opencontainers.image.title="obsidian-e2ee-sync" \
      org.opencontainers.image.description="Untrusted ciphertext store for Obsidian E2EE vault synchronization" \
      org.opencontainers.image.source="https://github.com/theonix-dev/obsidian-e2ee-sync" \
      org.opencontainers.image.licenses="MIT"

# The server stores uploads and index state under DATA_DIR; mount a volume there.
ENV PORT=8080 \
    HOST=0.0.0.0 \
    DATA_DIR=/data \
    NODE_ENV=production

COPY server/server.js /app/server.js

VOLUME /data

# Run as the unprivileged 'node' user provided by the base image.
# /data is created here so the volume inherits node ownership on first use.
RUN mkdir -p /data && chown node:node /data

USER node

WORKDIR /app

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

ENTRYPOINT ["node", "server.js"]
