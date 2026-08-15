# cliotp-server — minimal, non-root image with zero runtime dependencies.
FROM node:25-alpine

ENV NODE_ENV=production \
    PORT=8080 \
    HOST=0.0.0.0 \
    CLIOTP_DATA_DIR=/data

WORKDIR /app

COPY package.json server.js ./
COPY public ./public

RUN mkdir -p /data && chown -R node:node /data /app

USER node

EXPOSE 8080
VOLUME /data

# wget ships with busybox on alpine
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null 2>&1 || exit 1

CMD ["node", "server.js"]
