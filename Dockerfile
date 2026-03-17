FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY server.js ./
COPY public ./public

RUN addgroup -S appgroup && adduser -S appuser -G appgroup
RUN mkdir -p /app/data /data/shared && chown -R appuser:appgroup /app/data /data/shared

ENV PORT=4040
ENV SHARED_DIR=/data/shared
ENV ALLOW_FULL_FILESYSTEM=false

VOLUME /app/data

EXPOSE 4040

USER appuser

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget --spider -q http://localhost:4040/api/status || exit 1

CMD ["node", "server.js"]
