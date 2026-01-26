FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY server.js ./
COPY public ./public

ENV PORT=4040
ENV SHARED_DIR=/data/shared
ENV ALLOW_FULL_FILESYSTEM=false

VOLUME /app/data

EXPOSE 4040

CMD ["node", "server.js"]
