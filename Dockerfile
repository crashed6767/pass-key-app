FROM node:22-alpine

WORKDIR /app
ENV NODE_ENV=production

COPY package*.json ./
RUN npm ci --omit=dev

COPY --chmod=0644 src ./src
COPY --chmod=0755 public ./public
COPY --chmod=0755 scripts ./scripts
RUN chmod -R a+rX /app

EXPOSE 8091
CMD ["node", "src/server.mjs"]
