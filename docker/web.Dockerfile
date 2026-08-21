FROM node:24-alpine AS deps
WORKDIR /app
RUN npm install --global pnpm@11.5.0 \
    --fetch-retries=5 \
    --fetch-retry-mintimeout=20000 \
    --fetch-retry-maxtimeout=120000 \
    --fetch-timeout=300000
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/web/package.json ./apps/web/package.json
RUN pnpm install --frozen-lockfile --filter nope-web...

FROM node:24-alpine AS builder
WORKDIR /app
RUN npm install --global pnpm@11.5.0 \
    --fetch-retries=5 \
    --fetch-retry-mintimeout=20000 \
    --fetch-retry-maxtimeout=120000 \
    --fetch-timeout=300000
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/apps/web/node_modules ./apps/web/node_modules
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/web ./apps/web
RUN pnpm --dir apps/web build

FROM node:24-alpine AS runtime
WORKDIR /app/apps/web
ENV NODE_ENV=production
RUN addgroup -S nope && adduser -S nope -G nope
COPY --from=builder /app/node_modules /app/node_modules
COPY --from=builder /app/apps/web ./
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx
USER nope
EXPOSE 3000
CMD ["node", "node_modules/next/dist/bin/next", "start", "-p", "3000"]
