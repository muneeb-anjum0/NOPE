FROM node:24-alpine AS deps
WORKDIR /app/apps/web
COPY apps/web/package.json ./
RUN npm install

FROM node:24-alpine AS builder
WORKDIR /app/apps/web
COPY --from=deps /app/apps/web/node_modules ./node_modules
COPY apps/web ./
RUN npm run build

FROM node:24-alpine AS runtime
WORKDIR /app/apps/web
ENV NODE_ENV=production
RUN addgroup -S nope && adduser -S nope -G nope
COPY --from=builder /app/apps/web ./
USER nope
EXPOSE 3000
CMD ["npm", "run", "start"]
