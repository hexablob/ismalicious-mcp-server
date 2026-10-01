# check=skip=SecretsUsedInArgOrEnv
# Builds the stdio server from source and runs it. Glama builds this file to
# start the server and list its tools; `npx -y @ismalicious/mcp-server` stays
# the documented way to run it anywhere else.

FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* tsconfig.json tsup.config.ts ./
# In the isMalicious monorepo this tsconfig extends a workspace-only config
# that package.json lists as a devDependency; the public repository has
# neither. Dropping both is a no-op there and lets this file build either copy.
RUN npm pkg delete 'devDependencies.@ismalicious/typescript-config' \
  && sed -i '/"extends"/d' tsconfig.json \
  && npm install --no-audit --no-fund
COPY src ./src
RUN npm run build

# The server has no runtime dependencies: dist/ and package.json are enough.
FROM node:22-alpine
ENV NODE_ENV=production
# A placeholder key pair, not a secret (hence the check skipped on line 1): the
# image starts in keyed mode and `tools/list` returns every tool, where no key
# would offer only bootstrap_key. Listing tools makes no network call; calling
# one with this pair gets the API's 401. Pass a real pair with `-e`, or set
# both empty for bootstrap mode. The connection warm-up that follows
# `initialize` when a key is set is off here: the pair is a placeholder, and
# a registry listing tools has no use for a warm socket.
ENV ISMALICIOUS_API_KEY=placeholder \
    ISMALICIOUS_API_SECRET=placeholder \
    ISMALICIOUS_PREWARM=0
WORKDIR /app
COPY --from=build /app/package.json ./
COPY --from=build /app/dist ./dist
USER node
CMD ["node", "dist/index.js"]
