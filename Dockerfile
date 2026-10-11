FROM node:20-bookworm-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ && rm -rf /var/lib/apt/lists/*
COPY package*.json ./
RUN npm install --omit=dev
COPY . .
ENV NODE_ENV=production
ENV PORT=3000
ENV DATA_DIR=/data
RUN mkdir -p /data && chown -R node:node /app /data
USER node
EXPOSE 3000
CMD ["npm","start"]
