FROM node:latest
ADD . /app
WORKDIR /app
RUN npm ci
CMD ["node", "dist/server.js"]
