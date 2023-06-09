FROM node:17.7-alpine
ENV NODE_ENV=production

WORKDIR /app
COPY . .
ADD . /data
RUN npm install --production

CMD ["npm","run","start"]
