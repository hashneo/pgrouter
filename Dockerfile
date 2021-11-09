FROM node:10-jessie

WORKDIR /src
ADD . .

RUN npm install

EXPOSE 5000

CMD ["node", "proxy.js"]
