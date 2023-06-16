FROM node
WORKDIR /app
COPY ./node-statsd.js node-statsd.js
RUN npm install node-statsd
CMD ["node","node-statsd.js"]