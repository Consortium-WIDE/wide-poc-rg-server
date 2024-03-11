// redisClient.js
const Redis = require('ioredis');

// Initialize Redis Client
const redisClient = new Redis({
    port: process.env.UPSTASH_PORT,
    host: process.env.UPSTASH_ENDPOINT,
    password: process.env.UPSTASH_PASSWORD,
    tls: {}
});

module.exports = { redisClient };