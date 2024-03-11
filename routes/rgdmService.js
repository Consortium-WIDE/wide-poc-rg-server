const express = require('express');
const router = express.Router();
const { Web3 } = require('web3');
const { redisClient } = require('../clients/redisClient');
const isAuthenticated = require('../middleware/authenticate');
const verifyPresentation = require('../helpers/verifyPresentation');

const keyPrefix = process.env.REDIS_KEY_PREFIX || '';

const web3 = new Web3();

router.get('/', async (req, res) => {
    try {
        res.send({ success: true, message: 'Hello World' });
    } catch (error) {
        res.status(500).send('An error occurred');
    }
});

module.exports = router;