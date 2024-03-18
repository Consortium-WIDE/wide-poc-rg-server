const express = require('express');
const router = express.Router();
const { redisClient } = require('../clients/redisClient');

const keyPrefix = process.env.REDIS_KEY_PREFIX || '';

// Route for WIDE Client to upload data
router.post('/uploadData', async (req, res) => {
    const { key, data } = req.body;
    const redisKey = `${keyPrefix}:${key}`;

    redisClient.set(redisKey, JSON.stringify(data));

    res.status(200).json('Data uploaded successfully');
});

router.post('/registerProfileData/:type', async (req, res) => {
    const { key, data } = req.body;
    const { type } = req.params;

    //This assumes the presentation is only for 
    const value = data.credentialSubject.issuerDomains.flat()[0].data.credentials[0].value;
    
    const walletAddress = data.credentialSubject.id;
    const walletDataKey = `${keyPrefix}:user-wallet:${walletAddress}`

    const userId = await redisClient.get(walletDataKey);

    const userKey = `${keyPrefix}:user:${userId}`;

    const profile = await redisClient.hgetall(userKey);

    profile[type] = value;

    await redisClient.hset(userKey, profile);

    res.status(200).json('Data uploaded successfully');
});

router.post('/login', async (req, res) => {
    const tempKey = req.body.key;
    const userAddress = req.body.data.credentialSubject.id;
    const rgdmUserId = req.body.data.credentialSubject.issuerDomains[0].data.credentials.filter(c => c.name == 'id')[0].value;

    const redisTempKey = `${keyPrefix}:login-token:${tempKey}`;
    const redisKey = `${keyPrefix}:${rgdmUserId}`;

    const userRegisteredData = JSON.parse(await redisClient.get(redisKey));

    if (userRegisteredData) {
        if (userRegisteredData.credentialSubject.id === userAddress) {
            await redisClient.set(redisTempKey, JSON.stringify(rgdmUserId), 'EX', 30);
            res.send({ success: true, message: 'Authentication successful.' });
        } else {
            res.status(404).send({ success: false, message: 'Authentication failed.' });
        }
    } else {
        res.status(404).send({ success: false, message: 'Authentication failed.' });
    }
});

module.exports = router;