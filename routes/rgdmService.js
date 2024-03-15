const express = require('express');
const router = express.Router();
const { Web3 } = require('web3');
const { redisClient } = require('../clients/redisClient');
const isAuthenticated = require('../middleware/authenticate');
const verifyPresentation = require('../helpers/verifyPresentation');

const keyPrefix = process.env.REDIS_KEY_PREFIX || '';

const web3 = new Web3();

router.get('/data/:token', async (req, res) => {
  const key = req.params.token;
  const redisKey = `${keyPrefix}:${key}`;
  const data = await redisClient.get(redisKey);

  if (data) {
    res.status(200).json({ data: JSON.parse(data) });
  } else {
    res.status(404).json('Data not found');
  }
});

router.post('/user/register/:userId', async (req, res) => {
  const { userId } = req.params;
  const membershipCredential = req.body; // userData can be empty for anonymous users
  const userDataKey = `${keyPrefix}:${userId}`;
  const userKey = `${keyPrefix}:user:${userId}`;

  //There's two phases to what we do here.
  //First we fetch the presented poap for signup, through the upload token (which is also the userId), and we verify that this is the credential that was presented to WIDE
  //Then, provided the verification succeds, we may register the user
  try {
    //Step 1. Retrieve Credential from upload cache
    const registrationCredentialKey = `${keyPrefix}:${userId}`;
    const registrationCredential = JSON.parse(await redisClient.get(registrationCredentialKey));

    if (!registrationCredential) {
      res.status(400).send('Unable to find profile for user');
      return;
    }

    //Step 2. Verify authenticity since being added to WIDE
    const presentationVerified = await verifyPresentation(registrationCredential);

    if (!presentationVerified) {
      res.status(403).send('Presented credential failed verification. Cannot register user.');
      return;
    }

    //Step 3. Verify that the membershipCredential posted, aligns with the registration credential
    //This is to ensure that there was no malicious modification of data since issuance by WIDE

    const verifyCredentialAuthenticity = 
    membershipCredential.data.daoContract == getCredentialProperty(registrationCredential, 'id') &&
    membershipCredential.data.daoCreateDate == getCredentialProperty(registrationCredential, 'createdAt') &&
    membershipCredential.data.daoName == getCredentialProperty(registrationCredential, 'name') &&
    membershipCredential.data.dungeonMasterUserId == userId;

    if (!verifyCredentialAuthenticity){
      res.status(403).json('Credential mismatch. Unable to complete profile setup and sign in');
      return
    }

    //Step 3. Create empty profile and sign up the user
    const userData = {
      wideCredentialId: membershipCredential.wideCredentialId
    }

    const baseProfileData = { registrationDate: Math.floor(new Date().getTime() / 1000).toString() };
    const profileDataToUpdate = { ...baseProfileData, ...userData };

    await redisClient.hset(userKey, profileDataToUpdate);
    await redisClient.del(userDataKey);

    req.session.userId = userId;
    res.json({ message: `User profile set for userId ${userId}.` });

  } catch (error) {
    console.error('Error updating user profile:', error);
    res.status(500).send('Error updating user profile.');
  }
});

router.get('/user/status', async (req, res) => {
  if (req.session && req.session.userId) {
    const userId = req.session.userId;

    return res.json({ userId });
  } else {
    res.json(null);
  }
});

router.post('/authenticate', async (req, res) => {
  const token = req.body.authToken;
  const redisKey = `${keyPrefix}:${token}`;

  const userCredential = JSON.parse(await redisClient.get(redisKey));

  if (userCredential) {
    const userId = getCredentialProperty(userCredential, 'dungeonMasterUserId');
    req.session.userId = userId;
    const userKey = `${keyPrefix}:user:${userId}`;

    const profile = await redisClient.hgetall(userKey);

    await redisClient.del(redisKey);

    res.send({ success: true, user: profile, message: 'Authenticated Successfully' });
  } else {
    res.status(401).send({ success: false, message: 'Failed to Authenticate User.' });
  }
});

function getCredentialProperty(credential, property) {
  return credential.credentialSubject.issuerDomains.map(issuerDomain => issuerDomain.data.credentials).flat().filter(cred => cred.name.toLowerCase() == property.toLowerCase())[0].value;
}

module.exports = router;