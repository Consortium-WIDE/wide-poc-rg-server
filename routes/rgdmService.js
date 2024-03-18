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

router.post('/logout', isAuthenticated, (req, res) => {
  if (req.session) {
    // Destroy the session
    req.session.destroy(err => {
      if (err) {
        console.error('Error destroying session:', err);
        res.status(500).send('Error logging out');
      } else {
        // Optionally clear the client-side cookie
        res.clearCookie('connect.sid'); // The name 'connect.sid' is the default; adjust if you've configured it differently

        res.json({ success: true, message: 'Logged out successfully' });
      }
    });
  } else {
    res.status(400).json({ success: false, message: 'Not logged in' });
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

    if (!verifyCredentialAuthenticity) {
      res.status(403).json('Credential mismatch. Unable to complete profile setup and sign in');
      return
    }

    //Step 3. Create empty profile and sign up the user
    const walletAddress = registrationCredential.credentialSubject.id;
    const walletDataKey = `${keyPrefix}:user-wallet:${walletAddress}`

    const userData = {
      wideCredentialId: membershipCredential.wideCredentialId
    }

    const baseProfileData = { registrationDate: Math.floor(new Date().getTime() / 1000).toString() };
    const profileDataToUpdate = { ...baseProfileData, ...userData };

    await redisClient.hset(userKey, profileDataToUpdate);
    await redisClient.set(walletDataKey, userId);
    await redisClient.del(userDataKey);

    req.session.userId = userId;
    res.json({ message: `User profile set for userId ${userId}.` });

  } catch (error) {
    console.error('Error updating user profile:', error);
    res.status(500).send('Error updating user profile.');
  }
});

router.get('/user/status', isAuthenticated, async (req, res) => {
  if (req.session && req.session.userId) {
    const userId = req.session.userId;

    return res.json({ userId });
  } else {
    res.json(null);
  }
});

router.get('/user', isAuthenticated, async (req, res) => {
  const userId = req.session.userId;
  const userKey = `${keyPrefix}:user:${userId}`;

  try {
    const profile = await redisClient.hgetall(userKey);

    // Initialize the user's raiding status as false
    let isCurrentlyRaiding = false;

    // Retrieve all raids
    const raidIds = await redisClient.smembers(`${keyPrefix}:raids`);
    for (let id of raidIds) {
      const raidKey = `${keyPrefix}:raid:${id}`;
      const raidData = await redisClient.get(raidKey);
      if (raidData) {
        const raid = JSON.parse(raidData);
        // Check if the user is a member and the raid's status is 'Raiding'
        const isMemberRaiding = raid.members.some(member => member.userId === userId) && raid.status === 'Raiding';
        if (isMemberRaiding) {
          isCurrentlyRaiding = true;
          break; // Stop checking further if we already found the user raiding
        }
      }
    }

    // Add the isCurrentlyRaiding status to the user profile response
    res.json({ ...profile, isCurrentlyRaiding, userId });
  } catch (error) {
    console.error('Error retrieving user profile:', error);
    res.status(500).send('Error retrieving user profile.');
  }
});

router.put('/user', isAuthenticated, async (req, res) => {
  const userId = req.session.userId;
  const userKey = `${keyPrefix}:user:${userId}`;

  const { wideCredentialId, registrationDate } = await redisClient.hgetall(userKey);
  const updatedProfile = req.body;

  const baseProfile = {
    wideCredentialId,
    registrationDate
  }

  const profile = { ...baseProfile, ...updatedProfile };

  await redisClient.hset(userKey, profile);

  res.json(profile);
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

router.post('/raids', isAuthenticated, async (req, res) => {
  if (!req.session || !req.session.userId) {
    res.status(401).json({ success: false, message: 'User not authenticated' });
    return;
  }

  const userId = req.session.userId;
  const userKey = `${keyPrefix}:user:${userId}`;

  try {
    // Generate a unique ID for the raid
    const newId = await redisClient.incr('raidId');
    const raidKey = `${keyPrefix}:raid:${newId}`;

    // Fetch the user profile to get the memberName for the raid creator
    const userProfile = await redisClient.hgetall(userKey);
    const memberName = userProfile ? userProfile.memberName : 'Unknown Member'; // Fallback name

    const createdAt = Math.floor(new Date().getTime() / 1000);

    // Initialize the raid with the creator as the first member
    const raid = { ...req.body, members: [{ userId, memberName, role: 'Cleric' }], createdAt };

    // Store the raid data in Redis
    await redisClient.set(raidKey, JSON.stringify(raid));
    // Add the new raid ID to the set of all raids
    await redisClient.sadd(`${keyPrefix}:raids`, newId);

    res.json({ success: true, message: 'Raid created successfully', raidId: newId });
  } catch (error) {
    console.error('Error creating raid:', error);
    res.status(500).send('Error creating raid.');
  }
});


router.get('/raids/:id', isAuthenticated, async (req, res) => {
  const { id } = req.params;
  const raidKey = `${keyPrefix}:raid:${id}`;

  try {
    const raidData = await redisClient.get(raidKey);

    if (raidData) {
      const raid = JSON.parse(raidData);
      // Add the raid ID to the raid object
      raid.id = id;
      res.json({ success: true, raid: raid });
    } else {
      res.status(404).json({ success: false, message: 'Raid not found' });
    }
  } catch (error) {
    console.error('Error retrieving raid:', error);
    res.status(500).send('Error retrieving raid.');
  }
});
// router.put('/raids/:id', async (req, res) => {
//   const { id } = req.params;
//   const raidKey = `${keyPrefix}:raid:${id}`;

//   try {
//     const raidExists = await redisClient.exists(raidKey);

//     if (!raidExists) {
//       res.status(404).json({ success: false, message: 'Raid not found' });
//       return;
//     }

//     await redisClient.set(raidKey, JSON.stringify(req.body));

//     res.json({ success: true, message: 'Raid updated successfully' });
//   } catch (error) {
//     console.error('Error updating raid:', error);
//     res.status(500).send('Error updating raid.');
//   }
// });

// router.delete('/raids/:id', async (req, res) => {
//   const { id } = req.params;
//   const raidKey = `${keyPrefix}:raid:${id}`;

//   try {
//     const raidExists = await redisClient.exists(raidKey);

//     if (!raidExists) {
//       res.status(404).json({ success: false, message: 'Raid not found' });
//       return;
//     }

//     await redisClient.del(raidKey);

//     await redisClient.srem(`${keyPrefix}:raids`, id);

//     res.json({ success: true, message: 'Raid deleted successfully' });
//   } catch (error) {
//     console.error('Error deleting raid:', error);
//     res.status(500).send('Error deleting raid.');
//   }
// });

router.get('/raids', isAuthenticated, async (req, res) => {
  try {
    const raidIds = await redisClient.smembers(`${keyPrefix}:raids`);
    const raidsWithIds = [];

    for (const id of raidIds) {
      const raidData = await redisClient.get(`${keyPrefix}:raid:${id}`);
      if (raidData) {
        const raid = JSON.parse(raidData);
        // Add the raid ID to the raid object
        raid.id = id;
        raidsWithIds.push(raid);
      }
    }

    res.json({ success: true, raids: raidsWithIds });
  } catch (error) {
    console.error('Error listing raids:', error);
    res.status(500).send('Error listing raids.');
  }
});

router.post('/raids/:raidId/join', isAuthenticated, async (req, res) => {
  if (!req.session || !req.session.userId) {
    res.status(401).json({ success: false, message: 'User not authenticated' });
    return;
  }

  const { raidId } = req.params;
  const { role } = req.body;
  const userId = req.session.userId;

  const userKey = `${keyPrefix}:user:${userId}`;
  const raidKey = `${keyPrefix}:raid:${raidId}`;

  try {
    const userProfile = await redisClient.hgetall(userKey);
    if (!userProfile) {
      res.status(404).json({ success: false, message: 'User profile not found' });
      return;
    }
    const memberName = userProfile.memberName;

    const raidData = await redisClient.get(raidKey);
    if (!raidData) {
      res.status(404).json({ success: false, message: 'Raid not found' });
      return;
    }
    const raid = JSON.parse(raidData);

    const newMember = { userId, memberName, role };
    raid.members = raid.members || [];
    raid.members.push(newMember);

    await redisClient.set(raidKey, JSON.stringify(raid));

    res.json({ success: true, message: 'Member added successfully' });
  } catch (error) {
    console.error('Error adding member to raid:', error);
    res.status(500).send('Error adding member to raid.');
  }
});

router.post('/raids/:raidId/end', isAuthenticated, async (req, res) => {
  if (!req.session || !req.session.userId) {
    res.status(401).json({ success: false, message: 'User not authenticated' });
    return;
  }

  const { raidId } = req.params;
  const raidKey = `${keyPrefix}:raid:${raidId}`;

  try {
    // Fetch the raid
    const raidData = await redisClient.get(raidKey);
    if (!raidData) {
      res.status(404).json({ success: false, message: 'Raid not found' });
      return;
    }

    const raid = JSON.parse(raidData);

    // Check if the raid is already ended
    if (raid.ended) {
      res.status(400).json({ success: false, message: 'Raid already ended' });
      return;
    }

    // Update the raid to mark it as ended
    raid.status = 'Ended';
    raid.endedAt = Math.floor(new Date().getTime() / 1000); // Store the ended timestamp

    // Save the updated raid back to Redis
    await redisClient.set(raidKey, JSON.stringify(raid));

    res.json({ success: true, message: 'Raid ended successfully' });
  } catch (error) {
    console.error('Error ending raid:', error);
    res.status(500).send('Error ending raid.');
  }
});

router.post('/raids/:raidId/leave', isAuthenticated, async (req, res) => {
  if (!req.session || !req.session.userId) {
    res.status(401).json({ success: false, message: 'User not authenticated' });
    return;
  }

  const { raidId } = req.params;
  const userId = req.session.userId;
  const raidKey = `${keyPrefix}:raid:${raidId}`;

  try {
    // Fetch the raid
    const raidData = await redisClient.get(raidKey);
    if (!raidData) {
      res.status(404).json({ success: false, message: 'Raid not found' });
      return;
    }
    const raid = JSON.parse(raidData);

    // Find and remove the user from the members list
    const index = raid.members.findIndex(member => member.userId === userId);
    if (index === -1) {
      res.status(404).json({ success: false, message: 'Member not found in raid' });
      return;
    }

    raid.members.splice(index, 1); // Remove the member from the list

    // Save the updated raid back to Redis
    await redisClient.set(raidKey, JSON.stringify(raid));

    res.json({ success: true, message: 'Participation in raid ended successfully' });
  } catch (error) {
    console.error('Error ending participation in raid:', error);
    res.status(500).send('Error ending participation in raid.');
  }
});

module.exports = router;