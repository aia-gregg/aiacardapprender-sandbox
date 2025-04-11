const express = require('express');
const cors = require('cors');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { MongoClient, ServerApiVersion, Decimal128 } = require('mongodb');
const crypto = require('crypto');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const stripe = require('stripe')(process.env.STRIPE_TEST_KEY); // Test secret key
const { merchantPrivateKey, callWasabiApi } = require('./wasabiApi');
const fireblocks = require('./fireblocks');
const admin = require('./firebaseadmin');
const otplib = require('otplib');
const verifyJWT = require('./jwtMiddleware');
const verifyHMAC = require('./hmacMiddleware');

// MongoDB Connection
const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

function generateSignature(message, privateKey) {
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(message);
  signer.end();
  return signer.sign(privateKey, 'base64');
}

// Helper: Generate a random alphanumeric string of 22 characters for merchantOrderNo
function generateMerchantOrderNo(length = 22) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

// In-memory cache for transaction events (keyed by cardNo)
const transactionCache = {};

// Secret key for JWT (store securely in production)
const secretKey = process.env.JWT_SECRET;


const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Define your protected HMAC key endpoint BEFORE any other routes that need "app"
app.get('/api/get-hmac-secret', verifyJWT, (req, res) => {
  // The HMAC secret is set as an environment variable. Ensure you have set HMAC_SECRET in your Render config.
  const hmacSecret = process.env.HMAC_SECRET;
  if (!hmacSecret) {
    console.error('HMAC secret is not configured on the server.');
    return res.status(500).json({ error: 'HMAC secret is not configured on the server.' });
  }
  // For now we return the static key (be sure to rotate it periodically)
  res.json({ hmacSecret });
});

// Connect to MongoDB
client.connect()
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch((err) => console.error("❌ Error connecting to MongoDB:", err));

  async function decryptUsingMicroservice(encryptedData) {
    if (!encryptedData) return null;
    try {
      const response = await fetch("process.env.AIA_RENDER_SERVER_JAVA_URL/api/decrypt", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ data: encryptedData })
      });
      // Assuming the microservice returns the decrypted string as plain text
      const decrypted = await response.text();
      return decrypted;
    } catch (error) {
      console.error("Error calling decryption microservice:", error);
      return null;
    }
  }

/**
 * GET /api/generate-2fa?email=<user-email>
 *
 * Generates (or reuses) a TOTP secret for the user, saves it in MongoDB,
 * and returns the otpauth URL for Google Authenticator.
 */
app.get('/api/generate-2fa', async (req, res) => {
  const email = req.query.email;
  if (!email) {
    return res.status(400).json({ error: 'Missing email parameter' });
  }
  try {
    const database = client.db(process.env.MONGODB_DB_NAME);
    const collection = database.collection(process.env.MONGODB_COLLECTION);
    let user = await collection.findOne({ email });
    
    if (!user) {
      const totpSecret = otplib.authenticator.generateSecret();
      user = { 
        email, 
        totpSecret, 
        twoFAEnabled: false, 
        isGAVerified: false 
        // add additional default fields as needed
      };
      await collection.insertOne(user);
    } else if (!user.totpSecret) {
      const totpSecret = otplib.authenticator.generateSecret();
      await collection.updateOne({ email }, { $set: { totpSecret } });
      user.totpSecret = totpSecret;
    }
    
    const issuer = 'AIA Pay';
    const otpauthUrl = otplib.authenticator.keyuri(email, issuer, user.totpSecret);
    res.json({ otpauthUrl });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

app.post('/api/verify-2fa', async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) {
    return res.status(400).json({ error: 'Missing email or otp in request body' });
  }
  try {
    const database = client.db(process.env.MONGODB_DB_NAME);
    const collection = database.collection(process.env.MONGODB_COLLECTION);
    const user = await collection.findOne({ email });
    if (!user || !user.totpSecret) {
      return res.status(400).json({ error: 'User not found or 2FA not initialized' });
    }
    const isValid = otplib.authenticator.check(otp, user.totpSecret);
    if (isValid) {
      await collection.updateOne({ email }, { $set: { twoFAEnabled: true, isGAVerified: true } });
      const updatedUser = await collection.findOne({ email });
      const tokenPayload = {
        email: updatedUser.email,
        isGAVerified: updatedUser.isGAVerified,
      };
      const token = jwt.sign(tokenPayload, process.env.JWT_SECRET, { expiresIn: '1h' });
      return res.json({ valid: true, token, user: updatedUser });
    } else {
      return res.json({ valid: false, message: 'Invalid OTP' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

app.post('/api/reset-2fa', async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Missing email parameter' });
  }
  try {
    const database = client.db(process.env.MONGODB_DB_NAME);
    const collection = database.collection(process.env.MONGODB_COLLECTION);
    const user = await collection.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    const newSecret = otplib.authenticator.generateSecret();
    await collection.updateOne({ email }, { 
      $set: { totpSecret: newSecret, twoFAEnabled: false, isGAVerified: false } 
    });
    res.json({ success: true, totpSecret: newSecret });
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// --- Startup Data Seeding Function Using callWasabiApi ---
// async function seedWasabiData() {
//   try {
//     console.log("Starting data seeding from WasabiCard API...");

//     // Get the MongoDB collection for storing region, city, and mobile area code data
//     const db = client.db(process.env.MONGODB_DB_NAME_CITY);
//     const collection = db.collection(process.env.MONGODB_COLLECTION_CITY);

    // Fetch region data using callWasabiApi
    // const regionResult = await callWasabiApi('/merchant/core/mcb/common/region', {});
    // console.log("Fetched Region Data from WasabiCard API:", regionResult);
    // if (regionResult.success && Array.isArray(regionResult.data)) {
    //   for (const region of regionResult.data) {
    //     // Expecting region to have properties: code, standardCode, name
    //     await collection.updateOne(
    //       { type: "region", code: region.code },
    //       { $set: { ...region, type: "region" } },
    //       { upsert: true }
    //     );
    //   }
    // } else {
    //   console.warn("Region data not returned as expected:", regionResult);
    // }

    // Fetch city data using callWasabiApi
    // const cityResult = await callWasabiApi('/merchant/core/mcb/common/city', {});
    // console.log("Fetched City Data from WasabiCard API:", cityResult);
    // if (cityResult.success && Array.isArray(cityResult.data)) {
    //   for (const city of cityResult.data) {
    //     // Expecting city to have properties: code, name, country, countryStandardCode
    //     await collection.updateOne(
    //       { type: "city", code: city.code },
    //       { $set: { ...city, type: "city" } },
    //       { upsert: true }
    //     );
    //   }
    // } else {
    //   console.warn("City data not returned as expected:", cityResult);
    // }

    // Fetch mobile area code data using callWasabiApi
    // const mobileResult = await callWasabiApi('/merchant/core/mcb/common/mobileAreaCode', {});
    // console.log("Fetched Mobile Area Code Data from WasabiCard API:", mobileResult);
    // if (mobileResult.success && Array.isArray(mobileResult.data)) {
    //   for (const mobile of mobileResult.data) {
    //     // Expecting mobile to have properties: code, name, areaCode, language, enableGlobalTransfer
    //     await collection.updateOne(
    //       { type: "mobileAreaCode", code: mobile.code },
    //       { $set: { ...mobile, type: "mobileAreaCode" } },
    //       { upsert: true }
    //     );
    //   }
    // } else {
    //   console.warn("Mobile area code data not returned as expected:", mobileResult);
    // }

//     console.log("Data seeding complete.");
//   } catch (error) {
//     console.error("Error during data seeding:", error);
//   }
// }


// Coupon validation endpoint with logging and expiry check
app.post('/validate-coupon', verifyJWT, async (req, res) => {
  try {
    const { couponCode } = req.body;
    if (!couponCode) {
      return res.status(400).json({ success: false, message: 'Missing coupon code.' });
    }

    // Connect to the coupon database and collection
    const database = client.db(process.env.MONGODB_DB_NAME_VOUCHER);
    const collection = database.collection(process.env.MONGODB_COLLECTION_VOUCHER);

    // Query for the coupon using the provided coupon code
    const coupon = await collection.findOne({ couponCode: couponCode.trim().toUpperCase() });
    if (!coupon) {
      return res.status(400).json({ success: false, message: 'Invalid coupon.' });
    }

    // IMPORTANT: use 'coupon.couponExpiry' instead of 'coupon.expiry'
    const expiryDate = new Date(coupon.couponExpiry);
    const now = new Date();

    // Compare the two dates
    if (now > expiryDate) {
      return res.status(400).json({ success: false, message: 'Coupon expired.' });
    }

    // Coupon is valid
    return res.json({
      success: true,
      discountPercent: coupon.discountPercent,
      message: 'Coupon valid.',
    });
  } catch (error) {
    console.error('Error validating coupon:', error);
    return res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message,
    });
  }
});

// Endpoint to fetch referrals for a given referral ID
app.get('/referrals', verifyJWT, async (req, res) => {
  const { referralId } = req.query;
  if (!referralId) {
    return res.status(400).json({ success: false, message: "Missing referralId parameter" });
  }

  try {
    const database = client.db(process.env.MONGODB_DB_NAME);
    const collection = database.collection(process.env.MONGODB_COLLECTION);

    // Retrieve all users referred by the given referralId.
    const referredUsers = await collection.find({ referralId }).toArray();

    // Map over each referred user and calculate commission based on their position (1-indexed)
    const referralDetails = referredUsers.map((user, index) => {
      const activeCards = user.activeCards || 0;
      let commission = 0;
      const userPosition = index + 1; // 1-indexed position

      // Determine commission rates based on user tier (position in the array)
      let rates = { lite: 0, pro: 0, elite: 0 };

      if (userPosition <= 3) {
        rates.lite = 4.9;
        rates.pro = 9.9;
        rates.elite = 14.9;
      } else if (userPosition >= 4 && userPosition <= 10) {
        rates.lite = 7.35;
        rates.pro = 14.85;
        rates.elite = 22.35;
      } else if (userPosition >= 11 && userPosition <= 50) {
        rates.lite = 9.8;
        rates.pro = 19.8;
        rates.elite = 29.8;
      } else if (userPosition >= 51 && userPosition <= 100) {
        rates.lite = 12.25;
        rates.pro = 24.75;
        rates.elite = 37.25;
      } else if (userPosition >= 101) {
        rates.lite = 14.7;
        rates.pro = 29.7;
        rates.elite = 44.7;
      }

      // Loop through each active card and sum up the commission
      for (let i = 1; i <= activeCards; i++) {
        const cardType = user[`cardNo${i}aiaId`];
        if (cardType === 'lite') {
          commission += rates.lite;
        } else if (cardType === 'pro') {
          commission += rates.pro;
        } else if (cardType === 'elite') {
          commission += rates.elite;
        }
      }

      return {
        fullName: user.fullName 
          ? user.fullName 
          : `${user.firstName || ''} ${user.lastName || ''}`.trim(),
        activeCards: activeCards,
        commission: commission
      };
    });

    res.status(200).json({ success: true, data: referralDetails });
  } catch (error) {
    console.error("Error fetching referral details for referralId:", referralId, error);
    res.status(500).json({ success: false, message: "Internal server error", error: error.message });
  }
});

// New endpoint to fetch referral reward records from the referrals DB
app.get('/referral-rewards', verifyJWT, async (req, res) => {
  const { referralId } = req.query;
  if (!referralId) {
    return res.status(400).json({ success: false, message: "Missing referralId parameter" });
  }
  try {
    const referralDb = client.db(process.env.MONGODB_DB_NAME_REFER);
    const collection = referralDb.collection(process.env.MONGODB_COLLECTION_REFER);
    
    // Query for records with the matching referralId
    const rewards = await collection.find({ referralId }).toArray();
    
    // Sort rewards by createTime descending (most recent first)
    rewards.sort((a, b) => new Date(b.createTime) - new Date(a.createTime));
    
    // Optionally, map to only return the desired fields:
    const mappedRewards = rewards.map(record => ({
      fullName: record.fullName,
      createTime: record.createTime,
      commission: parseFloat(record.commission.toString()),
      rewardStatus: record.rewardStatus
    }));
    
    res.status(200).json({ success: true, data: mappedRewards });
  } catch (error) {
    console.error("Error fetching referral rewards:", error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// Endpoint to update the user's biometrics preference
app.post('/api/update-biometrics', verifyJWT, async (req, res) => {
  const { email, biometricsEnabled } = req.body;
  if (!email || typeof biometricsEnabled !== 'boolean') {
    return res.status(400).json({ error: 'Missing or invalid parameters' });
  }
  try {
    const database = client.db(process.env.MONGODB_DB_NAME);
    const collection = database.collection(process.env.MONGODB_COLLECTION);
    const updateResult = await collection.updateOne({ email }, { $set: { biometricsEnabled } });
    if (updateResult.modifiedCount > 0) {
      res.json({ success: true, biometricsEnabled });
    } else {
      res.status(404).json({ error: 'User not found or update failed' });
    }
  } catch (err) {
    console.error("Error updating biometrics:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Helper: Generate a 6-digit OTP code
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Function to open a card using the WasabiCard API and log orderNo to MongoDB
async function openCard(holderId, email, aiaCardId) {
  if (!holderId) {
    const errorMsg = 'Invalid holderId provided to openCard';
    console.error(errorMsg);
    throw new Error(errorMsg);
  }

  const payload = {
    merchantOrderNo: generateMerchantOrderNo(),
    holderId: holderId,
    cardTypeId: 111016,
    amount: 50,
    aiaCardId: aiaCardId, // Use the passed AIACardId (e.g., 'lite', 'pro', or 'elite')
  };

  try {
    const response = await callWasabiApi('/merchant/core/mcb/card/openCard', payload);

    // Assuming response.data is an array with at least one element containing orderNo
    let orderNo = null;
    if (response && response.data && Array.isArray(response.data) && response.data.length > 0) {
      orderNo = response.data[0].orderNo;
    }
    
    if (orderNo) {
      // Log the orderNo into MongoDB so that the webhook can later lookup the record.
      const database = client.db(process.env.MONGODB_DB_NAME);
      const collection = database.collection(process.env.MONGODB_COLLECTION);

      // First, retrieve the user document using the holderId so we can get activeCards count.
      const user = await collection.findOne({ holderId: holderId });
      const activeCards = user && user.activeCards ? user.activeCards : 0;
      const newCardIndex = activeCards + 1;
      const cardAIAField = `cardNo${newCardIndex}aiaId`; // e.g., cardNo1aiaId

      // Update the user record by lookup using the provided holderId:
      // set the orderNo and the new cardAIAField, and increment activeCards.
      const updateResult = await collection.updateOne(
        { holderId: holderId },
        { $set: { orderNo, [cardAIAField]: aiaCardId }}
      );

      if (updateResult.modifiedCount > 0) {
      } else {
        console.error(`Failed to update user with holderId ${holderId} with orderNo: ${orderNo}`);
      }
    } else {
      console.error('No orderNo found in the Wasabi API response.');
    }

    return response;
  } catch (error) {
    console.error('Error opening card:', error);
    throw error;
  }
}

// Express endpoint to expose openCard functions
app.post('/openCard', async (req, res) => {
  try {
    const { holderId, email, aiaCardId } = req.body;
    const result = await openCard(holderId, email, aiaCardId);
    res.status(200).json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Helper function to send push notifications via FCM
async function sendFCMPushNotification(deviceToken, notificationData) {
  const message = {
    token: deviceToken,
    notification: {
      title: notificationData.title,
      body: notificationData.body,
    },
    data: notificationData.data || {}, // Optional additional data payload
  };

  try {
    const response = await admin.messaging().send(message);
    return response;
  } catch (error) {
    console.error('Error sending FCM message:', error);
    throw error;
  }
}

// Helper function: send push notification using Expo push API
async function sendPushNotification(deviceToken, notificationData) {
  const newNotificationData = {
    ...notificationData,
    body: notificationData.body || notificationData.desc,
  };
  return sendFCMPushNotification(deviceToken, newNotificationData);
}

// Endpoint to trigger FCM push notifications
app.post('/send-notification', async (req, res) => {
  try {
    const { deviceToken, title, body } = req.body;
    if (!deviceToken || !title || !body) {
      return res.status(400).json({ success: false, message: "Missing required fields" });
    }
    await sendPushNotification(deviceToken, { title, body });
    res.json({ success: true, message: "Notification sent" });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error sending notification",
      error: error.message,
    });
  }
});

// Webhook endpoint
app.post('/webhook', express.json({verify: (req, res, buf) => {req.rawBody = buf.toString(); }, }),
  async (req, res) => {
    // Immediately acknowledge the webhook.
    const responsePayload = {
      success: true,
      code: 200,
      msg: 'Success',
      data: null,
    };
    res.status(200).json(responsePayload);

    // Process the webhook asynchronously.
    setImmediate(async () => {
      try {

        // (Signature verification code omitted for brevity)

        // Destructure fields from the webhook payload.
        const { merchantOrderNo, orderNo, status, type, cardNo, amount } = req.body;

        // Process deposit-type webhook updates.
        if (merchantOrderNo && status && type === 'deposit') {
          if (status !== 'success') {
            return;
          }

          // Use environment variable settings or fall back to the default values.
          const dbName = process.env.MONGODB_DB_NAME_TOPUP;
          const collectionName = process.env.MONGODB_COLLECTION_TOPUP;

          // Update the deposit record based solely on the merchantOrderNo.
          const depositDB = client.db(dbName);
          const depositCollection = depositDB.collection(collectionName);
          const updateResult = await depositCollection.updateMany(
            { merchantOrderNo },
            { $set: { status, orderNo, updatedAt: new Date() } }
          );

          if (updateResult.modifiedCount > 0) {

            // Delegate notifications (if applicable).
            const topupPayload = {
              orderNo, // updated orderNo from Wasabi
              merchantOrderNo,
              amount, // amount from webhook payload
              status,
            };
            await processTopupNotification(topupPayload);
          } else {
            console.error(`Failed to update deposit record for merchantOrderNo: ${merchantOrderNo}`);
          }
          return;
        }

        // -----------------------------------------------------
        // Process non-deposit notifications based on header category.
        // -----------------------------------------------------
        const category = req.headers['x-wsb-category'];
        if (category) {
          switch (category) {
            case 'card_transaction':
              processCardTransaction(req.body).catch((err) =>
                console.error('Error processing card_transaction:', err)
              );
              break;
            case 'card_auth_transaction':
              processCardAuthTransaction(req.body).catch((err) =>
                console.error('Error processing card_auth_transaction:', err)
              );
              break;
            case 'card_fee_patch':
              processCardFeePatch(req.body).catch((err) =>
                console.error('Error processing card_fee_patch:', err)
              );
              break;
            default:
              console.warn('Unhandled notification category:', category);
          }
          return; // Exit after handling category notifications.
        }

        // -----------------------------------------------------
        // Fallback Processing for Card Activation (or similar) webhooks.
        // -----------------------------------------------------
        if (!orderNo || !cardNo) {
          console.error('Missing orderNo or cardNo in webhook payload.');
          return;
        }
        if (type !== 'create') {
          return;
        }

        // For fallback card activation updates.
        const database = client.db(process.env.MONGODB_DB_NAME);
        const collection = database.collection(process.env.MONGODB_COLLECTION);
        const user = await collection.findOne({ orderNo });
        if (!user) {
          console.error(`No user found with orderNo: ${orderNo}`);
          return;
        }
        const activeCards = user.activeCards || 0;
        const newCardIndex = activeCards + 1;
        const cardFieldName = `cardNo${newCardIndex}`;

        const updateResult2 = await collection.updateOne(
          { _id: user._id },
          {
            $set: { [cardFieldName]: cardNo, orderNo: '' },
            $inc: { activeCards: 1 },
          }
        );

        if (updateResult2.modifiedCount > 0) {
          await handleReferralReward(user, cardNo);
        } else {
          console.error('Failed to update user record with new card information.');
        }
      } catch (err) {
        console.error('Error processing webhook:', err);
      }
    });
  }
);

// Endpoint to fetch paginated topup records from MongoDB
app.post('/get-topups', verifyJWT, async (req, res) => {
  try {
    const { pageNum = 1, pageSize = 15, cardNo, startTime, endTime } = req.body;

    // Validate required parameters
    if (!cardNo) {
      return res.status(400).json({ success: false, message: "cardNo is required" });
    }

    // Build the query object.
    // Note: Filtering on startTime/endTime may work properly only if the provided values are numeric.
    const query = { cardNo };
    if (startTime && endTime) {
      query.transactionTime = {
        $gte: Number(startTime),
        $lte: Number(endTime)
      };
    }

    const db = client.db(process.env.MONGODB_DB_NAME_TOPUP);
    const collection = db.collection(process.env.MONGODB_COLLECTION_TOPUP);

    // Fetch all matching records
    const allRecords = await collection.find(query).toArray();

    // Helper function: Convert transactionTime (which might be a number or a formatted string)
    function convertTransactionTime(val) {
      if (typeof val === 'number') {
        return val;
      } else if (typeof val === 'string') {
        // Expecting format "DD-MM-YYYY, HH:mm:ss"
        const parts = val.split(',');
        if (parts.length < 2) return 0;
        const datePart = parts[0].trim();  // e.g., "08-04-2025"
        const timePart = parts[1].trim();  // e.g., "02:17:02"
        const dateComponents = datePart.split('-'); // [DD, MM, YYYY]
        const timeComponents = timePart.split(':'); // [HH, MM, SS]
        if (dateComponents.length < 3 || timeComponents.length < 3) return 0;
        const day = parseInt(dateComponents[0], 10);
        const month = parseInt(dateComponents[1], 10) - 1; // JavaScript months are 0-indexed.
        const year = parseInt(dateComponents[2], 10);
        const hours = parseInt(timeComponents[0], 10);
        const minutes = parseInt(timeComponents[1], 10);
        const seconds = parseInt(timeComponents[2], 10);
        return new Date(year, month, day, hours, minutes, seconds).getTime();
      }
      return 0;
    }

    // Sort the records by normalized transactionTime in descending order (newest first)
    allRecords.sort((a, b) => convertTransactionTime(b.transactionTime) - convertTransactionTime(a.transactionTime));

    // Get total count and perform pagination manually.
    const total = allRecords.length;
    const startIndex = (pageNum - 1) * Number(pageSize);
    const paginatedRecords = allRecords.slice(startIndex, startIndex + Number(pageSize));

    return res.json({ success: true, data: { total, records: paginatedRecords } });
  } catch (error) {
    console.error("Error fetching topups:", error);
    return res.status(500).json({ success: false, message: error.message });
  }
});

// Updated helper function for calling the card-details endpoint
async function callCardDetailsEndpoint(email, cardNo) {
  try {
    const response = await fetch('process.env.AIA_RENDER_SERVER_URL/card-details', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, cardNo }),
    });
    return await response.json();
  } catch (error) {
    console.error("Error calling card-details endpoint:", error);
    throw error;
  }
}

// Updated processCardTransaction function using the card-details endpoint
async function processCardTransaction(payload) {
  const { orderNo, merchantOrderNo, cardNo, type, status } = payload;

  // Validate required fields based on transaction type.
  if (type === 'create') {
    if (!orderNo || !cardNo) {
      console.error('Missing orderNo or cardNo in card creation payload.');
      return;
    }
  } else if (type === 'deposit') {
    if (!merchantOrderNo || !cardNo) {
      console.error('Missing merchantOrderNo or cardNo in deposit payload.');
      return;
    }
  } else {
    return;
  }

  try {
    const database = client.db(process.env.MONGODB_DB_NAME);
    const collection = database.collection(process.env.MONGODB_COLLECTION);
    let user = null;

    // Use different user lookup depending on the transaction type.
    if (type === 'create') {
      user = await collection.findOne({ orderNo });
      if (!user) {
        console.error(`No user found with orderNo: ${orderNo}`);
        return;
      }
    } else if (type === 'deposit') {
      user = await collection.findOne({ merchantOrderNo });
      if (!user) {
        console.error(`No user found with merchantOrderNo: ${merchantOrderNo}`);
        return;
      }
    }

    // Process transaction based on type.
    if (type === 'create') {
      // Update the user's record for card creation.
      const activeCards = user.activeCards || 0;
      const newCardIndex = activeCards + 1;
      const cardFieldName = `cardNo${newCardIndex}`;

      // Update: clear orderNo but keep merchantOrderNo for deposit updates.
      const updateResult = await collection.updateOne(
        { _id: user._id },
        {
          $set: { [cardFieldName]: cardNo, orderNo: "" },
          $inc: { activeCards: 1 },
        }
      );

      if (updateResult.modifiedCount > 0) {
        
        // Retrieve full card details via the card-details endpoint.
        let maskedCardNumber = "**** " + cardNo.slice(-4);
        if (user.email) {
          try {
            const cardDetailsResponse = await callCardDetailsEndpoint(user.email, cardNo);
            if (cardDetailsResponse.success && cardDetailsResponse.data) {
              const fullCardNumber = cardDetailsResponse.data.cardNumber;
              if (fullCardNumber && fullCardNumber.length >= 4) {
                maskedCardNumber = "**** " + fullCardNumber.slice(-4);
              }
            } else {
              console.warn("Card-details endpoint did not return success; using fallback masked card number.");
            }
          } catch (err) {
            console.error("Error retrieving card details via endpoint:", err);
          }
        } else {
          console.warn("User email not available for calling card-details endpoint; using fallback masked card number.");
        }

        const notificationData = {
          title: "Card Activation",
          desc: `Your new card ending ${maskedCardNumber} has been successfully created and activated. Happy spending!`,
          notifyTime: new Date(),
          userNotify: user.holderId
        };

        // Insert the notification into the notifications collection first.
        await insertNotification(notificationData);

        // Then send push notifications using available tokens.
        if (user.fcmToken || user.expoPushToken) {
          await sendPushNotification(user.fcmToken || user.expoPushToken, notificationData);
        } else {
          let tokensSent = false;
          if (user.fcmTokens && Array.isArray(user.fcmTokens) && user.fcmTokens.length > 0) {
            for (const token of user.fcmTokens) {
              await sendPushNotification(token, notificationData);
            }
            tokensSent = true;
          }
          if (!tokensSent && user.expoPushToken) {
            await sendPushNotification(user.expoPushToken, notificationData);
            tokensSent = true;
          }
          if (!tokensSent) {
            console.warn(`No push token found for user ${user.email}`);
          }
        }
      } else {
        console.error('(Notification) Failed to update user record for card creation.');
      }
    } else if (type === 'deposit') {
      // Update deposit-related fields for the user record and clear merchantOrderNo after updating.
      const updateResult = await collection.updateOne(
        { _id: user._id },
        {
          $set: { depositStatus: status, merchantOrderNo: "" },
        }
      );


      if (updateResult.modifiedCount > 0) {
        const notificationData = {
          title: "Deposit Update",
          desc: `Your deposit for merchant order ${merchantOrderNo} has been updated successfully.`,
          notifyTime: new Date(),
          userNotify: user.holderId
        };

        // Insert the deposit notification into the notifications collection first.
        await insertNotification(notificationData);

        // Then send push notifications.
        if (user.fcmToken || user.expoPushToken) {
          await sendPushNotification(user.fcmToken || user.expoPushToken, notificationData);
        } else {
          console.warn(`No push token found for user ${user.email} during deposit update.`);
        }
      } else {
        console.error(`Failed to update deposit record for merchantOrderNo: ${merchantOrderNo}`);
      }
    }
  } catch (error) {
    console.error('Error processing card transaction notification:', error);
  }
}

// Helper function to insert a notification document into the notifications collection.
async function insertNotification(notificationData) {
  try {
    const notificationsDb = client.db(process.env.MONGODB_DB_NAME_NOTIFY);
    const notificationsCollection = notificationsDb.collection(process.env.MONGODB_COLLECTION_NOTIFY);
    const result = await notificationsCollection.insertOne(notificationData);
  } catch (error) {
    console.error("Error inserting notification:", error);
    throw error;
  }
}

// Helper function to process Card Authorization Transaction notifications
async function processCardAuthTransaction(payload) {
  const { cardNo, merchantName, amount, holderId } = payload;
  if (!cardNo || !merchantName || amount == null) {
    console.error('Missing cardNo, merchantName, or amount in card auth transaction payload.');
    return;
  }
  
  try {
    // Insert the transaction payload into the cardAuthTransactions collection.
    const database = client.db(process.env.MONGODB_DB_NAME);
    const collection = database.collection("cardAuthTransactions");
    await collection.insertOne(payload);
    
    // Look up the user using holderId.
    const usersDb = client.db(process.env.MONGODB_DB_NAME);
    const usersCollection = usersDb.collection(process.env.MONGODB_COLLECTION);
    const user = await usersCollection.findOne({ holderId });
    if (!user) {
      console.error(`No user found for holderId: ${holderId}`);
      return;
    }
    
    // Retrieve the card details by calling your card-details endpoint.
    let maskedCardNumber = "**** " + cardNumber.slice(-4);
    if (user.email) {
      try {
        const cardDetailsResponse = await callCardDetailsEndpoint(user.email, cardNumber);
        if (cardDetailsResponse.success && cardDetailsResponse.data) {
          const fullCardNumber = cardDetailsResponse.data.cardNumber;
          if (fullCardNumber && fullCardNumber.length >= 4) {
            maskedCardNumber = "**** " + fullCardNumber.slice(-4);
          }
        } else {
          console.warn("Card-details endpoint did not return success; using fallback masked card number.");
        }
      } catch (err) {
        console.error("Error retrieving card details via endpoint:", err);
      }
    } else {
      console.warn("User email not available for calling card-details endpoint; using fallback masked card number.");
    }
    
    // Build the notification payload.
    const notificationData = {
      title: "Transaction",
      desc: `Authorization transaction for ${amount} from card ending ${maskedCardNumber} has been processed at ${merchantName}.`,
      notifyTime: new Date(),
      userNotify: holderId || "All"
    };
    
    // Insert the notification into the notifications collection.
    await insertNotification(notificationData);
    
    // Send push notifications using the user's push tokens.
    if (holderId) {
      if (user.fcmToken || user.expoPushToken) {
        await sendPushNotification(user.fcmToken || user.expoPushToken, notificationData);
      } else {
        console.warn(`No push token found for holderId ${holderId}`);
      }
    } else {
    }
    
  } catch (error) {
    console.error('Error processing card auth transaction notification:', error);
  }
}

// Helper function to process Card Authorization Reversal Transaction notifications
async function processCardFeePatch(payload) {
  const { cardNo, tradeNo, originTradeNo, currency, amount, holderId } = payload;
  if (!cardNo || !tradeNo || !originTradeNo || !currency || amount == null) {
    console.error('Missing required fields in card fee patch payload.');
    return;
  }
  
  try {
    const database = client.db(process.env.MONGODB_DB_NAME);
    const collection = database.collection("cardFeePatchTransactions");
    await collection.insertOne(payload);
    
    // Look up the user using holderId
    const usersDb = client.db(process.env.MONGODB_DB_NAME);
    const usersCollection = usersDb.collection(process.env.MONGODB_COLLECTION);
    const user = await usersCollection.findOne({ holderId });
    
    // Set a fallback for maskedCardNumber using the provided cardNumber.
    let maskedCardNumber = cardNumber ? "**** " + cardNumber.slice(-4) : "N/A";
    
    // If the user's email is available, call the card-details endpoint.
    if (user && user.email && cardNumber) {
      try {
        const cardDetailsResponse = await callCardDetailsEndpoint(user.email, cardNumber);
        if (cardDetailsResponse.success && cardDetailsResponse.data) {
          const fullCardNumber = cardDetailsResponse.data.cardNumber;
          if (fullCardNumber && fullCardNumber.length >= 4) {
            maskedCardNumber = "**** " + fullCardNumber.slice(-4);
          }
        } else {
          console.warn("Card-details endpoint did not return success; using fallback masked card number.");
        }
      } catch (err) {
        console.error("Error retrieving card details via endpoint:", err);
      }
    } else {
      console.warn("User email not available; using fallback masked card number.");
    }
    
    const notificationData = {
      title: "Transaction Reversal",
      desc: `Reversal processed for ${currency} ${amount} for card ending ${maskedCardNumber}.`,
      notifyTime: new Date(),
      userNotify: holderId || "All"
    };

    await insertNotification(notificationData);

    // Send push notifications using the user's tokens.
    if (holderId) {
      if (user && (user.fcmToken || user.expoPushToken)) {
        await sendPushNotification(user.fcmToken || user.expoPushToken, notificationData);
      } else {
        console.warn(`No push token found for holderId ${holderId}`);
      }
    } else {
    }
    
  } catch (error) {
    console.error('Error processing card fee patch notification:', error);
  }
}

// Helper function to process Topup (Deposit) notifications
// Updated helper function to process Topup (Deposit) notifications
async function callCardDetailsEndpoint(email, cardNo) {
  try {
    // Adjust this function using your preferred HTTP client (e.g., fetch, axios)
    const response = await fetch('process.env.AIA_RENDER_SERVER_URL/card-details', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, cardNo }),
    });
    return await response.json();
  } catch (error) {
    console.error("Error calling card-details endpoint:", error);
    throw error;
  }
}

async function processTopupNotification(payload) {
  const { orderNo, merchantOrderNo, amount, status } = payload;

  if (!orderNo || !merchantOrderNo) {
    console.error("Missing orderNo or merchantOrderNo in topup payload.");
    return;
  }

  if (status !== "success") {
    return;
  }

  try {
    // Look up the deposit record from the topup database/collection.
    const depositRecord = await client
      .db(process.env.MONGODB_DB_NAME_TOPUP)
      .collection(process.env.MONGODB_COLLECTION_TOPUP)
      .findOne({ merchantOrderNo });

    if (!depositRecord) {
      console.error(`No deposit record found for merchantOrderNo: ${merchantOrderNo}`);
      return;
    }

    const lookupHolderId = depositRecord.holderId;
    if (!lookupHolderId) {
      console.error(`Deposit record for merchantOrderNo: ${merchantOrderNo} is missing holderId.`);
      return;
    }

    // Look up the user from your main user collection.
    const database = client.db(process.env.MONGODB_DB_NAME);
    const usersCollection = database.collection(process.env.MONGODB_COLLECTION);
    const user = await usersCollection.findOne({ holderId: lookupHolderId });
    
    if (!user) {
      console.error(`No user found for holderId: ${lookupHolderId}`);
      return;
    }

    // Instead of fetching card details directly from the database,
    // call your existing /card-details endpoint.
    let maskedCardNumber = "N/A";
    if (user.email) {
      // Call the endpoint using the email and, if available, the card number from deposit or user.
      const effectiveCardNo = depositRecord.cardNo || user.cardNumber;
      try {
        const cardDetailsResponse = await callCardDetailsEndpoint(user.email, effectiveCardNo);
        if (cardDetailsResponse.success && cardDetailsResponse.data) {
          maskedCardNumber = cardDetailsResponse.data.maskedCardNumber || maskedCardNumber;
        } else {
          console.warn("Card-details endpoint did not return success; using fallback masked card number.");
          if (user.cardNumber) {
            maskedCardNumber = "**** " + user.cardNumber.slice(-4);
          }
        }
      } catch (err) {
        console.error("Error retrieving card details via endpoint:", err);
        if (user.cardNumber) {
          maskedCardNumber = "**** " + user.cardNumber.slice(-4);
        }
      }
    } else {
      console.warn("User email not available for calling card-details endpoint; using fallback masked card number.");
      if (user.cardNumber) {
        maskedCardNumber = "**** " + user.cardNumber.slice(-4);
      }
    }

    // Build the notification payload.
    const notificationData = {
      title: "Topup Successful",
      desc: `Your topup of $${amount} for card ending ${maskedCardNumber} has been successfully completed.`,
      notifyTime: new Date(),
      userNotify: lookupHolderId,
    };

    // Insert the notification into the notifications collection.
    await insertNotification(notificationData);

    // Send push notifications using the user's push tokens.
    let tokensSent = false;
    if (user.fcmTokens && Array.isArray(user.fcmTokens) && user.fcmTokens.length > 0) {
      for (const token of user.fcmTokens) {
        await sendPushNotification(token, notificationData);
      }
      tokensSent = true;
    }
    if (!tokensSent && user.expoPushToken) {
      await sendPushNotification(user.expoPushToken, notificationData);
      tokensSent = true;
    }
    if (!tokensSent) {
      console.warn(`No push token found for user ${user.email}`);
    }

    // Optionally, send an email notification.
    if (user.email) {
      const emailSubject = "Topup Successful";
      const emailBody = `Your topup of $${amount} for card ending ${maskedCardNumber} has been successfully completed.`;
      await sendTopupEmail(user.email, emailSubject, emailBody);
    } else {
      console.warn("User email not provided; skipping email notification.");
    }
  } catch (error) {
    console.error("Error processing topup notification:", error);
  }
}

// New endpoint to fetch notifications from the dedicated notifications database/collection
app.get('/notifications', async (req, res) => {
  try {
    const database = client.db(process.env.MONGODB_DB_NAME_NOTIFY);
    const collection = database.collection(process.env.MONGODB_COLLECTION_NOTIFY);

    // Optional filtering: if a "user" query parameter is provided,
    // return notifications where userNotify is either the given holderId or "All".
    let query = {};
    if (req.query.user) {
      const userNotify = req.query.user;
      query = { userNotify: { $in: [userNotify, "All"] } };
    }

    // Retrieve all notifications sorted by notifyTime descending
    const notifications = await collection.find(query).sort({ notifyTime: -1 }).toArray();
    res.status(200).json({ success: true, notifications });
  } catch (error) {
    console.error("Error fetching notifications:", error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// Endpoint to save the FCM token for a user.
// The token is stored in the "fcmTokens" array field in the user's document.
app.post('/api/save-token', async (req, res) => {
  const { email, token } = req.body;
  if (!email || !token) {
    return res.status(400).json({ success: false, message: "Email and token are required." });
  }
  try {
    const database = client.db(process.env.MONGODB_DB_NAME);
    const collection = database.collection(process.env.MONGODB_COLLECTION);

    // Use $addToSet so that the token is added only if it's not already in the array.
    const updateResult = await collection.updateOne(
      { email },
      { $addToSet: { fcmTokens: token } }
    );

    // Optionally, you can log updateResult to verify changes.

    res.json({ success: true, message: "Token saved successfully." });
  } catch (error) {
    console.error("Error saving FCM token:", error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// A helper function to decrypt a base64-encoded field from Wasabi using your RSA private key.
function decryptRSA(encryptedBase64, privateKey) {
  if (!encryptedBase64) return null;
  try {
    const buffer = Buffer.from(encryptedBase64, 'base64');
    // Use the appropriate padding based on your encryption method.
    const decryptedBuffer = crypto.privateDecrypt(
      {
        key: privateKey,
        // If your encryption uses PKCS1 padding and you're on a newer Node version, you might need:
        // padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        // Or run Node with the --openssl-legacy-provider flag and uncomment the line below:
        padding: crypto.constants.RSA_PKCS1_PADDING,
        // padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      },
      buffer
    );
    return decryptedBuffer.toString('utf8');
  } catch (err) {
    console.error('Decryption failed:', err);
    return null;
  }
}

// Endpoint to pull card authorization transactions from Wasabi API
app.post('/card-auth-transactions', async (req, res) => {
  try {
    const { pageNum, pageSize, cardNo, type, tradeNo, startTime, endTime } = req.body;
    const payload = {
      pageNum: pageNum || 1,
      pageSize: pageSize || 10,
      ...(cardNo && { cardNo }),
      ...(type && { type }),
      ...(tradeNo && { tradeNo }),
      ...(startTime && { startTime }),
      ...(endTime && { endTime }),
    };

    const response = await callWasabiApi('/merchant/core/mcb/card/authTransaction', payload);
    res.status(200).json(response);
  } catch (error) {
    console.error('Error fetching card auth transactions:', error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// Endpoint to get active cards details for a user based on email
app.post('/get-active-cards', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ success: false, message: "Email is required" });
    }
    
    const database = client.db(process.env.MONGODB_DB_NAME);
    const collection = database.collection(process.env.MONGODB_COLLECTION);
    
    // Lookup user document by email
    const user = await collection.findOne({ email });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }
    
    const activeCardsCount = user.activeCards || 0;
    const cardDetailsArray = [];

    for (let i = 1; i <= activeCardsCount; i++) {
      const cardNoField = `cardNo${i}`;
      const cardTypeField = `cardNo${i}aiaId`;
      
      const cardNo = user[cardNoField];
      const aiaCardId = user[cardTypeField];  // e.g. 'lite', 'pro', or 'elite'
      if (!cardNo) continue;
      
      // Prepare payload for the Wasabi Card Info API call
      const payload = {
        cardNo: cardNo,
        onlySimpleInfo: false,
      };
      
      // Call Wasabi's API using your helper function
      const response = await callWasabiApi('/merchant/core/mcb/card/info', payload);
      
      if (response && response.success && response.data) {
        const data = response.data;
        
        // Decrypt the validPeriod (expiry) using the Java microservice.
        const rawValidPeriod = data.validPeriod; // Encrypted expiry
        const expiry = await decryptUsingMicroservice(rawValidPeriod) || 'N/A';
        
        // For cardNumber, do not attempt decryption—simply mask the last four digits.
        const rawCardNumber = data.cardNumber;
        let maskedCardNumber = "";
        if (rawCardNumber && rawCardNumber.length >= 4) {
          maskedCardNumber = "**** " + rawCardNumber.slice(-4);
        }
        
        // Decrypt CVV if provided.
        let decryptedCvv = null;
        if (data.cvv) {
          decryptedCvv = await decryptUsingMicroservice(data.cvv);
        }
        
        const balance = data.balanceInfo?.amount || null;
        
        const cardDetail = {
          aiaCardId,             // e.g., 'lite', 'pro', or 'elite'
          cardNo: data.cardNo,     // Bank Card ID from Wasabi
          maskedCardNumber,       // Now simply "**** " + last 4 digits
          expiry,                 // Decrypted expiry or "N/A"
          balance,                // Card balance
          cvv: decryptedCvv,      // Decrypted CVV, if available
          status: data.status,
          statusStr: data.statusStr,
          bindTime: data.bindTime,
          remark: data.remark,
        };
        
        cardDetailsArray.push(cardDetail);
      } else {
        console.error(`Failed to retrieve card info for cardNo: ${cardNo}`);
      }
    }
    
    return res.status(200).json({ success: true, data: cardDetailsArray });
  } catch (error) {
    console.error("Error in /get-active-cards:", error);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

// New Topup/Deposit Endpoint
app.post('/top-up', verifyJWT, verifyHMAC, async (req, res) => {
  const { cardNo, merchantOrderNo, amount, holderId, chosenCrypto } = req.body;

  if (!cardNo || !merchantOrderNo || !amount) {
    console.error("Validation error: Missing required fields", req.body);
    return res.status(400).json({
      success: false,
      message: 'Missing required fields: cardNo, merchantOrderNo, and amount are required.'
    });
  }

  const depositPayload = {
    cardNo,
    merchantOrderNo,
    amount,
    currency: "USD", // Adjust as necessary.
    holderId  // Optional field.
  };

  try {
    const data = await callWasabiApi('/merchant/core/mcb/card/deposit', depositPayload);

    if (data.success && data.data && data.data.status === 'processing') {
      // Store the original transaction time (as returned by Wasabi)
      const originalTransactionTime = data.data.transactionTime;

      // Build the topup record without converting the transaction time.
      const topupRecord = {
        merchantOrderNo,
        cardNo,
        amount,
        orderNo: data.data.orderNo,
        status: data.data.status,
        remark: data.data.remark,
        transactionTime: originalTransactionTime, // Save as-is.
        details: data.data,
        chosenCrypto,  // Includes details like name, network, display.
        createdAt: new Date(),
        holderId
      };

      const dbName = process.env.MONGODB_DB_NAME_TOPUP;
      const collectionName = process.env.MONGODB_COLLECTION_TOPUP;
      const insertResult = await client.db(dbName).collection(collectionName).insertOne(topupRecord);

      return res.status(200).json({ success: true, data });
    } else {
      console.error('Deposit API did not return processing status. Data:', data.data);
      return res.status(400).json({
        success: false,
        message: 'Deposit API call did not return a processing status.',
        data: data.data
      });
    }
  } catch (error) {
    console.error('Error in /top-up endpoint:', error);
    return res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Freeze endpoint with dynamic Wasabi API call
app.post('/merchant/core/mcb/card/freeze', async (req, res) => {
  const { cardNo, maskedCardNumber } = req.body;

  if (!cardNo) {
    const errorResponse = {
      success: false,
      code: 400,
      msg: "Missing cardNo parameter"
    };
    console.error("Freeze endpoint error:", errorResponse);
    return res.status(400).json(errorResponse);
  }

  // Create the payload for Wasabi API
  const payload = { cardNo, maskedCardNumber };

  try {
    // Call the Wasabi Pay API endpoint for freezing the card
    const freezeResponse = await callWasabiApi('/merchant/core/mcb/card/freeze', payload);
    res.json(freezeResponse);
  } catch (error) {
    console.error("Error freezing card:", error);
    res.status(500).json({ success: false, code: 500, msg: "Internal Server Error" });
  }
});

// Unfreeze endpoint with dynamic Wasabi API call
app.post('/merchant/core/mcb/card/unfreeze', async (req, res) => {
  const { cardNo, maskedCardNumber } = req.body;

  if (!cardNo) {
    const errorResponse = {
      success: false,
      code: 400,
      msg: "Missing cardNo parameter"
    };
    console.error("Unfreeze endpoint error:", errorResponse);
    return res.status(400).json(errorResponse);
  }

  // Create the payload for Wasabi API
  const payload = { cardNo, maskedCardNumber };

  try {
    // Call the Wasabi Pay API endpoint for unfreezing the card
    const unfreezeResponse = await callWasabiApi('/merchant/core/mcb/card/unfreeze', payload);
    res.json(unfreezeResponse);
  } catch (error) {
    console.error("Error unfreezing card:", error);
    res.status(500).json({ success: false, code: 500, msg: "Internal Server Error" });
  }
});

// Nodemailer Configuration
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
  tls: { ciphers: 'SSLv3' }
});

// Registration Endpoint
app.post('/register', async (req, res) => {
  try {
    const { email, password, ...userData } = req.body;
    const database = client.db(process.env.MONGODB_DB_NAME);
    const collection = database.collection(process.env.MONGODB_COLLECTION);

    // Check if the email is already registered
    const existingUser = await collection.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ success: false, message: "Email already registered. Please log in." });
    }

    const hashedPassword = await bcryptjs.hash(password, 10);
    const otp = generateOTP();
    const otpExpiry = new Date();
    otpExpiry.setMinutes(otpExpiry.getMinutes() + 10);

    // Helper function to trim the trailing space if present
    const trimTrailingSpace = (str) => {
      if (typeof str === 'string' && str.endsWith(' ')) {
        return str.slice(0, -1);
      }
      return str;
    };

    // List of fields to check and trim if the last character is a space
    const fieldsToTrim = ['firstName', 'lastName', 'email', 'mobile', 'address', 'postCode', 'referralId'];
    fieldsToTrim.forEach(field => {
      if (userData[field]) {
        userData[field] = trimTrailingSpace(userData[field]);
      }
    });

    // Insert the user data with the trimmed fields
    await collection.insertOne({
      ...userData,
      email, // Ensuring email is also passed as a top-level field
      password: hashedPassword,
      otp,
      otpExpiry,
      otpVerified: false,
      isGAVerified: false,
      activeCards: 0
    });

    console.log(`📩 Generated OTP for ${email}: ${otp}`);

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Your OTP Code",
      text: `Your OTP code is: ${otp}. It is valid for 10 minutes.`
    });

    res.status(200).json({ success: true, message: "OTP sent for verification." });
  } catch (error) {
    console.error("❌ Error during registration:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// OTP Verification for Registration
app.post('/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    const database = client.db(process.env.MONGODB_DB_NAME);
    const collection = database.collection(process.env.MONGODB_COLLECTION);

    const user = await collection.findOne({ email });
    if (!user) return res.status(404).json({ success: false, message: "User not found." });

    if (user.otp !== otp || new Date(user.otpExpiry) < new Date()) {
      return res.status(400).json({ success: false, message: "Invalid or expired OTP. Please try again." });
    }

    await collection.updateOne(
      { email },
      { $set: { otpVerified: true }, $unset: { otp: "", otpExpiry: "" } }
    );

    const token = jwt.sign({ id: user._id, email: user.email }, secretKey, { expiresIn: '1h' });

    res.status(200).json({
      success: true,
      token,
      user: {
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        photo: user.photo,         
        birthday: user.birthday,
        address: user.address,
        town: user.town,
        postCode: user.postCode,
        country: user.country,
        referralId: user.referralId,
        holderId: user.holderId,
        isGAVerified: false, // explicitly include GA flag
      }
    });
  } catch (error) {
    console.error("❌ Error verifying OTP:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// New endpoint for token-based biometric auto-login (refresh token endpoint)
app.post('/refresh-token', async (req, res) => {
  const { email, refreshToken } = req.body;
  if (!email || !refreshToken) {
    return res.status(400).json({ success: false, message: "Email and refresh token are required." });
  }
  try {
    // Verify the refresh token using the refresh secret (fallback to secretKey if not set)
    let decoded;
    try {
      decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET || secretKey);
    } catch (err) {
      return res.status(401).json({ success: false, message: "Invalid refresh token." });
    }
    if (decoded.email !== email) {
      return res.status(401).json({ success: false, message: "Refresh token does not match the provided email." });
    }
    // Optionally, you could check against a stored refresh token in your database if needed.

    // Generate a new access token
    const newAccessToken = jwt.sign(
      { email },
      process.env.JWT_SECRET || secretKey,
      { expiresIn: '1h' }
    );
    return res.status(200).json({ success: true, accessToken: newAccessToken });
  } catch (error) {
    console.error("Error in /refresh-token:", error);
    return res.status(500).json({ success: false, message: "Server error", error: error.message });
  }
});

// Login & OTP Send Endpoint
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const database = client.db(process.env.MONGODB_DB_NAME);
    const collection = database.collection(process.env.MONGODB_COLLECTION);

    const user = await collection.findOne({ email });
    if (!user) {
      return res.status(401).json({ success: false, message: "Invalid username or password." });
    }

    if (!user.password) {
      return res.status(500).json({ success: false, message: "User password is missing from the database." });
    }

    if (!(await bcryptjs.compare(password, user.password))) {
      return res.status(401).json({ success: false, message: "Invalid username or password." });
    }

    // Generate tokens
    const accessToken = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET || secretKey,
      { expiresIn: '1h' }
    );
    const refreshToken = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_REFRESH_SECRET || secretKey,
      { expiresIn: '7d' }
    );

    // Generate OTP for additional login verification
    const otp = generateOTP();
    const otpExpiry = new Date(Date.now() + 10 * 60000);
    console.log(`🔑 Generated Login OTP for ${email}: ${otp}`);

    await collection.updateOne({ email }, { $set: { otp, otpExpiry } });

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Your Login OTP Code",
      text: `Your OTP code for login is: ${otp}. It is valid for 10 minutes.`
    });

    return res.status(200).json({
      success: true,
      requiresOTP: true,
      message: "OTP sent for login verification.",
      accessToken,           // Newly generated access token
      refreshToken,          // Newly generated refresh token
      user: {
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        photo: user.photo,
        birthday: user.birthday,
        address: user.address,
        town: user.town,
        postCode: user.postCode,
        country: user.country,
        referralId: user.referralId,
        holderId: user.holderId,
        isGAVerified: user.isGAVerified,  // This field will be true if the user is GA verified
        yourReferralId: user.yourReferralId,
      }
    });
  } catch (error) {
    console.error("❌ Error during login:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Biometric Login & OTP Send Endpoint
app.post('/biometric-login', async (req, res) => {
  const { email, refreshToken } = req.body;
  if (!email || !refreshToken) {
    return res.status(400).json({ success: false, message: "Email and refresh token are required." });
  }
  try {
    // Verify the refresh token
    let decoded;
    try {
      decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET || secretKey);
    } catch (err) {
      return res.status(401).json({ success: false, message: "Invalid refresh token." });
    }
    if (decoded.email !== email) {
      return res.status(401).json({ success: false, message: "Refresh token does not match the provided email." });
    }
    // Fetch user data from your database
    const database = client.db(process.env.MONGODB_DB_NAME);
    const collection = database.collection(process.env.MONGODB_COLLECTION);
    const user = await collection.findOne({ email });
    if (!user) {
      return res.status(401).json({ success: false, message: "Invalid user." });
    }
    // Generate new tokens if needed
    const accessToken = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET || secretKey,
      { expiresIn: '1h' }
    );
    const newRefreshToken = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_REFRESH_SECRET || secretKey,
      { expiresIn: '7d' }
    );
    // Generate OTP for login verification
    const otp = generateOTP();
    const otpExpiry = new Date(Date.now() + 10 * 60000);
    console.log(`🔑 Generated Biometric Login OTP for ${email}: ${otp}`);
    await collection.updateOne({ email }, { $set: { otp, otpExpiry } });
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Your Login OTP Code",
      text: `Your OTP code for login is: ${otp}. It is valid for 10 minutes.`
    });
    return res.status(200).json({
      success: true,
      requiresOTP: true,
      message: "OTP sent for biometric login verification.",
      accessToken,
      refreshToken: newRefreshToken,
      user: {
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        photo: user.photo,
        birthday: user.birthday,
        address: user.address,
        town: user.town,
        postCode: user.postCode,
        country: user.country,
        referralId: user.referralId,
        holderId: user.holderId,
        isGAVerified: user.isGAVerified,
        yourReferralId: user.yourReferralId,
      }
    });
  } catch (error) {
    console.error("Error in /biometric-login:", error);
    return res.status(500).json({ success: false, message: "Server error", error: error.message });
  }
});

// Resend OTP for Login
app.post('/resend-login-otp', async (req, res) => {
  try {
    const { email } = req.body;
    const database = client.db(process.env.MONGODB_DB_NAME);
    const collection = database.collection(process.env.MONGODB_COLLECTION);

    const user = await collection.findOne({ email });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found." });
    }

    const otp = generateOTP();
    const otpExpiry = new Date(Date.now() + 10 * 60000);
    console.log(`🔑 Resent Login OTP for ${email}: ${otp}`);

    await collection.updateOne({ email }, { $set: { otp, otpExpiry } });
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Your Login OTP Code",
      text: `Your OTP code for login is: ${otp}. It is valid for 10 minutes.`
    });

    res.status(200).json({ success: true, message: "OTP resent for login verification." });
  } catch (error) {
    console.error("❌ Error resending login OTP:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Resend OTP for Registration
app.post('/resend-register-otp', async (req, res) => {
  try {
    const { email } = req.body;
    const database = client.db(process.env.MONGODB_DB_NAME);
    const collection = database.collection(process.env.MONGODB_COLLECTION);

    const user = await collection.findOne({ email });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found." });
    }

    const otp = generateOTP();
    const otpExpiry = new Date();
    otpExpiry.setMinutes(otpExpiry.getMinutes() + 10);
    console.log(`📩 Resent Register OTP for ${email}: ${otp}`);

    await collection.updateOne({ email }, { $set: { otp, otpExpiry } });
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Your OTP Code",
      text: `Your OTP code is: ${otp}. It is valid for 10 minutes.`
    });

    res.status(200).json({ success: true, message: "OTP resent for registration verification." });
  } catch (error) {
    console.error("❌ Error resending register OTP:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// OTP Verification for Login
app.post('/verify-login-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    const database = client.db(process.env.MONGODB_DB_NAME);
    const collection = database.collection(process.env.MONGODB_COLLECTION);

    const user = await collection.findOne({ email });
    if (!user || user.otp !== otp || new Date(user.otpExpiry) < new Date()) {
      return res.status(400).json({ success: false, message: "Invalid or expired OTP. Please try again." });
    }

    await collection.updateOne({ email }, { $unset: { otp: "", otpExpiry: "" } });

    const token = jwt.sign({ id: user._id, email: user.email }, secretKey, { expiresIn: '1h' });

    res.status(200).json({
      success: true,
      token,
      user: {
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        photo: user.photo,
        birthday: user.birthday,
        address: user.address,
        town: user.town,
        postCode: user.postCode,
        country: user.country,
        referralId: user.referralId,
        yourReferralId: user.yourReferralId,
        holderId: user.holderId,
        isGAVerified: user.isGAVerified,  // Explicitly include GA flag
      }
    });
  } catch (error) {
    console.error("❌ Error verifying login OTP:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Update Profile Endpoint
app.post('/updateProfile', async (req, res) => {
  try {
    const { email, ...updatedData } = req.body;
    if (!email) {
      return res.status(400).json({ success: false, message: "Email is required." });
    }
    const database = client.db(process.env.MONGODB_DB_NAME);
    const collection = database.collection(process.env.MONGODB_COLLECTION);

    // Perform the update
    const result = await collection.updateOne({ email }, { $set: updatedData });
    if (result.modifiedCount > 0) {
      // Retrieve the updated user record
      const updatedUser = await collection.findOne({ email });

      // **Generate a NEW token** with updated user info (e.g., if email changed).
      const newToken = jwt.sign(
        { id: updatedUser._id, email: updatedUser.email },
        secretKey,
        { expiresIn: '1h' }
      );

      // Return the new token & updated user
      res.status(200).json({ 
        success: true,
        user: updatedUser,
        token: newToken, 
      });
    } else {
      res.status(400).json({ success: false, message: "Update failed." });
    }
  } catch (error) {
    console.error("Error updating profile:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Request to change email
app.post('/change-email-otp', async (req, res) => {
  try {
    const { currentEmail, newEmail } = req.body;
    if (!currentEmail || !newEmail) {
      return res
        .status(400)
        .json({ success: false, message: "Both currentEmail and newEmail are required." });
    }

    const database = client.db(process.env.MONGODB_DB_NAME);
    const collection = database.collection(process.env.MONGODB_COLLECTION);

    // Validate the user by current email
    const user = await collection.findOne({ email: currentEmail });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found." });
    }

    const emailChangeOtp = generateOTP();
    const otpExpiry = new Date(Date.now() + 10 * 60000);

    await collection.updateOne(
      { email: currentEmail },
      {
        $set: {
          emailChangeOtp,
          emailChangeExpiry: otpExpiry,
          tempNewEmail: newEmail,
        },
      }
    );

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: newEmail,
      subject: "Your Email Change OTP Code",
      text: `Your OTP code for changing email is: ${emailChangeOtp}. It is valid for 10 minutes.`,
    });

    res.status(200).json({
      success: true,
      message: "OTP sent to new email address. Please verify to complete the change.",
    });
  } catch (error) {
    console.error("❌ Error in /change-email-otp:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Verify and update email
app.post('/verify-change-email-otp', async (req, res) => {
  try {
    const { currentEmail, otp } = req.body;
    if (!currentEmail || !otp) {
      return res
        .status(400)
        .json({ success: false, message: "currentEmail and otp are required." });
    }

    const database = client.db(process.env.MONGODB_DB_NAME);
    const collection = database.collection(process.env.MONGODB_COLLECTION);

    const user = await collection.findOne({ email: currentEmail });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found." });
    }

    if (
      user.emailChangeOtp !== otp ||
      !user.emailChangeExpiry ||
      new Date(user.emailChangeExpiry) < new Date()
    ) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid or expired OTP. Please try again." });
    }

    const newEmail = user.tempNewEmail;
    if (!newEmail) {
      return res.status(400).json({
        success: false,
        message: "No new email found. Please request email change again.",
      });
    }

    const existingUserWithNewEmail = await collection.findOne({ email: newEmail });
    if (existingUserWithNewEmail) {
      return res
        .status(400)
        .json({ success: false, message: "New email is already in use." });
    }

    await collection.updateOne(
      { email: currentEmail },
      {
        $set: { email: newEmail },
        $unset: {
          emailChangeOtp: "",
          emailChangeExpiry: "",
          tempNewEmail: "",
        },
      }
    );

    const updatedUser = await collection.findOne({ email: newEmail });

    const token = jwt.sign(
      { id: updatedUser._id, email: updatedUser.email },
      secretKey,
      { expiresIn: '1h' }
    );

    res.status(200).json({
      success: true,
      message: "Email updated successfully.",
      newEmail,
      token,  
      user: updatedUser
    });
  } catch (error) {
    console.error("❌ Error in /verify-change-email-otp:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Request to change phone
app.post('/change-phone-otp', async (req, res) => {
  try {
    // Instead of single phone, retrieve area codes & mobiles:
    const { currentAreaCode, currentMobile, newAreaCode, newMobile } = req.body;
    if (!currentAreaCode || !currentMobile || !newAreaCode || !newMobile) {
      return res
        .status(400)
        .json({ success: false, message: "currentAreaCode, currentMobile, newAreaCode, and newMobile are required." });
    }

    const database = client.db(process.env.MONGODB_DB_NAME);
    const collection = database.collection(process.env.MONGODB_COLLECTION);

    // Find user by BOTH fields
    const user = await collection.findOne({ areaCode: currentAreaCode, mobile: currentMobile });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found." });
    }

    const phoneChangeOtp = generateOTP();
    const otpExpiry = new Date(Date.now() + 10 * 60000);

    // Store new areaCode + mobile in temp fields
    await collection.updateOne(
      { areaCode: currentAreaCode, mobile: currentMobile },
      {
        $set: {
          phoneChangeOtp,
          phoneChangeExpiry: otpExpiry,
          tempNewAreaCode: newAreaCode,
          tempNewPhone: newMobile,
        },
      }
    );

    // If user has an email, send them the OTP. 
    if (user.email) {
      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: user.email,
        subject: "Your Phone Change OTP Code",
        text: `Your OTP code for changing phone is: ${phoneChangeOtp}. It is valid for 10 minutes.`,
      });
    }

    res.status(200).json({
      success: true,
      message: "OTP sent. Please verify to complete phone change.",
    });
  } catch (error) {
    console.error("❌ Error in /change-phone-otp:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Verify phone OTP and update
app.post('/verify-change-phone-otp', async (req, res) => {
  try {
    // Retrieve areaCode, mobile, and OTP
    const { currentAreaCode, currentMobile, otp } = req.body;
    if (!currentAreaCode || !currentMobile || !otp) {
      return res
        .status(400)
        .json({ success: false, message: "currentAreaCode, currentMobile, and otp are required." });
    }

    const database = client.db(process.env.MONGODB_DB_NAME);
    const collection = database.collection(process.env.MONGODB_COLLECTION);

    const user = await collection.findOne({ areaCode: currentAreaCode, mobile: currentMobile });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found." });
    }

    if (
      user.phoneChangeOtp !== otp ||
      !user.phoneChangeExpiry ||
      new Date(user.phoneChangeExpiry) < new Date()
    ) {
      return res.status(400).json({ success: false, message: "Invalid or expired OTP. Please try again." });
    }

    // Retrieve the new areaCode + mobile stored in temp fields
    const newAreaCode = user.tempNewAreaCode;
    const newMobile = user.tempNewPhone;
    if (!newAreaCode || !newMobile) {
      return res.status(400).json({
        success: false,
        message: "No new phone found. Please request phone change again.",
      });
    }

    // Ensure new phone is not already in use
    const existingUserWithNewPhone = await collection.findOne({ areaCode: newAreaCode, mobile: newMobile });
    if (existingUserWithNewPhone) {
      return res.status(400).json({ success: false, message: "New phone is already in use." });
    }

    await collection.updateOne(
      { areaCode: currentAreaCode, mobile: currentMobile },
      {
        $set: { areaCode: newAreaCode, mobile: newMobile },
        $unset: {
          phoneChangeOtp: "",
          phoneChangeExpiry: "",
          tempNewAreaCode: "",
          tempNewPhone: "",
        },
      }
    );

    const updatedUser = await collection.findOne({ areaCode: newAreaCode, mobile: newMobile });

    const token = jwt.sign(
      { id: updatedUser._id, email: updatedUser.email, mobile: updatedUser.mobile },
      secretKey,
      { expiresIn: '1h' }
    );

    res.status(200).json({
      success: true,
      message: "Phone updated successfully.",
      newPhone: newAreaCode + newMobile,
      token,
      user: updatedUser
    });
  } catch (error) {
    console.error("❌ Error in /verify-change-phone-otp:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Change Password OTP Endpoint
app.post('/change-password-otp', async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!req.headers.authorization) {
      return res.status(401).json({ success: false, message: "Authorization token is required." });
    }
    const token = req.headers.authorization.split(' ')[1];
    let decoded;
    try {
      decoded = jwt.verify(token, secretKey);
    } catch (err) {
      return res.status(401).json({ success: false, message: "Invalid token." });
    }
    const email = decoded.email;
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ success: false, message: "Current and new password are required." });
    }
    const database = client.db(process.env.MONGODB_DB_NAME);
    const collection = database.collection(process.env.MONGODB_COLLECTION);
    const user = await collection.findOne({ email });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found." });
    }
    const valid = await bcryptjs.compare(currentPassword, user.password);
    if (!valid) {
      return res.status(401).json({ success: false, message: "Current password is incorrect." });
    }
    // Generate OTP for password change
    const passwordChangeOtp = generateOTP();
    const otpExpiry = new Date(Date.now() + 10 * 60000); // valid for 10 minutes
    // Store OTP and the new password in a temporary field
    await collection.updateOne({ email }, {
      $set: {
        passwordChangeOtp,
        passwordChangeExpiry: otpExpiry,
        tempNewPassword: newPassword
      }
    });

    // Send OTP via email
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Your Password Change OTP Code",
      text: `Your OTP code for changing password is: ${passwordChangeOtp}. It is valid for 10 minutes.`
    });
    res.status(200).json({
      success: true,
      message: "OTP sent to your email for password change. Please verify to complete the change."
    });
  } catch (error) {
    console.error("❌ Error in /change-password-otp:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Verify Change Password OTP and Update Endpoint
app.post('/verify-change-password-otp', async (req, res) => {
  try {
    const { otp } = req.body;
    if (!req.headers.authorization) {
      return res.status(401).json({ success: false, message: "Authorization token is required." });
    }
    const token = req.headers.authorization.split(' ')[1];
    let decoded;
    try {
      decoded = jwt.verify(token, secretKey);
    } catch (err) {
      return res.status(401).json({ success: false, message: "Invalid token." });
    }
    const email = decoded.email;
    if (!otp) {
      return res.status(400).json({ success: false, message: "OTP is required." });
    }
    const database = client.db(process.env.MONGODB_DB_NAME);
    const collection = database.collection(process.env.MONGODB_COLLECTION);
    const user = await collection.findOne({ email });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found." });
    }
    if (user.passwordChangeOtp !== otp || !user.passwordChangeExpiry || new Date(user.passwordChangeExpiry) < new Date()) {
      return res.status(400).json({ success: false, message: "Invalid or expired OTP." });
    }
    const tempNewPassword = user.tempNewPassword;
    if (!tempNewPassword) {
      return res.status(400).json({ success: false, message: "New password not found. Please request a password change again." });
    }
    // Hash the new password
    const hashedNewPassword = await bcryptjs.hash(tempNewPassword, 10);
    // Update the user's password and remove temporary fields
    const updateResult = await collection.updateOne({ email }, {
      $set: { password: hashedNewPassword },
      $unset: { passwordChangeOtp: "", passwordChangeExpiry: "", tempNewPassword: "" }
    });
    if (updateResult.modifiedCount > 0) {
      const updatedUser = await collection.findOne({ email });
      const newToken = jwt.sign(
        { id: updatedUser._id, email: updatedUser.email },
        secretKey,
        { expiresIn: '1h' }
      );
      return res.status(200).json({
        success: true,
        message: "Password updated successfully.",
        token: newToken,
        user: updatedUser
      });
    } else {
      return res.status(400).json({ success: false, message: "Failed to update password." });
    }
  } catch (error) {
    console.error("❌ Error in /verify-change-password-otp:", error);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

// Forgot Password OTP Endpoint
app.post('/forgot-password-otp', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ success: false, message: "Email is required." });
    }
    const database = client.db(process.env.MONGODB_DB_NAME);
    const collection = database.collection(process.env.MONGODB_COLLECTION);

    const user = await collection.findOne({ email });
    if (!user) {
      return res.status(404).json({ success: false, message: "Invalid email address." });
    }

    const otp = generateOTP();
    const otpExpiry = new Date(Date.now() + 10 * 60000); // valid for 10 minutes

    await collection.updateOne({ email }, {
      $set: {
        forgotPasswordOtp: otp,
        forgotPasswordExpiry: otpExpiry,
      },
    });

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Your Forgot Password OTP Code",
      text: `Your OTP code for password recovery is: ${otp}. It is valid for 10 minutes.`,
    });

    res.status(200).json({ success: true, message: "OTP sent to your email address." });
  } catch (error) {
    console.error("❌ Error in /forgot-password-otp:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Forgot Change Password Endpoint (updated)
app.post('/forgot-change-password', async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;
    if (!email || !otp || !newPassword) {
      return res.status(400).json({ success: false, message: "Email, OTP and new password are required." });
    }
    const database = client.db(process.env.MONGODB_DB_NAME);
    const collection = database.collection(process.env.MONGODB_COLLECTION);
    const user = await collection.findOne({ email });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found." });
    }
    if (user.forgotPasswordOtp !== otp || !user.forgotPasswordExpiry || new Date(user.forgotPasswordExpiry) < new Date()) {
      return res.status(400).json({ success: false, message: "Invalid or expired OTP." });
    }
    // Hash the new password
    const hashedNewPassword = await bcryptjs.hash(newPassword, 10);
    const updateResult = await collection.updateOne({ email }, {
      $set: { password: hashedNewPassword },
      $unset: { forgotPasswordOtp: "", forgotPasswordExpiry: "" }
    });
    if (updateResult.modifiedCount > 0) {
      const updatedUser = await collection.findOne({ email });
      const newToken = jwt.sign(
        { id: updatedUser._id, email: updatedUser.email },
        secretKey,
        { expiresIn: '1h' }
      );
      return res.status(200).json({
        success: true,
        message: "Password updated successfully.",
        token: newToken,
        user: updatedUser
      });
    } else {
      return res.status(400).json({ success: false, message: "Failed to update password." });
    }
  } catch (error) {
    console.error("❌ Error in /forgot-change-password:", error);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

// Verify Forgot Password OTP Endpoint
app.post('/verify-forgot-password-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) {
      return res.status(400).json({ success: false, message: "Email and OTP are required." });
    }
    const database = client.db(process.env.MONGODB_DB_NAME);
    const collection = database.collection(process.env.MONGODB_COLLECTION);
    const user = await collection.findOne({ email });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found." });
    }
    if (user.forgotPasswordOtp !== otp || !user.forgotPasswordExpiry || new Date(user.forgotPasswordExpiry) < new Date()) {
      return res.status(400).json({ success: false, message: "Invalid or expired OTP." });
    }
    // OTP is valid
    res.status(200).json({ success: true, message: "OTP verified successfully." });
  } catch (error) {
    console.error("❌ Error in /verify-forgot-password-otp:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// NEW: Endpoint to send OTP for Card Details Verification
app.post('/send-card-details-otp', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ success: false, message: "Email is required." });
    }
    const database = client.db(process.env.MONGODB_DB_NAME);
    const collection = database.collection(process.env.MONGODB_COLLECTION);
    const user = await collection.findOne({ email });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found." });
    }
    // Generate OTP for card details and set expiry to 10 minutes from now
    const otp = generateOTP();
    const otpExpiry = new Date(Date.now() + 10 * 60000);
    
    // Save the OTP and expiry on the user document (using new fields)
    await collection.updateOne({ email }, { 
      $set: { cardDetailsOtp: otp, cardDetailsOtpExpiry: otpExpiry } 
    });
    console.log(`🔑 Generated Card Details OTP for ${email}: ${otp}`);

    // Send the OTP via email using your configured transporter
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Your Card Details OTP Code",
      text: `Your OTP for card details verification is: ${otp}. It is valid for 10 minutes.`
    });

    res.status(200).json({ success: true, message: "OTP sent for card details verification." });
  } catch (error) {
    console.error("❌ Error sending Card Details OTP:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// NEW: Endpoint to verify OTP for Card Details Verification
app.post('/verify-card-details-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) {
      return res.status(400).json({ success: false, message: "Email and OTP are required." });
    }
    const database = client.db(process.env.MONGODB_DB_NAME);
    const collection = database.collection(process.env.MONGODB_COLLECTION);
    const user = await collection.findOne({ email });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found." });
    }
    // Verify that the provided OTP matches and has not expired
    if (user.cardDetailsOtp !== otp || new Date(user.cardDetailsOtpExpiry) < new Date()) {
      return res.status(400).json({ success: false, message: "Invalid or expired OTP. Please try again." });
    }
    // OTP is valid; clear the OTP fields
    await collection.updateOne({ email }, { $unset: { cardDetailsOtp: "", cardDetailsOtpExpiry: "" } });
    res.status(200).json({ success: true, message: "OTP verified successfully." });
  } catch (error) {
    console.error("❌ Error verifying Card Details OTP:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// NEW: Resend Card Details OTP Endpoint
app.post('/resend-card-details-otp', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ success: false, message: "Email is required." });
    }
    const database = client.db(process.env.MONGODB_DB_NAME);
    const collection = database.collection(process.env.MONGODB_COLLECTION);
    const user = await collection.findOne({ email });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found." });
    }
    // Generate a new 6-digit OTP for card details and set expiry to 10 minutes from now
    const otp = generateOTP();
    const otpExpiry = new Date(Date.now() + 10 * 60000);
    // Update the user's document with the new OTP in dedicated fields
    await collection.updateOne({ email }, { $set: { cardDetailsOtp: otp, cardDetailsOtpExpiry: otpExpiry } });
    console.log(`🔑 Resent Card Details OTP for ${email}: ${otp}`);
    // Send the OTP via email
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Your Card Details OTP Code",
      text: `Your OTP for card details verification is: ${otp}. It is valid for 10 minutes.`
    });
    res.status(200).json({ success: true, message: "OTP sent for card details verification." });
  } catch (error) {
    console.error("❌ Error resending Card Details OTP:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post('/resend-change-email-otp', async (req, res) => {
  try {
    const { currentEmail } = req.body;
    if (!currentEmail) {
      return res.status(400).json({ success: false, message: "Current email is required." });
    }
    const database = client.db(process.env.MONGODB_DB_NAME);
    const collection = database.collection(process.env.MONGODB_COLLECTION);
    const user = await collection.findOne({ email: currentEmail });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found." });
    }
    const otp = generateOTP();
    const otpExpiry = new Date(Date.now() + 10 * 60000);
    await collection.updateOne(
      { email: currentEmail },
      { $set: { changeEmailOtp: otp, changeEmailOtpExpiry: otpExpiry } }
    );
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: currentEmail,
      subject: "Your Change Email OTP Code",
      text: `Your OTP code for changing your email is: ${otp}. It is valid for 10 minutes.`
    });
    res.status(200).json({ success: true, message: "OTP sent for change email verification." });
  } catch (error) {
    console.error("❌ Error resending change email OTP:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post('/resend-change-phone-otp', async (req, res) => {
  try {
    const { currentAreaCode, currentMobile } = req.body;
    if (!currentAreaCode || !currentMobile) {
      return res.status(400).json({ success: false, message: "Area code and mobile are required." });
    }
    const database = client.db(process.env.MONGODB_DB_NAME);
    const collection = database.collection(process.env.MONGODB_COLLECTION);
    const user = await collection.findOne({ areaCode: currentAreaCode, mobile: currentMobile });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found." });
    }
    const otp = generateOTP();
    const otpExpiry = new Date(Date.now() + 10 * 60000);
    await collection.updateOne(
      { areaCode: currentAreaCode, mobile: currentMobile },
      { $set: { changePhoneOtp: otp, changePhoneOtpExpiry: otpExpiry } }
    );
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: "Your Change Phone OTP Code",
      text: `Your OTP code for changing your phone number is: ${otp}. It is valid for 10 minutes.`
    });
    res.status(200).json({ success: true, message: "OTP sent for change phone verification." });
  } catch (error) {
    console.error("❌ Error resending change phone OTP:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Add this new endpoint at an appropriate place in your server.js file
app.post('/create-zendesk-ticket', async (req, res) => {
  try {
    const { subject, message, requesterName, requesterEmail } = req.body;
    if (!subject || !message || !requesterName || !requesterEmail) {
      return res.status(400).json({ success: false, message: "Missing required fields" });
    }
    
    // Zendesk credentials – ensure these are correct!
    const zendeskSubdomain = process.env.ZENDESK_SUBDOMAIN;
    const zendeskEmail = process.env.ZENDESK_EMAIL;
    const zendeskApiToken = process.env.ZENDESK_TOKEN;
    
    // For testing, you might remove the async flag:
    const zendeskEndpoint = 'tickets.json';
    const url = `https://${zendeskSubdomain}.zendesk.com/api/v2/${zendeskEndpoint}`;
    
    const auth = `${zendeskEmail}/token:${zendeskApiToken}`;
    const encodedAuth = Buffer.from(auth).toString('base64');

    const payload = {
      ticket: {
        subject: subject,
        comment: { body: message },
        requester: {
          name: requesterName,
          email: requesterEmail,
        },
      },
    };

    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Basic " + encodedAuth,
      },
      body: JSON.stringify(payload),
    });

    // Rename the parsed JSON response to avoid naming conflicts:
    const zendeskData = await response.json();

    if (response.status === 202 || response.status === 200) {
      return res.json({ success: true, message: "Ticket creation accepted", data: zendeskData });
    } else {
      return res.status(response.status).json({ success: false, message: "Ticket creation failed", data: zendeskData });
    }
  } catch (error) {
    console.error("Error creating Zendesk ticket:", error);
    return res.status(500).json({ success: false, message: "Server error", error: error.toString() });
  }
});

// Ping Endpoint
app.get('/', (req, res) => {
  res.status(200).send('Server is up and running');
});

// Stripe Integration Endpoint
app.post('/payment-sheet', async (req, res) => {
  const { amount } = req.body;
  try {
    const customer = await stripe.customers.create();
    const ephemeralKey = await stripe.ephemeralKeys.create(
      { customer: customer.id },
      { apiVersion: '2022-11-15' }
    );
    const paymentIntent = await stripe.paymentIntents.create({
      amount,
      currency: 'usd',
      payment_method_types: ['card'],
    });
    res.json({
      paymentIntent: paymentIntent.client_secret,
      ephemeralKey: ephemeralKey.secret,
      customer: customer.id,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create Cardholder Endpoint & Open Card Integration
app.post('/create-cardholder', async (req, res) => {
  try {
    const { email, aiaCardId } = req.body;
    if (!email) {
      return res.status(400).json({ success: false, message: "Email is required" });
    }

    const database = client.db(process.env.MONGODB_DB_NAME);
    const collection = database.collection(process.env.MONGODB_COLLECTION);
    const user = await collection.findOne({ email });

    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    const requiredFields = [
      "firstName", "lastName", "email", "areaCode",
      "mobile", "birthday", "address", "town", "postCode", "country"
    ];
    for (const field of requiredFields) {
      if (!user[field]) {
        return res.status(400).json({ success: false, message: `Missing required field: ${field}` });
      }
    }

    let holderId = user.holderId;

    if (!holderId) {
      // Prepare Wasabi payload
      const payload = {
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        areaCode: user.areaCode,
        mobile: user.mobile,
        birthday: user.birthday,
        address: user.address,
        town: user.town,
        postCode: user.postCode,
        country: user.country,
        cardTypeId: 111016,
        holderId: '' // Placeholder
      };

      // Call Wasabi API
      const wasabiResult = await callWasabiApi("/merchant/core/mcb/card/holder/create", payload);
      holderId = wasabiResult.data.holderId;

      // Base update object
      const updateData = { holderId };

      // If referralId exists, calculate refereeTier
      if (user.referralId) {
        const referredCount = await collection.countDocuments({
          referralId: user.referralId,
          holderId: { $exists: true, $ne: "" }
        });

        let refereeTier = 1;
        if (referredCount >= 3 && referredCount <= 9) refereeTier = 2;
        else if (referredCount >= 10 && referredCount <= 49) refereeTier = 3;
        else if (referredCount >= 50 && referredCount <= 99) refereeTier = 4;
        else if (referredCount >= 100) refereeTier = 5;

        updateData.refereeTier = refereeTier;
      }

      // Update user with holderId (+ refereeTier if applicable)
      await collection.updateOne({ email: user.email }, { $set: updateData });
    }

    // Call openCard
    try {
      const openCardResponse = await openCard(holderId, email, aiaCardId);
    } catch (openError) {
      console.error("Failed to open card for holderId", holderId, openError);
    }

    res.json({ success: true, holderId, message: "HolderId processed successfully" });
  } catch (error) {
    console.error("Error creating cardholder on WasabiCard API:", error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// Card Details Endpoint – retrieves card info (with CVV fetched dynamically)
app.post('/card-details', async (req, res) => {
  try {
    const { email, cardNo } = req.body;
    if (!email) {
      return res.status(400).json({ success: false, message: "Email is required" });
    }

    const database = client.db(process.env.MONGODB_DB_NAME);
    const collection = database.collection(process.env.MONGODB_COLLECTION);
    const user = await collection.findOne({ email });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    // Use the passed cardNo if available; otherwise, fallback to user.cardNumber
    const effectiveCardNo = cardNo || user.cardNumber;
    if (!effectiveCardNo || !user.holderId) {
      return res.status(400).json({ success: false, message: "Card information not available for this user." });
    }

    const payload = {
      cardNo: effectiveCardNo,
      onlySimpleInfo: false,
    };

    const wasabiResponse = await callWasabiApi('/merchant/core/mcb/card/info', payload);

    if (wasabiResponse.success && wasabiResponse.data) {
      const decryptedValidPeriod = await decryptUsingMicroservice(wasabiResponse.data.validPeriod);
      wasabiResponse.data.validPeriod = decryptedValidPeriod || user.expiryDate || 'N/A';

      const rawCardNumber = wasabiResponse.data.cardNumber;
      if (rawCardNumber && rawCardNumber.length >= 4) {
        wasabiResponse.data.maskedCardNumber = "**** " + rawCardNumber.slice(-4);
      } else {
        wasabiResponse.data.maskedCardNumber = "N/A";
      }

      if (wasabiResponse.data.cvv) {
        const decryptedCvv = await decryptUsingMicroservice(wasabiResponse.data.cvv);
        wasabiResponse.data.cvv = decryptedCvv;
      }
    }

    res.json(wasabiResponse);
  } catch (error) {
    console.error("Error fetching card details:", error);
    res.status(500).json({ success: false, message: error.message });
  }
});

app.post('/create-vault-account', async (req, res) => {
  try {
    const payload = req.body;
    // Call the exported createVaultAccount function.
    const result = await fireblocks.createVaultAccount(payload);
    res.json({ success: true, data: result });
  } catch (error) {
    console.error('Error calling Fireblocks API:', error);
    res.status(500).json({ success: false, message: error.message });
  }
});

const server = app.listen(port, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${port}`);
});
server.on('error', (err) => {
  console.error('Server error:', err);
});

