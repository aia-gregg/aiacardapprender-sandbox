
const express = require('express');
const cors = require('cors');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { MongoClient, ServerApiVersion, Decimal128 } = require('mongodb');
const crypto = require('crypto');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const stripe = require('stripe')('sk_test_51Qy1IkDO1xHmcck34QjJM47p4jkKFGViTuIVlbY1njZqObWxc9hWMvrWCsiSVgCRd08Xx1fyfXYG90Hxw6yl84WO00Xt3GGTjU'); // Test secret key
const { merchantPrivateKey, callWasabiApi } = require('./wasabiApi');
const fireblocks = require('./fireblocks');
// const http = require('http');
const otplib = require('otplib');
//const mongoose = require('mongoose');

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
const secretKey = "your_super_secret_key";

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Connect to MongoDB
client.connect()
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch((err) => console.error("❌ Error connecting to MongoDB:", err));

// client.connect()
//   .then(() => {
//     console.log("✅ Connected to MongoDB");
//     // Call seedData on server start
//     seedWasabiData();
//   })
//   .catch((err) => console.error("❌ Error connecting to MongoDB:", err));

  async function decryptUsingMicroservice(encryptedData) {
    if (!encryptedData) return null;
    try {
      const response = await fetch("https://aiacardappjava-sandbox.onrender.com/api/decrypt", {
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
  
// Connect to MongoDB (ensure process.env.MONGODB_URI is set in your environment)
// mongoose.connect(process.env.MONGODB_URI)

// Define the user schema and model.
// const userSchema = new mongoose.Schema({
//   email: { type: String, required: true, unique: true },
//   totpSecret: { type: String },
//   twoFAEnabled: { type: Boolean, default: false },
//   isGAVerified: { type: Boolean, default: false },  // Ensure this is included
//   biometricsEnabled: { type: Boolean, default: false },
//   // ...other fields
// });

// const User = mongoose.model('User', userSchema);

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
    const database = client.db("aiacard-sandbox-db");
    const collection = database.collection("aiacard-sandox-col");
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

/**
 * POST /api/verify-2fa
 *
 * Request body should include: { email: string, otp: string }
 * Verifies the OTP code using the stored secret in MongoDB.
 * If valid, marks the user's 2FA as enabled.
 */

app.post('/api/verify-2fa', async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) {
    return res.status(400).json({ error: 'Missing email or otp in request body' });
  }
  try {
    const database = client.db("aiacard-sandbox-db");
    const collection = database.collection("aiacard-sandox-col");
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
    const database = client.db("aiacard-sandbox-db");
    const collection = database.collection("aiacard-sandox-col");
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
//     const db = client.db("aiacard-sandbox-cities");
//     const collection = db.collection("aiacard-sandcity-col");

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

// Endpoint to fetch referrals for a given referral ID
app.get('/referrals', async (req, res) => {
  const { referralId } = req.query;
  if (!referralId) {
    return res.status(400).json({ success: false, message: "Missing referralId parameter" });
  }

  try {
    const database = client.db("aiacard-sandbox-db");
    const collection = database.collection("aiacard-sandox-col");

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
app.get('/referral-rewards', async (req, res) => {
  const { referralId } = req.query;
  if (!referralId) {
    return res.status(400).json({ success: false, message: "Missing referralId parameter" });
  }
  try {
    const referralDb = client.db("aiacard-sandbox-refer");
    const collection = referralDb.collection("aiacard-sandrefer-col");
    
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
app.post('/api/update-biometrics', async (req, res) => {
  const { email, biometricsEnabled } = req.body;
  if (!email || typeof biometricsEnabled !== 'boolean') {
    return res.status(400).json({ error: 'Missing or invalid parameters' });
  }
  try {
    const database = client.db("aiacard-sandbox-db");
    const collection = database.collection("aiacard-sandox-col");
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

// Helper: Generate a 6-digit OTP
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
    amount: 45,
    aiaCardId: aiaCardId, // Use the passed AIACardId (e.g., 'lite', 'pro', or 'elite')
  };

  try {
    const response = await callWasabiApi('/merchant/core/mcb/card/openCard', payload);
    // console.log('Card opened successfully:', response);

    // Assuming response.data is an array with at least one element containing orderNo
    let orderNo = null;
    if (response && response.data && Array.isArray(response.data) && response.data.length > 0) {
      orderNo = response.data[0].orderNo;
    }
    
    if (orderNo) {
      // Log the orderNo into MongoDB so that the webhook can later lookup the record.
      const database = client.db("aiacard-sandbox-db");
      const collection = database.collection("aiacard-sandox-col");

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
        // console.log(`User with holderId ${holderId} updated with orderNo: ${orderNo} and ${cardAIAField}: ${aiaCardId}`);
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

// Express endpoint to expose openCard function
app.post('/openCard', async (req, res) => {
  try {
    const { holderId, email, aiaCardId } = req.body;
    const result = await openCard(holderId, email, aiaCardId);
    res.status(200).json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Helper function: send push notification using Expo push API
async function sendPushNotification(expoPushToken, notificationData) {
  const message = {
    to: expoPushToken,
    sound: 'default',
    title: notificationData.title,
    body: notificationData.desc,
    data: { ...notificationData },
  };

  try {
    const response = await fetch('https://exp.host/--/api/v2/push/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(message),
    });
    const data = await response.json();
    console.log('Push notification response:', data);
  } catch (error) {
    console.error('Error sending push notification:', error);
  }
}

// Webhook API
app.post( '/webhook', express.json({
    verify: (req, res, buf) => {
      req.rawBody = buf.toString();
    },
  }),
  (req, res) => {
    // Immediately acknowledge with the expected JSON response
    const responsePayload = {
      success: true,
      code: 200,
      msg: "Success",
      data: null,
    };
    res.status(200).json(responsePayload);
    console.log('Webhook acknowledged:', responsePayload);

    // Process the webhook asynchronously
    setImmediate(async () => {
      try {
        console.log('Webhook raw payload:', req.rawBody);
        console.log('Webhook parsed payload:', req.body);

        // Verify signature if provided
        const signature = req.headers['x-signature'];
        if (signature) {
          const computedSignature = crypto
            .createHmac('sha256', process.env.WASABI_WEBHOOK_SECRET)
            .update(req.rawBody)
            .digest('hex');
          if (computedSignature !== signature) {
            console.error('Signature verification failed.');
            return;
          }
        } else {
          console.warn('No signature header found.');
        }

        // Check for notification category header
      const category = req.headers['x-wsb-category'];
      if (category) {
        console.log('Notification category:', category);
        // Process category-based notifications concurrently
        switch (category) {
          case 'card_transaction':
            processCardTransaction(req.body).catch(err =>
              console.error('Error processing card_transaction:', err)
            );
            break;
          case 'card_auth_transaction':
            processCardAuthTransaction(req.body).catch(err =>
              console.error('Error processing card_auth_transaction:', err)
            );
            break;
          case 'card_fee_patch':
            processCardFeePatch(req.body).catch(err =>
              console.error('Error processing card_fee_patch:', err)
            );
            break;
          default:
            console.warn('Unhandled notification category:', category);
        }
        return; // Exit if category was handled
      }


        // Fallback processing if no category header
        const { orderNo, cardNo, type } = req.body;
        if (!orderNo || !cardNo) {
          console.error('Missing orderNo or cardNo in webhook payload.');
          return;
        }
        if (type !== 'create') {
          console.log(`Webhook type is ${type} (expected 'create'). Skipping processing.`);
          return;
        }

        // Connect to the database
        const database = client.db("aiacard-sandbox-db");
        const collection = database.collection("aiacard-sandox-col");

        // Find the user by orderNo (ensure this field is indexed)
        const user = await collection.findOne({ orderNo });
        if (!user) {
          console.error(`No user found with orderNo: ${orderNo}`);
          return;
        }

        // Calculate new card index and field name
        const activeCards = user.activeCards || 0;
        const newCardIndex = activeCards + 1;
        const cardFieldName = `cardNo${newCardIndex}`;

        // Update the user record concurrently with other operations
        const updatePromise = collection.updateOne(
          { _id: user._id },
          {
            $set: { [cardFieldName]: cardNo, orderNo: "" },
            $inc: { activeCards: 1 },
          }
        );

        // Optionally, you can fire off additional operations in parallel here.

        const updateResult = await updatePromise;
        if (updateResult.modifiedCount > 0) {
          console.log(`User ${user.email} updated: ${cardFieldName} set to ${cardNo}. Active cards: ${newCardIndex}`);
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

// Helper function to process Card Transaction notifications
async function processCardTransaction(payload) {
  const { orderNo, cardNo, type } = payload;
  if (!orderNo || !cardNo) {
    console.error('Missing orderNo or cardNo in card transaction payload.');
    return;
  }
  if (type !== 'create') {
    console.log(`Card transaction type is ${type}. No processing implemented for this type.`);
    return;
  }
  try {
    const database = client.db("aiacard-sandbox-db");
    const collection = database.collection("aiacard-sandox-col");

    const user = await collection.findOne({ orderNo });
    if (!user) {
      console.error(`No user found with orderNo: ${orderNo}`);
      return;
    }

    const activeCards = user.activeCards || 0;
    const newCardIndex = activeCards + 1;
    const cardFieldName = `cardNo${newCardIndex}`;
    const updateResult = await collection.updateOne(
      { _id: user._id },
      {
        $set: { [cardFieldName]: cardNo, orderNo: "" },
        $inc: { activeCards: 1 }
      }
    );
    if (updateResult.modifiedCount > 0) {
      console.log(`(Notification) User ${user.email} updated: ${cardFieldName} set to ${cardNo}. Active cards: ${newCardIndex}`);

      // Create a masked card number (last 4 digits)
      const maskedCardNo = "**** " + cardNo.slice(-4);

      // Insert a notification document
      const notificationData = {
        title: "Card Activation",
        desc: `Your new card ending ${maskedCardNo} has been successfully created and activated. Happy spending!`,
        notifyTime: new Date(),
        userNotify: user.holderId  // or "All" if applicable
      };
      await insertNotification(notificationData);

      // Send push notification if the user has an Expo push token
      if (user.expoPushToken) {
        await sendPushNotification(user.expoPushToken, notificationData);
      } else {
        console.warn(`No Expo push token found for user ${user.email}`);
      }

      // Fetch the updated user record so that activeCards and new fields are current
      const updatedUser = await collection.findOne({ _id: user._id });
      console.log("Calling handleReferralReward with updated user:", { email: updatedUser.email, activeCards: updatedUser.activeCards });
      await handleReferralReward(updatedUser, cardNo);
    } else {
      console.error('(Notification) Failed to update user record for card transaction.');
    }
  } catch (error) {
    console.error('Error processing card transaction notification:', error);
  }
}

// Helper function to insert a notification document into the notifications collection
async function insertNotification(notificationData) {
  try {
    const notificationsDb = client.db("aiacard-sandbox-notify");
    const notificationsCollection = notificationsDb.collection("aiacard-sandnotify-col");
    await notificationsCollection.insertOne(notificationData);
    console.log("Notification inserted:", notificationData);
  } catch (error) {
    console.error("Error inserting notification:", error);
  }
}

// Helper function to process Card Authorization Transaction notifications
async function processCardAuthTransaction(payload) {
  const { cardNo, merchantName, amount } = payload;
  if (!cardNo || !merchantName || amount == null) {
    console.error('Missing cardNo, merchantName, or amount in card auth transaction payload.');
    return;
  }
  console.log('Processing card auth transaction notification:', payload);
  try {
    const database = client.db("aiacard-sandbox-db");
    const collection = database.collection("cardAuthTransactions");
    await collection.insertOne(payload);
    console.log(`(Notification) Card auth transaction logged successfully.`);
    
    // Create a masked card number using the last four digits
    const maskedCardNo = "**** " + cardNo.slice(-4);
    
    // Build a more user-friendly description using merchantName and amount
    const notificationData = {
      title: "Transaction",
      desc: `Authorization transaction for ${currency} ${amount} from card ending ${maskedCardNo} has been processed at ${merchantName}.`,
      notifyTime: new Date(),
      userNotify: payload.holderId || "All" // Adjust if payload contains a specific holderId
    };
    
    await insertNotification(notificationData);

    // If this notification targets a specific user, try to send a push notification
    if (payload.holderId) {
      const usersDb = client.db("aiacard-sandbox-db");
      const usersCollection = usersDb.collection("aiacard-sandox-col");
      const user = await usersCollection.findOne({ holderId: payload.holderId });
      if (user && user.expoPushToken) {
        await sendPushNotification(user.expoPushToken, notificationData);
      } else {
        console.warn(`No Expo push token found for holderId ${payload.holderId}`);
      }
    } else {
      console.log("Broadcast push notification for all users not implemented.");
    }
    
  } catch (error) {
    console.error('Error processing card auth transaction notification:', error);
  }
}

// Helper function to process Card Authorization Reversal Transaction notifications
async function processCardFeePatch(payload) {
  const { cardNo, tradeNo, originTradeNo, currency, amount } = payload;
  if (!cardNo || !tradeNo || !originTradeNo || !currency || amount == null) {
    console.error('Missing required fields in card fee patch payload.');
    return;
  }
  console.log('Processing card fee patch (reversal) notification:', payload);
  try {
    const database = client.db("aiacard-sandbox-db");
    const collection = database.collection("cardFeePatchTransactions");
    await collection.insertOne(payload);
    console.log(`(Notification) Card fee patch transaction for tradeNo ${tradeNo} logged successfully.`);
    
    // Create a masked card number using the last 4 digits
    const maskedCardNo = "**** " + cardNo.slice(-4);
    
    // Build a more user-friendly notification description
    const notificationData = {
      title: "Transaction Reversal",
      desc: `Reversal processed for ${currency} ${amount} for card ending ${maskedCardNo}.`,
      notifyTime: new Date(),
      userNotify: payload.holderId || "All"  // Adjust if payload contains a specific holderId
    };
    await insertNotification(notificationData);

    if (payload.holderId) {
      const usersDb = client.db("aiacard-sandbox-db");
      const usersCollection = usersDb.collection("aiacard-sandox-col");
      const user = await usersCollection.findOne({ holderId: payload.holderId });
      if (user && user.expoPushToken) {
        await sendPushNotification(user.expoPushToken, notificationData);
      } else {
        console.warn(`No Expo push token found for holderId ${payload.holderId}`);
      }
    } else {
      console.log("Broadcast push notification for all users not implemented.");
    }
    
  } catch (error) {
    console.error('Error processing card fee patch notification:', error);
  }
}

// New endpoint to fetch notifications from the dedicated notifications database/collection
app.get('/notifications', async (req, res) => {
  try {
    const database = client.db("aiacard-sandbox-notify");
    const collection = database.collection("aiacard-sandnotify-col");

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

    console.log('Sending payload to Wasabi API:', JSON.stringify(payload));
    const response = await callWasabiApi('/merchant/core/mcb/card/authTransaction', payload);
    console.log('Received response from Wasabi API:', JSON.stringify(response));
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
    
    const database = client.db("aiacard-sandbox-db");
    const collection = database.collection("aiacard-sandox-col");
    
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
      // console.log('Raw response from Wasabi API for cardNo:', cardNo, response);
      
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
app.post('/top-up', async (req, res) => {
  // Log the entire request body to check what is being sent - DELETE
  // console.log("Received /top-up request:", req.body);

  const { cardNo, merchantOrderNo, amount } = req.body;

  // Validate required fields
  if (!cardNo || !merchantOrderNo || !amount) {
    console.error("Validation error: Missing required fields", req.body);
    return res.status(400).json({
      success: false,
      message: 'Missing required fields: cardNo, merchantOrderNo, and amount are required.'
    });
  }

  // Prepare payload for the Wasabi deposit API call.
  // Added "currency": "USD" as a potential required field.
  const depositPayload = {
    cardNo,
    merchantOrderNo,
    amount: amount, // Already formatted as a string like "51.75"
    currency: "USD"
  };
  // console.log('Sending deposit payload to Wasabi:', JSON.stringify(depositPayload)); // DELETE

  try {
    // Call Wasabi deposit API using the helper function.
    const data = await callWasabiApi('/merchant/core/mcb/card/deposit', depositPayload);

    // 3. Log the raw response - DELETE
    // console.log('Wasabi deposit API response:', JSON.stringify(data));

    if (data.success && data.data && data.data.status === 'processing') {
      // Prepare topup record to save in MongoDB
      const topupRecord = {
        merchantOrderNo,
        cardNo,
        amount,
        orderNo: data.data.orderNo,
        status: data.data.status,
        remark: data.data.remark,
        transactionTime: new Date(data.data.transactionTime),
        details: data.data,
        createdAt: new Date()
      };

      const dbName = process.env.MONGODB_DB_NAME_TOPUP;
      const collectionName = process.env.MONGODB_COLLECTION_TOPUP;

      // Log before insertion
      // console.log('Inserting topup record into MongoDB:', JSON.stringify(topupRecord));

      const insertResult = await client.db(dbName).collection(collectionName).insertOne(topupRecord);
      // console.log('MongoDB insertion result:', insertResult);

      return res.status(200).json({ success: true, data });
    } else {
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

  // console.log("Received freeze request payload:", req.body);

  // Create the payload for Wasabi API
  const payload = { cardNo, maskedCardNumber };

  try {
    // Call the Wasabi Pay API endpoint for freezing the card
    const freezeResponse = await callWasabiApi('/merchant/core/mcb/card/freeze', payload);
    // console.log("Freeze response from Wasabi API:", freezeResponse);
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

  // console.log("Received unfreeze request payload:", req.body);

  // Create the payload for Wasabi API
  const payload = { cardNo, maskedCardNumber };

  try {
    // Call the Wasabi Pay API endpoint for unfreezing the card
    const unfreezeResponse = await callWasabiApi('/merchant/core/mcb/card/unfreeze', payload);
    // console.log("Unfreeze response from Wasabi API:", unfreezeResponse);
    res.json(unfreezeResponse);
  } catch (error) {
    console.error("Error unfreezing card:", error);
    res.status(500).json({ success: false, code: 500, msg: "Internal Server Error" });
  }
});

// Nodemailer Configuration
const transporter = nodemailer.createTransport({
  host: "smtp-mail.outlook.com",
  port: 587,
  secure: false,
  auth: {
    user: "verify@card.aianalysis.group",
    pass: "1gL5zemXG6gFsv331epx",
  },
  tls: { ciphers: 'SSLv3' }
});

// Registration Endpoint
app.post('/register', async (req, res) => {
  try {
    const { email, password, ...userData } = req.body;
    const database = client.db("aiacard-sandbox-db");
    const collection = database.collection("aiacard-sandox-col");

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
      from: "verify@card.aianalysis.group",
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
    const database = client.db("aiacard-sandbox-db");
    const collection = database.collection("aiacard-sandox-col");

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
    // console.log(`✅ OTP verified for ${email}. User is now verified.`);

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
    const database = client.db("aiacard-sandbox-db");
    const collection = database.collection("aiacard-sandox-col");

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
      from: "verify@card.aianalysis.group",
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
    const database = client.db("aiacard-sandbox-db");
    const collection = database.collection("aiacard-sandox-col");
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
      from: "verify@card.aianalysis.group",
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
    const database = client.db("aiacard-sandbox-db");
    const collection = database.collection("aiacard-sandox-col");

    const user = await collection.findOne({ email });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found." });
    }

    const otp = generateOTP();
    const otpExpiry = new Date(Date.now() + 10 * 60000);
    console.log(`🔑 Resent Login OTP for ${email}: ${otp}`);

    await collection.updateOne({ email }, { $set: { otp, otpExpiry } });
    await transporter.sendMail({
      from: "verify@card.aianalysis.group",
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
    const database = client.db("aiacard-sandbox-db");
    const collection = database.collection("aiacard-sandox-col");

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
      from: "verify@card.aianalysis.group",
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
    const database = client.db("aiacard-sandbox-db");
    const collection = database.collection("aiacard-sandox-col");

    const user = await collection.findOne({ email });
    if (!user || user.otp !== otp || new Date(user.otpExpiry) < new Date()) {
      return res.status(400).json({ success: false, message: "Invalid or expired OTP. Please try again." });
    }

    await collection.updateOne({ email }, { $unset: { otp: "", otpExpiry: "" } });

    const token = jwt.sign({ id: user._id, email: user.email }, secretKey, { expiresIn: '1h' });
    // console.log(`✅ OTP verified for ${email}. User is now logged in.`);

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
    const database = client.db("aiacard-sandbox-db");
    const collection = database.collection("aiacard-sandox-col");

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

    const database = client.db("aiacard-sandbox-db");
    const collection = database.collection("aiacard-sandox-col");

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

    console.log(`🔑 Generated Email Change OTP for ${currentEmail}: ${emailChangeOtp}`);

    await transporter.sendMail({
      from: "verify@card.aianalysis.group",
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

    const database = client.db("aiacard-sandbox-db");
    const collection = database.collection("aiacard-sandox-col");

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

    // console.log(`✅ Email updated from ${currentEmail} to ${newEmail} successfully. New token generated.`);

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

    const database = client.db("aiacard-sandbox-db");
    const collection = database.collection("aiacard-sandox-col");

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

    console.log(`🔑 Generated Phone Change OTP for ${currentAreaCode}${currentMobile}: ${phoneChangeOtp}`);

    // If user has an email, send them the OTP. 
    if (user.email) {
      await transporter.sendMail({
        from: "verify@card.aianalysis.group",
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

    const database = client.db("aiacard-sandbox-db");
    const collection = database.collection("aiacard-sandox-col");

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

    // console.log(`✅ Phone updated from ${currentAreaCode}${currentMobile} to ${newAreaCode}${newMobile} successfully. Token regenerated.`);

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
    const database = client.db("aiacard-sandbox-db");
    const collection = database.collection("aiacard-sandox-col");
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
    console.log(`🔑 Generated Password Change OTP for ${email}: ${passwordChangeOtp}`);
    // Send OTP via email
    await transporter.sendMail({
      from: "verify@card.aianalysis.group",
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
    const database = client.db("aiacard-sandbox-db");
    const collection = database.collection("aiacard-sandox-col");
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
      // console.log(`✅ Password updated for ${email}. New token generated.`);
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
    const database = client.db("aiacard-sandbox-db");
    const collection = database.collection("aiacard-sandox-col");

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

    console.log(`🔑 Generated Forgot Password OTP for ${email}: ${otp}`);

    await transporter.sendMail({
      from: "verify@card.aianalysis.group",
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
    const database = client.db("aiacard-sandbox-db");
    const collection = database.collection("aiacard-sandox-col");
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
      // console.log(`✅ Password updated for ${email}. New token generated.`);
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
    const database = client.db("aiacard-sandbox-db");
    const collection = database.collection("aiacard-sandox-col");
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
    const database = client.db("aiacard-sandbox-db");
    const collection = database.collection("aiacard-sandox-col");
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
    const database = client.db("aiacard-sandbox-db");
    const collection = database.collection("aiacard-sandox-col");
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
    // console.log(`✅ Card Details OTP verified for ${email}.`);
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
    const database = client.db("aiacard-sandbox-db");
    const collection = database.collection("aiacard-sandox-col");
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
    const database = client.db("aiacard-sandbox-db");
    const collection = database.collection("aiacard-sandox-col");
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
    console.log(`🔑 Resent Change Email OTP for ${currentEmail}: ${otp}`);
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
    const database = client.db("aiacard-sandbox-db");
    const collection = database.collection("aiacard-sandox-col");
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
    console.log(`🔑 Resent Change Phone OTP for ${currentAreaCode}${currentMobile}: ${otp}`);
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

    // console.log('Using Zendesk endpoint:', url);
    // console.log('Encoded Auth Header (masked):', encodedAuth.substring(0, 10) + '...');

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
    // console.log('Zendesk response status:', response.status);
    // console.log('Zendesk response data:', zendeskData);

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

    const database = client.db("aiacard-sandbox-db");
    const collection = database.collection("aiacard-sandox-col");
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

    const database = client.db("aiacard-sandbox-db");
    const collection = database.collection("aiacard-sandox-col");
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
