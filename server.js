const express = require('express');
const cors = require('cors');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { MongoClient, ServerApiVersion } = require('mongodb');
const crypto = require('crypto');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const stripe = require('stripe')('sk_test_51Qy1IkDO1xHmcck34QjJM47p4jkKFGViTuIVlbY1njZqObWxc9hWMvrWCsiSVgCRd08Xx1fyfXYG90Hxw6yl84WO00Xt3GGTjU'); // Test secret key
const { merchantPrivateKey, callWasabiApi } = require('./wasabiApi');
const fireblocks = require('./fireblocks');
const http = require('http');
const otplib = require('otplib');
const mongoose = require('mongoose');

// MongoDB Connection
const uri = "mongodb+srv://faz:p6dH6vkUBrcGy4Ed@aiacard-sandbox.a03vg.mongodb.net/?retryWrites=true&w=majority&appName=aiacard-sandbox";
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

// Connect to MongoDB (ensure process.env.MONGODB_URI is set in your environment)
mongoose.connect(process.env.MONGODB_URI)

// Define the user schema and model.
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  totpSecret: { type: String },
  twoFAEnabled: { type: Boolean, default: false },
  isGAVerified: { type: Boolean, default: false },  // Ensure this is included
  biometricsEnabled: { type: Boolean, default: false },
  // ...other fields
});

const User = mongoose.model('User', userSchema);

/**
 * GET /api/generate-2fa?email=<user-email>
 *
 * Generates (or reuses) a TOTP secret for the user, saves it in MongoDB,
 * and returns the otpauth URL for Google Authenticator.
 */
app.get('/api/generate-2fa', async (req, res) => {
  const email = req.query.email;
  console.log('Received /api/generate-2fa request with email:', email);

  if (!email) {
    console.error('Missing email parameter');
    return res.status(400).json({ error: 'Missing email parameter' });
  }

  try {
    // Find the user or create a new user document.
    let user = await User.findOne({ email });
    console.log('User found:', user);
    if (!user) {
      console.log('No user found. Creating new user document for email:', email);
      user = new User({ email });
    }

    // Generate a new secret if one is not already set.
    if (!user.totpSecret) {
      user.totpSecret = otplib.authenticator.generateSecret();
      console.log(`Generated totpSecret for ${email}:`, user.totpSecret);
      await user.save();
      console.log('User document saved:', user);
    } else {
      console.log(`User already has totpSecret for ${email}:`, user.totpSecret);
    }

    // Create the otpauth URL.
    const issuer = 'AIA Pay';
    const otpauthUrl = otplib.authenticator.keyuri(email, issuer, user.totpSecret);
    console.log('Generated otpauthUrl:', otpauthUrl);

    res.json({ otpauthUrl });
  } catch (error) {
    console.error('Error generating 2FA data:', error);
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
    const user = await User.findOne({ email });
    if (!user || !user.totpSecret) {
      return res.status(400).json({ error: 'User not found or 2FA not initialized' });
    }

    // Verify the OTP code using otplib.
    const isValid = otplib.authenticator.check(otp, user.totpSecret);
    console.log(`OTP verification for ${email}:`, isValid);

    if (isValid) {
      // Mark user as 2FA verified.
      user.twoFAEnabled = true;
      user.isGAVerified = true;  // Set GA flag to true
      await user.save();

      // Generate a new token with updated user info.
      const tokenPayload = {
        email: user.email,
        isGAVerified: true,
        // ... include other necessary user properties if needed
      };
      const token = jwt.sign(tokenPayload, process.env.JWT_SECRET, { expiresIn: '1h' });

      return res.json({ valid: true, token, user });
    } else {
      return res.json({ valid: false, message: 'Invalid OTP' });
    }
  } catch (error) {
    console.error('Error verifying OTP:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

app.post('/api/reset-2fa', async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Missing email parameter' });
  }
  try {
    let user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    // Generate a new secret for TOTP.
    const newSecret = otplib.authenticator.generateSecret();
    user.totpSecret = newSecret;
    // Optionally, disable 2FA until the user sets it up again.
    user.twoFAEnabled = false;
    user.isGAVerified = false;
    await user.save();
    res.json({ success: true, totpSecret: newSecret });
  } catch (err) {
    console.error("Error resetting 2FA:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Endpoint to update the user's biometrics preference
app.post('/api/update-biometrics', async (req, res) => {
  const { email, biometricsEnabled } = req.body;

  // Validate input
  if (!email || typeof biometricsEnabled !== 'boolean') {
    return res.status(400).json({ error: 'Missing or invalid parameters' });
  }

  try {
    // Find the user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Update the biometricsEnabled field
    user.biometricsEnabled = biometricsEnabled;
    await user.save();

    res.json({ success: true, biometricsEnabled });
  } catch (err) {
    console.error("Error updating biometrics:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Helper: Generate a 4-digit OTP
function generateOTP() {
  return Math.floor(1000 + Math.random() * 9000).toString();
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
    console.log('Card opened successfully:', response);

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
        console.log(`User with holderId ${holderId} updated with orderNo: ${orderNo} and ${cardAIAField}: ${aiaCardId}`);
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

 // function generateOTP() {
  //   return Math.floor(100000 + Math.random() * 900000).toString();
  // }
  // 6-digit OTP

// Webhook endpoint for Wasabi API
app.post('/webhook', express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf.toString();
  }
}), (req, res) => {
  // Immediately acknowledge with the expected JSON response
  const responsePayload = {
    success: true,
    code: 200,
    msg: "Success",
    data: null
  };
  res.status(200).json(responsePayload);

  // Console log to indicate immediate acknowledgement
  console.log('Webhook immediately acknowledged with response:', responsePayload);

  // Process the webhook asynchronously so as not to delay the response
  setImmediate(async () => {
    console.log('Webhook raw payload:', req.rawBody);
    console.log('Webhook parsed payload:', req.body);

    // Check for a signature header if provided
    const signature = req.headers['x-signature'];
    if (signature) {
      const computedSignature = crypto.createHmac('sha256', process.env.WASABI_WEBHOOK_SECRET)
                                      .update(req.rawBody)
                                      .digest('hex');
      console.log('Computed signature:', computedSignature);
      console.log('Received signature:', signature);
      if (computedSignature !== signature) {
        console.error('Signature verification failed.');
        return;
      }
    } else {
      console.warn('No signature header found.');
    }

    // Extract key parameters from the webhook payload
    const { orderNo, cardNo, type } = req.body;
    if (!orderNo || !cardNo) {
      console.error('Missing orderNo or cardNo in webhook payload.');
      return;
    }
    // Only process webhook if type is 'create'
    if (type !== 'create') {
      console.log(`Webhook type is ${type} (expected 'create'). Skipping processing.`);
      return;
    }

    try {
      const database = client.db("aiacard-sandbox-db");
      const collection = database.collection("aiacard-sandox-col");

      // Lookup the user by orderNo only
      const user = await collection.findOne({ orderNo: orderNo });
      if (!user) {
        console.error(`No user found with orderNo: ${orderNo}`);
        return;
      }

      // Determine the current number of active cards (default to 0 if not set)
      const activeCards = user.activeCards || 0;
      const newCardIndex = activeCards + 1;
      // Create a new field name, e.g., "cardNo1", "cardNo2", etc.
      const cardFieldName = `cardNo${newCardIndex}`;

      // Update the user record: add the new cardNo field and increment activeCards
      const updateResult = await collection.updateOne(
        { _id: user._id },
        { 
          $set: { [cardFieldName]: cardNo },
          $inc: { activeCards: 1 }
        }
      );

      if (updateResult.modifiedCount > 0) {
        console.log(`User ${user.email} updated: ${cardFieldName} set to ${cardNo}. Active cards now: ${newCardIndex}`);
      } else {
        console.error('Failed to update user record with new card information.');
      }
    } catch (dbError) {
      console.error('Error updating MongoDB with card details:', dbError);
    }
  });
});

// // A helper function to decrypt a base64-encoded field from Wasabi using your RSA private key.
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

    // Make sure merchantPrivateKey is defined/imported (from wasabiApi.js, for example)
    // e.g., const { merchantPrivateKey } = require('./wasabiApi');
    
    for (let i = 1; i <= activeCardsCount; i++) {
      const cardNoField = `cardNo${i}`;
      // Update this field name to exactly match what's stored in MongoDB
      const cardTypeField = `cardNo${i}aiaId`; // e.g. "cardNo1aiaId"
      
      const cardNo = user[cardNoField];
      const aiaCardId = user[cardTypeField];  // This value should be 'lite', 'pro', or 'elite'
      if (!cardNo) continue; // Skip if no card number stored
      
      // Prepare payload for the Wasabi Card Info API call
      const payload = {
        cardNo: cardNo,
        onlySimpleInfo: false, // Retrieve full details including balance info
      };
      
      // Call Wasabi's API using your helper function
      const response = await callWasabiApi('/merchant/core/mcb/card/info', payload);
      // Log the raw response from Wasabi API for debugging
      console.log('Raw response from Wasabi API for cardNo:', cardNo, response);
      
      if (response && response.success && response.data) {
        const data = response.data;
        
        // 1. Decrypt the validPeriod (expiry) with your RSA private key
        const rawValidPeriod = data.validPeriod; // This is the base64-encrypted string
        const expiry = decryptRSA(rawValidPeriod, merchantPrivateKey) || 'N/A';
        
        // 2. Decrypt cardNumber if necessary; otherwise, use raw and mask it.
        const rawCardNumber = data.cardNumber;
        let maskedCardNumber = "";
        // Try to decrypt; if decryption fails, fall back to masking the raw value
        const decryptedCardNumber = decryptRSA(rawCardNumber, merchantPrivateKey);
        if (decryptedCardNumber && decryptedCardNumber.length >= 4) {
          maskedCardNumber = "**** " + decryptedCardNumber.slice(-4);
        } else if (data.cardNumber && data.cardNumber.length >= 4) {
          maskedCardNumber = "**** " + data.cardNumber.slice(-4);
        }
        
        // Extract balance from balanceInfo.amount
        const balance = data.balanceInfo?.amount || null;

        // Build a card detail object, merging the MongoDB field (aiaCardId) with the Wasabi data.
        const cardDetail = {
          aiaCardId,               // e.g., 'lite', 'pro', or 'elite' from MongoDB
          cardNo: data.cardNo,       // Bank Card ID from Wasabi
          maskedCardNumber,         // e.g., "**** 2595"
          expiry,                   // Decrypted expiry or "N/A"
          balance,                  // Card balance
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

  console.log("Received freeze request payload:", req.body);

  // Create the payload for Wasabi API
  const payload = { cardNo, maskedCardNumber };

  try {
    // Call the Wasabi Pay API endpoint for freezing the card
    const freezeResponse = await callWasabiApi('/merchant/core/mcb/card/freeze', payload);
    console.log("Freeze response from Wasabi API:", freezeResponse);
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

  console.log("Received unfreeze request payload:", req.body);

  // Create the payload for Wasabi API
  const payload = { cardNo, maskedCardNumber };

  try {
    // Call the Wasabi Pay API endpoint for unfreezing the card
    const unfreezeResponse = await callWasabiApi('/merchant/core/mcb/card/unfreeze', payload);
    console.log("Unfreeze response from Wasabi API:", unfreezeResponse);
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

    const existingUser = await collection.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ success: false, message: "Email already registered. Please log in." });
    }

    const hashedPassword = await bcryptjs.hash(password, 10);
    const otp = generateOTP();
    const otpExpiry = new Date();
    otpExpiry.setMinutes(otpExpiry.getMinutes() + 10);

    await collection.insertOne({
      ...userData,
      email,
      password: hashedPassword,
      otp,
      otpExpiry,
      otpVerified: false,
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
    console.log(`✅ OTP verified for ${email}. User is now verified.`);

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
      }
    });
  } catch (error) {
    console.error("❌ Error verifying OTP:", error);
    res.status(500).json({ success: false, message: "Server error" });
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

    // console.log("Stored password:", user.password, "Provided password:", password);

    if (!user.password) {
      return res.status(500).json({ success: false, message: "User password is missing from the database." });
    }

    if (!(await bcryptjs.compare(password, user.password))) {
      return res.status(401).json({ success: false, message: "Invalid username or password." });
    }

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

    res.status(200).json({ success: true, requiresOTP: true, message: "OTP sent for login verification." });
  } catch (error) {
    console.error("❌ Error during login:", error);
    res.status(500).json({ success: false, message: "Server error" });
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
    console.log(`✅ OTP verified for ${email}. User is now logged in.`);

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

    console.log(`✅ Email updated from ${currentEmail} to ${newEmail} successfully. New token generated.`);

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

    console.log(`✅ Phone updated from ${currentAreaCode}${currentMobile} to ${newAreaCode}${newMobile} successfully. Token regenerated.`);

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
      console.log(`✅ Password updated for ${email}. New token generated.`);
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
      console.log(`✅ Password updated for ${email}. New token generated.`);
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
    console.log(`✅ Card Details OTP verified for ${email}.`);
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
    // Expecting these fields from the client:
    const { subject, message, requesterName, requesterEmail } = req.body;
    if (!subject || !message || !requesterName || !requesterEmail) {
      return res.status(400).json({ success: false, message: "Missing required fields" });
    }
    
    // Zendesk credentials (you can also load these from environment variables)
    const zendeskSubdomain = 'aianalysisexchange';
    const zendeskEmail = 'info@aianalysis.group';
    const zendeskApiToken = 'cAab9YFtbmFEdE7h29Z4p46oHltjkzrE8Co50K9n';
    
    // Use asynchronous ticket creation by adding ?async=true to the endpoint
    const zendeskEndpoint = 'tickets.json?async=true';
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

    const data = await response.json();
    if (response.status === 202) {
      return res.json({ success: true, message: "Ticket creation accepted", data });
    } else {
      return res.status(response.status).json({ success: false, message: "Ticket creation failed", data });
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
    const { email } = req.body;
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
      // Create payload with an empty holderId if it doesn't exist
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
        holderId: ''  // Placeholder, will be filled by the Wasabi API
      };

      // Call the Wasabi API to create a new cardholder
      const wasabiResult = await callWasabiApi("/merchant/core/mcb/card/holder/create", payload);
      console.log("WasabiCard API response:", wasabiResult);

      // Retrieve the new holderId from the API response
      holderId = wasabiResult.data.holderId;

      // Update the user's record with the newly created holderId
      await collection.updateOne({ email: user.email }, { $set: { holderId } });
      console.log(`Created and updated user ${email} with holderId: ${holderId}`);
    } else {
      console.log(`User ${email} already has holderId: ${holderId}`);
    }

    // Call openCard using the holderId (existing or newly created)
    try {
      const openCardResponse = await openCard(holderId);
      console.log("Open Card API response:", openCardResponse);
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
    // Validate that the email is provided in the request body
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ success: false, message: "Email is required" });
    }

    // Connect to MongoDB and find the user record by email
    const database = client.db("aiacard-sandbox-db");
    const collection = database.collection("aiacard-sandox-col");
    const user = await collection.findOne({ email });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    // Ensure that the user has card information stored – only cardNumber and expiry date should be stored.
    if (!user.cardNumber || !user.holderId) {
      return res.status(400).json({ success: false, message: "Card information not available for this user." });
    }

    // Build the payload to call Wasabi's Card Info API.
    // The documentation states that the Card Info API requires a cardNo and an optional onlySimpleInfo flag.
    // We use the cardNumber stored in MongoDB.
    const payload = {
      cardNo: user.cardNumber,
      onlySimpleInfo: false, // set false to get full details including CVV
    };

    // Call Wasabi's API using your helper function.
    // Note: The documented endpoint is '/merchant/core/mcb/card/info'
    const wasabiResponse = await callWasabiApi('/merchant/core/mcb/card/info', payload);
    console.log("WasabiCard API card info response:", wasabiResponse);

    // Optionally, you could merge the stored expiry date (if needed) with the response.
    // For example, if wasabiResponse.data does not include the expiry date, you might add it:
    if (wasabiResponse.success && wasabiResponse.data) {
      wasabiResponse.data.expiryDate = user.expiryDate; // assuming you stored expiry date as 'expiryDate'
    }

    // Return the response from Wasabi to the client.
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

