// server
const express = require('express');
const cors = require('cors');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { MongoClient, ServerApiVersion } = require('mongodb');
const crypto = require('crypto');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY || 'sk_test_...');
const { callWasabiApi } = require('./wasabiApi');

// MongoDB Connection URI (set via environment variable on Render)
const uri = process.env.MONGODB_URI || "mongodb://localhost:27017/your-local-db";
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

function generateMerchantOrderNo(length = 22) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

async function openCard(holderId) {
  const payload = {
    merchantOrderNo: generateMerchantOrderNo(),
    holderId: holderId,
    cardTypeId: 111016,
    amount: 50
  };
  try {
    const response = await callWasabiApi('/merchant/core/mcb/card/openCard', payload);
    console.log('Card opened successfully:', response);
    return response;
  } catch (error) {
    console.error('Error opening card:', error);
    throw error;
  }
}

const secretKey = process.env.JWT_SECRET || "your_super_secret_key";

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Connect to MongoDB
client.connect()
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch((err) => console.error("❌ Error connecting to MongoDB:", err));

function generateOTP() {
  return Math.floor(1000 + Math.random() * 9000).toString();
}

const transporter = nodemailer.createTransport({
  host: "smtp-mail.outlook.com",
  port: 587,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER || "verify@card.aianalysis.group",
    pass: process.env.EMAIL_PASS || "your-email-password",
  },
  tls: { ciphers: 'SSLv3' }
});

// --- Registration Endpoint ---
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
      from: process.env.EMAIL_USER || "verify@card.aianalysis.group",
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

// --- OTP Verification for Registration ---
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

// --- Login & OTP Send Endpoint ---
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

    const otp = generateOTP();
    const otpExpiry = new Date(Date.now() + 10 * 60000);
    console.log(`🔑 Generated Login OTP for ${email}: ${otp}`);

    await collection.updateOne({ email }, { $set: { otp, otpExpiry } });

    await transporter.sendMail({
      from: process.env.EMAIL_USER || "verify@card.aianalysis.group",
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

// --- Resend and Verify OTP endpoints, Profile Update, Change Email/Phone/Password endpoints, Payment, etc. ---
// (Include the remaining endpoints as in your local version.)

// --- Ping Endpoint ---
app.get('/ping', (req, res) => {
  res.status(200).json({ message: 'pong' });
});

// --- Stripe Payment Endpoint ---
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

// --- Create Cardholder and Open Card Endpoint ---
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
    };

    const wasabiResult = await callWasabiApi("/merchant/core/mcb/card/holder/create", payload);
    console.log("WasabiCard API response:", wasabiResult);

    const holderId = wasabiResult.data.holderId;
    await collection.updateOne({ email: user.email }, { $set: { holderId } });
    console.log(`Updated user ${email} with holderId: ${holderId}`);

    try {
      const openCardResponse = await openCard(holderId);
      console.log("Open Card API response:", openCardResponse);
    } catch (openError) {
      console.error("Failed to open card for holderId", holderId, openError);
    }

    res.json({ success: true, data: wasabiResult });
  } catch (error) {
    console.error("Error creating cardholder on WasabiCard API:", error);
    res.status(500).json({ success: false, message: error.message });
  }
});

const server = app.listen(port, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${port}`);
});
server.on('error', (err) => {
  console.error('Server error:', err);
});
