// server
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { MongoClient, ServerApiVersion } = require('mongodb');
const crypto = require('crypto');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const { callWasabiApi } = require('./wasabiApi');

// MongoDB Connection URI (set via environment variable on Render)
const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

// test comment

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

const secretKey = process.env.JWT_SECRET;

const app = express();
const port = process.env.PORT;

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
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
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
      from: process.env.EMAIL_USER,
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
