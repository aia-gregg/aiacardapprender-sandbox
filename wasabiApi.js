// wasabiApi
const crypto = require('crypto');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));

const WASABI_BASE_URL = "https://sandbox-api-merchant.wasabicard.com";

const apiKey = process.env.WASABI_API_KEY;
const merchantPrivateKey = Buffer.from(process.env.WASABI_PRIVATE_KEY_B64, 'base64').toString('utf8');
console.log("Merchant Private Key starts with:", merchantPrivateKey.slice(0, 30));

function generateSignature(message, privateKey) {
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(message);
  signer.end();
  return signer.sign(privateKey, 'base64');
}

async function callWasabiApi(endpoint, payloadObj) {
  const payloadString = JSON.stringify(payloadObj);
  console.log("Payload for WasabiCard:", payloadString);
  const signature = generateSignature(payloadString, merchantPrivateKey);
  console.log("Generated Signature:", signature);
  const headers = {
    "Content-Type": "application/json",
    "X-WSB-API-KEY": apiKey,
    "X-WSB-SIGNATURE": signature,
  };
  const url = `${WASABI_BASE_URL}${endpoint}`;
  console.log("Calling Wasabi API at:", url);
  const response = await fetch(url, {
    method: "POST",
    headers,
    body: payloadString,
  });
  
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Wasabi API Error (${response.status}): ${errorText}`);
  }
  
  return response.json();
}

module.exports = { callWasabiApi };
