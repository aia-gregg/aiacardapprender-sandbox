// fireblocks.js

const fetch = require('node-fetch');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Fireblocks configuration (ensure these are set in your environment)
const FIREBLOCKS_BASE_URL = process.env.FIREBLOCKS_BASE_URL;
const API_KEY = process.env.FIREBLOCKS_API_KEY;
// Decode the private key from base64 (assuming it's stored encoded)
const PRIVATE_KEY = Buffer.from(process.env.FIREBLOCKS_PRIVATE_KEY, 'base64').toString('utf8');

/**
 * Generate a random nonce.
 */
function generateNonce() {
  return crypto.randomBytes(16).toString('hex');
}

/**
 * Generates a JWT for a Fireblocks API request.
 * @param {string} uri - The request URI (e.g., "/v1/vault/accounts")
 * @param {string} method - HTTP method (GET, POST, etc.)
 * @param {object} body - Request payload (if any)
 * @returns {string} - The signed JWT token.
 */
function generateFireblocksJwt(uri, method, body) {
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + 60; // token valid for 60 seconds
  const nonce = generateNonce();

  // If there is a request body, hash it using SHA256
  let bodyHash = "";
  if (body && Object.keys(body).length > 0) {
    const hash = crypto.createHash('sha256');
    hash.update(JSON.stringify(body));
    bodyHash = hash.digest('hex');
  }

  const payload = {
    uri,          // the API endpoint path (e.g., "/v1/vault/accounts")
    nonce,        // a unique identifier for this request
    iat,          // issued at
    exp,          // expiration time
    sub: API_KEY  // your Fireblocks API key
  };

  // Include the body hash if applicable
  if (bodyHash) {
    payload.body = bodyHash;
  }

  // Sign the JWT with RS256 using your decoded private key
  const token = jwt.sign(payload, PRIVATE_KEY, { algorithm: 'RS256' });

  // Log the JWT header and payload for debugging (remove in production)
  const decoded = jwt.decode(token, { complete: true });
  console.log("JWT Header and Payload:", JSON.stringify(decoded, null, 2));

  return token;
}

/**
 * A generic function to call the Fireblocks API.
 * @param {string} method - HTTP method (GET, POST, etc.)
 * @param {string} endpoint - API endpoint (e.g., "/vault/accounts")
 * @param {object} body - Request payload (if applicable)
 * @returns {object} - The parsed JSON response.
 */
async function callFireblocksApi(method, endpoint, body) {
  // Prepend "/v1" if not already included (Fireblocks endpoints typically start with /v1)
  const uri = endpoint.startsWith("/v1") ? endpoint : `/v1${endpoint}`;
  const token = generateFireblocksJwt(uri, method, body);
  const url = `${FIREBLOCKS_BASE_URL}${uri}`;

  const options = {
    method,
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${token}`
    }
  };

  if (body) {
    options.body = JSON.stringify(body);
  }

  const response = await fetch(url, options);
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Fireblocks API Error (${response.status}): ${errorText}`);
  }
  return response.json();
}

module.exports = {
  callFireblocksApi,
};
