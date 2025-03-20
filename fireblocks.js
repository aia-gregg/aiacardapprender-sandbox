// fireblocks.js
const fs = require('fs');
const { FireblocksSDK } = require('fireblocks-sdk');

// Force the SDK to use your full URL for API calls
process.env.FIREBLOCKS_API_URL = 'https://sandbox-api.fireblocks.io/v1';

// Read your PEM-formatted private key
const FIREBLOCKS_PRIVATE_KEY_FILE = fs.readFileSync('./fireblocks_secret.key', 'utf8');

// Get your Fireblocks API key from the environment
const API_KEY = process.env.FIREBLOCKS_API_KEY;

// Set options (the 'environment' option usually determines the default URL)
const options = {
  environment: 'sandbox'
};

// Instantiate the Fireblocks SDK client
const fireblocksClient = new FireblocksSDK(FIREBLOCKS_PRIVATE_KEY_FILE, API_KEY, options);

module.exports = {
  /**
   * Creates a new vault account using the Fireblocks SDK.
   * @param {object} accountData - e.g., { name, hiddenOnUI, customerRefId, autoFuel, vaultType, autoAssign }
   * @returns {Promise<object>} - The Fireblocks response.
   */
  createVaultAccount: async function(accountData) {
    return fireblocksClient.createVaultAccount(accountData);
  }
};
