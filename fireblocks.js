// fireblocks.js
const fs = require('fs');
const { FireblocksSDK } = require('fireblocks-sdk');

// Read the private key directly from the .key file.
// Make sure the file is in the same directory or adjust the path accordingly.
const PRIVATE_KEY = fs.readFileSync('./fireblocks_secret.key', 'utf8');

// Get the Fireblocks API key from your environment variables.
const API_KEY = process.env.FIREBLOCKS_API_KEY;

// Optionally, set additional options (e.g., choose 'sandbox' or 'production')

// Set options explicitly, including baseUrl
const options = { 
  environment: 'sandbox'
};

// Instantiate the Fireblocks SDK client.
// The SDK will handle JWT signing and other authentication details.
const fireblocksClient = new FireblocksSDK(PRIVATE_KEY, API_KEY, options);

// Export the functions that wrap the Fireblocks SDK methods.
module.exports = {
  /**
   * Creates a new vault account using the Fireblocks SDK.
   * @param {object} accountData - An object containing account parameters:
   *   { name, hiddenOnUI, customerRefId, autoFuel, vaultType, autoAssign }
   * @returns {Promise<object>} - The response from Fireblocks.
   */
  createVaultAccount: async function(accountData) {
    return fireblocksClient.createVaultAccount(accountData);
  },
  
  // You can add more exported functions for additional Fireblocks API calls here.
};
