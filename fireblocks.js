const fs = require('fs');
const { FireblocksSDK } = require('fireblocks-sdk');

// Read the private key directly from the .key file.
const FIREBLOCKS_PRIVATE_KEY_FILE = fs.readFileSync('./fireblocks_secret.key', 'utf8');

// Get the Fireblocks API key from your environment variables.
const API_KEY = process.env.FIREBLOCKS_API_KEY;

// Set options explicitly.
// Here we explicitly set the API URL for sandbox (ensure that this is a string).
const options = {
  environment: 'sandbox',
  apiUrl: 'https://sandbox-api.fireblocks.io/v1'
};

// Instantiate the Fireblocks SDK client.
// The SDK will handle JWT signing and other authentication details.
const fireblocksClient = new FireblocksSDK(FIREBLOCKS_PRIVATE_KEY_FILE, API_KEY, options);
console.log("fireblocksClient.baseURL type:", typeof fireblocksClient.baseURL, "value:", fireblocksClient.baseURL);


// Export the function wrapping the SDK method.
module.exports = {
  /**
   * Creates a new vault account using the Fireblocks SDK.
   * @param {object} accountData - An object containing account parameters.
   *   For example: { name, hiddenOnUI, customerRefId, autoFuel, vaultType, autoAssign }
   * @returns {Promise<object>} - The response from Fireblocks.
   */
  createVaultAccount: async function(accountData) {
    return fireblocksClient.createVaultAccount(accountData);
  },
  // Add other functions as needed.
};
