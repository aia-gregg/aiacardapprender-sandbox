// Attempt to patch the axios instance that Fireblocks SDK uses
const axios = require('fireblocks-sdk/node_modules/axios');
axios.defaults.baseURL = 'https://sandbox-api.fireblocks.io/v1';
console.log("Patched axios defaults.baseURL:", axios.defaults.baseURL);

const fs = require('fs');
const { FireblocksSDK } = require('fireblocks-sdk');

// Read the private key directly from the .key file.
const FIREBLOCKS_PRIVATE_KEY_FILE = fs.readFileSync('./fireblocks_secret.key', 'utf8');

// Get the Fireblocks API key from your environment variables.
const API_KEY = process.env.FIREBLOCKS_API_KEY;

// Set options using only the environment property.
const options = { 
  environment: 'sandbox'
};

// Instantiate the Fireblocks SDK client.
// Let the SDK set the default API URL based on the environment.
const fireblocksClient = new FireblocksSDK(FIREBLOCKS_PRIVATE_KEY_FILE, API_KEY, options);

// Patch the internal Axios instance so that its baseURL is explicitly set as a string.
if (fireblocksClient && fireblocksClient.axiosInstance) {
  const url = 'https://sandbox-api.fireblocks.io/v1';
  fireblocksClient.axiosInstance.defaults.baseURL = url.toString();
  console.log("Patched axios baseURL:", fireblocksClient.axiosInstance.defaults.baseURL);
} else {
  console.log("fireblocksClient.axiosInstance not available");
}

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
