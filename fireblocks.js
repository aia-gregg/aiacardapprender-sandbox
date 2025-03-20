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

// Attempt to patch the internal request method (_request) to force absolute URLs.
if (fireblocksClient && typeof fireblocksClient._request === 'function') {
  const originalRequest = fireblocksClient._request;
  fireblocksClient._request = function(config) {
    // If the URL is relative, prepend the full endpoint.
    if (config.url && !config.url.startsWith('http')) {
      config.url = 'https://sandbox-api.fireblocks.io/v1' + config.url;
    }
    return originalRequest.call(this, config);
  };
  console.log('Patched fireblocksClient._request to use absolute URLs.');
} else {
  console.warn('fireblocksClient._request is not available.');
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
