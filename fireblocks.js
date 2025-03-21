const { FireblocksSDK } = require('fireblocks-sdk');

// Define your PEM-formatted private key as a string literal.
const FIREBLOCKS_PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MIIJQQIBADANBgkqhkiG9w0BAQEFAASCCSswggknAgEAAoICAQDQr64LSXNy6GFM
gIaMEFY++k0cKFsEdAjc66+1Cdi/ZkiB2PfC3/y562X4XiAWVK1ZgIgvW0hxr7bb
qjJYyZdDgX2TJr1zpG4QkCcF2d930GuqZY6eIxMzgXSQkvo564cQ3FF/HZxBAoXn
cK53UzREa+T4Tb5Z62X8wkLl1X0geqrGMljTQ3Mt146JTHtK70tejr0A9+OsBT5w
DhGokAqAwHz7BdnH/+X4cjaFWJ3ZM326b1J1CrYFH/JeHZzPHvxi788DcjDwPs1/
HG2/L7Ww3m+GnD63KyDHnchVI+qzG6vnL6Oz/zMEC1vL5Q/yOWnjLxzW8U/su1nO
DG0D6PApw3znBHI0r02OUrozhC89+q3Sr3RsRvBBvWmoZ56q8XgXchB1mTGgXKRX
xK5zoyZFrr+cdOX0aUV3bKmGjHjhP3zvd4ZOrfMVcECsnlyq+6cISTOlokIJHG5s
SC12wVwjreU6cNPs2E1wGlOQZGWH684Uz+0PFtluV8m5MNNt7SLEMe6kLC+YV6oz
0yaajhs85nCtOhqbpbxwcSmuzckI4hNwYTX+6caz1VJZ1dBtfKkkdvQ5Y/p2XTJX
DPcrYg58PkUZFaD6PpMSORn6HwkTjOSqdpJ6A8Twehw0s8ZPv9eH7PTWjWGqQRFt
wdo7aNxxsKvaulI3Ht4GQRp+sikqSQIDAQABAoIB/1Ns84OzbOBNO5EbndUgQQo7
NnJrHj9h3kBb77kf+HFA40vxfHiL/qNiWiZwtostVz4U4sO90ohI3p+Yq+ngbgnp
NqotXIxDmigMT6aiBUJEykmQbXI9X8UKGixJeSuVLBZz9NfWDUi6MqOdDcmWUZ/q
LvEhfNBgnvEJw468CDJ4gzDeffDtnKby8O0O40riPSspz9O/hNhGUk2tMo9LzCU+
9lS294VagzQbA+eE5HTn0cO0Ka8lTS89tuXHVfNIyWgqH9cqtg07vxU6v0DU+/8P
beDmCmVANT+op86dojw3LUaoBRq7Yc6G5hFbhoC+x1Wk2G7C9X2RklhcQpydmc/N
/lb6lWgHoPEvkFDZLf/LmVZA+LlbMr9UOAT8Y4saZZN5H9izjWSxJsPOVLojmeaZ
8hjj07/032ab4FhGxYWunsrLZHkf2EAEdE+czPg10FU9Qazm/DwjS0KQetk57dm0
7b+2/LWpQayL9vaQYDV0kvIiuBqjaGwm4/tS/iLOc6Tg7iAFAumGtBrRnPYQ95A3
GMscZeAKraw1ZR/L/VhnW6cXYLES2WCnBVah+BvXs1hv2LB+zqWviA6qyNIYLcaq
Dz6g7UiXIrfs3J8gF5Jl3ZlGL88FCFOFCR1ek/GVCVXW3ElUGlrBfATHvjGJ4CkZ
rjkZ1MFf9Qapx5JfW10CggEBAPESOIRLdiQS4rB0zFRVERkxUHyZDna4tS2C1Rpc
M9iMrBsH8Hvl7h2Xklxf7ZiidGMMdbhVFXKx9x7j/dRoQLnPQDvtofDNMnBOwGtP
Oy+FHnpMjJLGqj1w/caKjmDlG+Qq9WpmLIQqZeakao9qAb4BLD8eQupHUXG2jFgk
Wl6Kvwv5wA5JDfTRDikXZWvdA6UsBDWdmQykQN9cMuAqKyok0IvKP81+bzqRdL17
NZfQ+7k1japbcRWAiSqPUmbCIsDhh+jaUJ2vBlb3fWBIEFMUQsKLEpsbbx3S7waD
17ZARpeUq9uIuRwQriOaZBUK4bSIcAZBC8ElY6KQB5bxoisCggEBAN2cDOdFqTwa
ycvESYybVM0u3CpYGiJZ5emQZpxV3O3/3NZA/vT8TInSOrNBAywGJwLaTTw8OBVq
Agxmx+bg/GdDhUGZX9ZDQWE7NRFWpybO30dO8L5HFYxNvOjLRu5I8BirIU/GRx9M
5pU08w61CI/rgdvFvydWVp3SMeYb/PhVy1hMeRKA53UdEDEfIHEj7DOqX6hqCDMY
xtVeEFmja7JdLyd9kAI+nbMm7kd4syQASb/rrdMSLsG273NERCVcTLylDFRMOD5u
Qz8O3kgM2p2Ua6AkcRqmgltsGE6X6F2wxkA0kPSWQg7p2k6auu65T6LLEXoB9uhm
V1zrYbdMD1sCggEBAMjBhMFfWl5GP/P1AGhGgzu4nq90guAJiBADgVY3bJGs7HKC
VRnI7FhGboNw+5t9xnDp4msEqBzg6cwWz76Ap05Vssd1aMPxDk0KuCFlVQOI102/
y907hnAuVZhusI0unuCPidr2haH28O93Aqq1/AdwUJmrqMwTYlbRT+TjOUK8RsdB
UFhVLEMxiZpcuoBuCOgXVNYVjWxCqSeZT2DwnQu2ptmTLzkBTr22fkKBhasNRWQC
nhw9lFn0tcX0nwmmKGz6JEWc8T+vjxcDeayhtr6JA+OhD3iOCyYKEDYbu5sxwdff
3pKvNICTv4E0xJ3ldvryGGCM8K4DZgrt6PQh/AsCggEAadbRwtLeVLpmjk8c4W5+
PdCXjhGtyaIt0DMLDrdjYLfGfP1lxxOIanphVqNCJJB7qT0hjhckofWTLOEZsAbc
BWWWCxJ5Vxef7hQc8D72be53bNMi332LqQqnoncTVVK4eM+ihTspVKWhqrkzLF8B
y9qqlpAHD36It69f7YqIcwJmr7E2UcQGx0QuK4e2MtL5SGOidAjQCbdXnyfhny4R
jYo7rxyk3q2RG7MIMlJPHG6WynaA+kHA2vvHuMFt2noOnDonfUs5wXdf3on3V2ns
Lz5neIBvFE9aCtfBdCfQ7o4y4Q85+9aXjg/aF5iGluUiR5m8qwytI6ldKB+y95v3
6QKCAQBpmrzdJUn4VUQSMvNbxv1Rv9GjCQw5Eewd9A8xdRha8kW4jKqOVqJHF49/
p6PaBGmTY+D8t0fcwXTFIqRUmFrg1dxPQ5g/u0Ta/HYQsEMreRRz7255t9wdD8qN
HCTrBh5ayAHPEIX8OgsI84bTZCOPJEEI2jo6QZ3QE1ZJ/H/CUmLuyq91/UVk49N2
emXzu5rNq/p0SJ9n7A5BLuKlmkNgbo7I9Q+tVHOEOE+DSN8NxAERCj6inmmpKNhF
mNNi9OXLFxzBv/g6aUCfTzHWGJd8D/TjzqIsLLOFufLKHqaHxxtfJKL+qgH5n7ED
y3sgvpDI1ZDFLNXDH7N5AYWUZZ79
-----END PRIVATE KEY-----`;

const API_KEY = process.env.FIREBLOCKS_API_KEY;

// Use an options object with the environment set to 'sandbox'.
// This will cause the SDK to use the default sandbox API URL (which is "https://sandbox-api.fireblocks.io/v1").
const options = {
  environment: 'sandbox'
};

// Instantiate the Fireblocks SDK client using the options object.
const fireblocksClient = new FireblocksSDK(FIREBLOCKS_PRIVATE_KEY, API_KEY, options);

// Patch the createVaultAccount method to ensure payload flattening.
// Instead of accessing the axiosInstance (which might be undefined), call the original method.
const originalCreateVaultAccount = fireblocksClient.createVaultAccount.bind(fireblocksClient);
fireblocksClient.createVaultAccount = async function(accountData) {
  // Construct a payload exactly as expected by the Fireblocks API.
  const payload = {
    name: accountData.name, // should be a string
    hiddenOnUI: accountData.hiddenOnUI,
    customerRefId: accountData.customerRefId,
    autoFuel: accountData.autoFuel,
    vaultType: accountData.vaultType,
    autoAssign: accountData.autoAssign
  };
  // Call the original method with the flattened payload.
  return originalCreateVaultAccount(payload);
};

module.exports = {
  /**
   * Creates a new vault account using the Fireblocks SDK.
   * @param {object} accountData - e.g., { name: string, hiddenOnUI: boolean, customerRefId: string, autoFuel: boolean, vaultType: string, autoAssign: boolean }
   * @returns {Promise<object>} - The Fireblocks response.
   */
  createVaultAccount: async function(accountData) {
    return fireblocksClient.createVaultAccount(accountData);
  }
};
