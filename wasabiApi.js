// wasabiApi
const crypto = require('crypto');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));

const WASABI_BASE_URL = "https://sandbox-api-merchant.wasabicard.com";

const apiKey = process.env.WASABI_API_KEY;
const merchantPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAIVs24rAE+XSupt8
utUk0uoLm0DlvTHL2B9aBVlLziLsF0uu/bS41+E49Ze9Nec8EWfv+2Ncghi0uL+X
902M+2pm03nIBrJrvigqYn7dbYJ24Si9asf2QZQjqzA+hTmuNS01eYDgaB2xa91D
1t1kmUXY4ysTM4DIhMulQroRediHAgMBAAECgYBuUvqdmgFZ8YsXcmVSROaZXAt9
9/keqb0E/3yYv5OtUKZakFF8E7N9qYl5dJyTnRmPZeHp4N4564Uv90ont8FSoflz
0zCJ0RwR102q0KKdpKGRPQnO28WF39FZG8Lb18bk329kU/L7IFEP7AaUc0gaHx2T
ad87EyKvql2b5CvosQJBAL5lmDyedGYVNzbNtjTzp4w5xlQyI6ymmxLJIv/OmRNh
PiGIRd2P0BcGI30EFhc0PAHKT/0q/zm4kc4XpsnFtpsCQQCzZfIJxCZky3Xo+R+g
sX6XjQZCbmmDE8LHjKnkOk8vs0StaKXdRcZYcDZMnhLyEL58GkBryEqYfibABgSi
6I6FAkA6viWmLk1DYbBTXEynMbWz8e9a8s1G63BU73G48wkPjaUZu22y2jgdoms4
mxYlupv5AW6EcculB2kU6P8wqauZAkEAqB+ABtsGSCvM4nqlw0jUJF8LYLJsu2SH
g881YCetEjzkvcZ2urmrOjJfEMqLYsOCYHeRq/DWx7Zhxk9dhPaAqQJAASIhQ1aSA
aRy/g3gfDZGyrc2fv2sD455DohrWsI1Y0Q6DfJ9VD2AX043hl/g4AwNsndST2y43
mI/N3zFBaUIRw==
-----END RSA PRIVATE KEY-----`;

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
