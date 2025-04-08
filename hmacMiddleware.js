// hmacMiddleware.js
const crypto = require('crypto');

function verifyHMAC(req, res, next) {
  // Extract the client-provided HMAC signature from header
  const providedSignature = req.headers['x-hmac-signature'];
  if (!providedSignature) {
    return res.status(401).json({ error: 'Missing HMAC signature in headers' });
  }
  
  // Use a secret key stored in an env variable (make sure the client signs using the same key)
  const hmacSecret = process.env.HMAC_SECRET;
  if (!hmacSecret) {
    console.error('HMAC secret key is not defined');
    return res.status(500).json({ error: 'Server configuration error' });
  }
  
  // Build the message string. This could be the stringified body or a concatenation of select fields.
  // Ensure that the client and server agree on the message format.
  const message = JSON.stringify(req.body);
  
  // Compute HMAC using SHA256
  const computedSignature = crypto
    .createHmac('sha256', hmacSecret)
    .update(message)
    .digest('hex');
  
  // Compare using timing safe equal
  const providedBuffer = Buffer.from(providedSignature, 'hex');
  const computedBuffer = Buffer.from(computedSignature, 'hex');
  
  // Ensure the buffers are the same length before comparing to avoid errors
  if (providedBuffer.length !== computedBuffer.length ||
      !crypto.timingSafeEqual(providedBuffer, computedBuffer)) {
    console.error('HMAC signature mismatch. Provided:', providedSignature, 'Computed:', computedSignature);
    return res.status(401).json({ error: 'Invalid HMAC signature' });
  }
  
  next();
}

module.exports = verifyHMAC;
